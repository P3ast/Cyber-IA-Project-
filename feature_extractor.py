import re
import json
import os
import concurrent.futures
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime
import whois

config_path = os.path.join(os.path.dirname(__file__), "config.json")
try:
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)
except Exception:
    config = {}

URGENT_KEYWORDS = config.get("URGENT_KEYWORDS", [])
SUSPICIOUS_TLDS = config.get("SUSPICIOUS_TLDS", [])
TRUSTED_DOMAINS = config.get("TRUSTED_DOMAINS", [])

class FeatureExtractor:
    def extract(self, email_data: dict) -> dict:
        body = email_data.get("body", "")
        headers = email_data.get("headers", {})
        sender = email_data.get("from", "")

        urls = self._extract_urls(body)
        sender_domain = self._extract_domain(sender)

        features = {
            # --- En-têtes ---
            "spf_pass": self._check_spf(headers, sender_domain),
            "dmarc_pass": self._check_dmarc(headers, sender_domain),
            "reply_to_mismatch": self._reply_to_mismatch(email_data),
            "sender_domain": sender_domain,

            # --- URLs ---
            "url_count": len(urls),
            "suspicious_urls": self._has_suspicious_urls(urls),
            "ip_in_url": self._has_ip_url(urls),
            "url_domain_mismatch": self._url_domain_mismatch(urls, sender_domain),

            # --- Contenu ---
            "urgent_keywords": self._has_urgent_keywords(body),
            "html_only": self._is_html_only(email_data),
            "has_attachment": bool(email_data.get("attachments")),
            "attachment_types": email_data.get("attachments", []),

            # --- Domaine expéditeur ---
            "domain_age_days": self._get_domain_age(sender_domain),
            "domain_is_trusted": sender_domain in TRUSTED_DOMAINS,
            "suspicious_tld": any(sender_domain.endswith(t) for t in SUSPICIOUS_TLDS),

            "urls_found": urls[:10],
        }

        return features


    def _extract_urls(self, text: str) -> list:
        pattern = r'https?://[^\s\'"<>]+'
        return list(set(re.findall(pattern, text)))

    def _extract_domain(self, email_address: str) -> str:
        match = re.search(r'@([\w.\-]+)', email_address)
        return match.group(1).lower() if match else ""

    def _check_spf(self, headers: dict, sender_domain: str) -> bool:
        received_spf = headers.get("Received-SPF", "").lower()
        auth_results = headers.get("Authentication-Results", "").lower()
        if "pass" in received_spf or "spf=pass" in auth_results:
            return True
        if sender_domain:
            try:
                answers = dns.resolver.resolve(sender_domain, 'TXT')
                for rdata in answers:
                    if 'v=spf1' in rdata.to_text():
                        return True
            except Exception:
                pass
        return False

    def _check_dmarc(self, headers: dict, sender_domain: str) -> bool:
        auth_results = headers.get("Authentication-Results", "").lower()
        if "dmarc=pass" in auth_results:
            return True
        if sender_domain:
            try:
                answers = dns.resolver.resolve(f"_dmarc.{sender_domain}", 'TXT')
                for rdata in answers:
                    if 'v=DMARC1' in rdata.to_text():
                        return True
            except Exception:
                pass
        return False

    def _reply_to_mismatch(self, email_data: dict) -> bool:
        from_domain = self._extract_domain(email_data.get("from", ""))
        reply_domain = self._extract_domain(email_data.get("reply_to", ""))
        if not reply_domain:
            return False
        return from_domain != reply_domain

    def _has_suspicious_urls(self, urls: list) -> bool:
        for url in urls:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if any(domain.endswith(t) for t in SUSPICIOUS_TLDS):
                return True
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                return True
            for trusted in TRUSTED_DOMAINS:
                if trusted in domain and not domain.endswith(trusted):
                    return True  # Ex: paypal.com.malicious.xyz
        return False

    def _has_ip_url(self, urls: list) -> bool:
        for url in urls:
            host = urlparse(url).netloc.split(":")[0]
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
                return True
        return False

    def _url_domain_mismatch(self, urls: list, sender_domain: str) -> bool:
        if not sender_domain:
            return False
        for url in urls:
            url_domain = urlparse(url).netloc.lower()
            if sender_domain and sender_domain not in url_domain:
                return True
        return False

    def _has_urgent_keywords(self, body: str) -> bool:
        body_lower = body.lower()
        return any(kw.lower() in body_lower for kw in URGENT_KEYWORDS)

    def _is_html_only(self, email_data: dict) -> bool:
        return email_data.get("content_type", "").startswith("text/html")

    def _get_domain_age(self, domain: str) -> int:
        """Retourne l'âge du domaine en jours avec timeout de 5s. -1 si erreur."""
        if not domain or domain in TRUSTED_DOMAINS:
            return 9999  # Domaines connus = très ancien
            
        def fetch_whois():
            return whois.whois(domain)

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(fetch_whois)
                w = future.result(timeout=5)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                return (datetime.now() - creation).days
        except Exception:
            pass
        return -1

