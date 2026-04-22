import re
from urllib.parse import urlparse
from datetime import datetime
import whois


URGENT_KEYWORDS = [
    "urgent", "immédiat", "compte bloqué", "vérifiez maintenant",
    "cliquez ici", "mot de passe expiré", "action requise",
    "suspended", "verify your account", "click here", "limited time",
    "vous avez gagné", "félicitations", "winner", "congratulations",
    "invoice", "facture impayée", "paiement requis"
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".cf"]

TRUSTED_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "twitter.com", "github.com",
    "orange.fr", "sfr.fr", "laposte.net", "free.fr"
]

class FeatureExtractor:
    def extract(self, email_data: dict) -> dict:
        body = email_data.get("body", "")
        headers = email_data.get("headers", {})
        sender = email_data.get("from", "")

        urls = self._extract_urls(body)
        sender_domain = self._extract_domain(sender)

        features = {
            # --- En-têtes ---
            "spf_pass": self._check_spf(headers),
            "dmarc_pass": self._check_dmarc(headers),
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

    def _check_spf(self, headers: dict) -> bool:
        received_spf = headers.get("Received-SPF", "").lower()
        auth_results = headers.get("Authentication-Results", "").lower()
        return "pass" in received_spf or "spf=pass" in auth_results

    def _check_dmarc(self, headers: dict) -> bool:
        auth_results = headers.get("Authentication-Results", "").lower()
        return "dmarc=pass" in auth_results

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
        """Retourne l'âge du domaine en jours. -1 si erreur."""
        if not domain or domain in TRUSTED_DOMAINS:
            return 9999  # Domaines connus = très ancien
        try:
            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                return (datetime.now() - creation).days
        except Exception:
            pass
        return -1

