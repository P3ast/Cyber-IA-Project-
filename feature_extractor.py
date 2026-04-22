import re
from urllib.parse import urlparse
from datetime import datetime
import whois  # pip install python-whois


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

