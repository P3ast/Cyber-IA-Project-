"""
Parser d'emails (.eml) — extrait sujet, expéditeur, corps, en-têtes et pièces jointes.
"""

import email
from email import policy
from email.parser import BytesParser, Parser


def parse_email(raw: str) -> dict:
    """
    Analyse un email brut (texte ou bytes) et retourne un dict structuré.
    """
    if isinstance(raw, bytes):
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    else:
        msg = Parser(policy=policy.default).parsestr(raw)

    result = {
        "subject":      msg.get("Subject", ""),
        "from":         msg.get("From", ""),
        "to":           msg.get("To", ""),
        "reply_to":     msg.get("Reply-To", ""),
        "date":         msg.get("Date", ""),
        "content_type": msg.get_content_type(),
        "headers":      dict(msg.items()),
        "body":         "",
        "html_body":    "",
        "attachments":  [],
    }

    # Parcours des parties MIME
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in disposition:
                result["attachments"].append(part.get_filename() or "unknown")
            elif ctype == "text/plain" and not result["body"]:
                result["body"] = _decode_part(part)
            elif ctype == "text/html" and not result["html_body"]:
                result["html_body"] = _decode_part(part)
    else:
        ctype = msg.get_content_type()
        if ctype == "text/html":
            result["html_body"] = _decode_part(msg)
            result["body"] = _strip_html(result["html_body"])
        else:
            result["body"] = _decode_part(msg)

    # Fallback : utiliser le HTML si pas de texte brut
    if not result["body"] and result["html_body"]:
        result["body"] = _strip_html(result["html_body"])

    return result


def _decode_part(part) -> str:
    """Décode une partie MIME en str avec gestion des encodages."""
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    except Exception:
        return str(part.get_payload() or "")


def _strip_html(html: str) -> str:
    """Supprime les balises HTML pour obtenir le texte brut."""
    import re
    clean = re.sub(r'<[^>]+>', ' ', html)
    clean = re.sub(r'\s+', ' ', clean)
    return clean.strip()
