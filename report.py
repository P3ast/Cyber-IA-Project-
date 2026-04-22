import json
from datetime import datetime


RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def generate_report(result: dict, save_json: bool = False) -> str:
    """Génère un rapport lisible depuis le dict de résultats."""
    score   = result.get("score", 0)
    verdict = result.get("verdict", "INCONNU")
    raisons = result.get("raisons", [])
    features = result.get("features", {})

    if verdict == "PHISHING":
        color = RED
    elif verdict == "SUSPECT":
        color = YELLOW
    else:
        color = GREEN

    lines = [
        "",
        f"{BOLD}{'='*60}{RESET}",
        f"{BOLD}  RAPPORT DE DÉTECTION PHISHING{RESET}",
        f"  {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
        f"{'='*60}",
        "",
        f"  Expéditeur : {BLUE}{result.get('sender', 'N/A')}{RESET}",
        f"  Sujet      : {result.get('email_subject', 'N/A')}",
        "",
        f"  Score de risque : {color}{BOLD}{score}/100{RESET}",
        f"  Verdict         : {color}{BOLD}{verdict}{RESET}",
        "",
        f"{BOLD}  Indicateurs détectés :{RESET}",
    ]

    for r in raisons:
        lines.append(f"    {YELLOW}•{RESET} {r}")

    lines += [
        "",
        f"{BOLD}  Métriques techniques :{RESET}",
        f"    SPF valide      : {'✓' if features.get('spf_pass') else '✗'}",
        f"    DMARC valide    : {'✓' if features.get('dmarc_pass') else '✗'}",
        f"    URLs suspectes  : {'Oui' if features.get('suspicious_urls') else 'Non'}",
        f"    Mots urgents    : {'Oui' if features.get('urgent_keywords') else 'Non'}",
        f"    Âge du domaine  : {features.get('domain_age_days', 'N/A')} jours",
        f"    Pièces jointes  : {', '.join(features.get('attachment_types', [])) or 'Aucune'}",
        "",
        f"{BOLD}  Recommandation :{RESET}",
        f"    {result.get('recommandation', 'N/A')}",
        "",
        f"{'='*60}",
        "",
    ]

    report = "\n".join(lines)

    if save_json:
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        report += f"\n  Rapport JSON sauvegardé : {filename}\n"

    return report
