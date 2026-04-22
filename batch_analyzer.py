import os
import sys
import json
from datetime import datetime
from agent import PhishingAgent
from report import generate_report, RED, YELLOW, GREEN, BOLD, RESET


def analyze_folder(folder_path: str):
    agent = PhishingAgent()
    results = []

    eml_files = [f for f in os.listdir(folder_path) if f.endswith(".eml")]

    if not eml_files:
        print(f"Aucun fichier .eml trouvé dans {folder_path}")
        return

    print(f"\n{BOLD}Analyse de {len(eml_files)} email(s)...{RESET}\n")

    for filename in eml_files:
        filepath = os.path.join(folder_path, filename)
        print(f"  → Traitement : {filename}")

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                raw = f.read()
            result = agent.analyze(raw)
            result["filename"] = filename
            results.append(result)
        except Exception as e:
            print(f"    Erreur : {e}")
            results.append({"filename": filename, "error": str(e)})

    # Rapport global
    _print_summary(results)

    # Sauvegarde JSON
    out_file = f"batch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n  Rapport complet sauvegardé : {out_file}\n")


def _print_summary(results: list):
    phishing = [r for r in results if r.get("verdict") == "PHISHING"]
    suspect  = [r for r in results if r.get("verdict") == "SUSPECT"]
    legit    = [r for r in results if r.get("verdict") == "LEGITIME"]
    errors   = [r for r in results if "error" in r]

    print(f"\n{'='*50}")
    print(f"{BOLD}  RÉSUMÉ DE L'ANALYSE{RESET}")
    print(f"{'='*50}")
    print(f"  Total analysé : {len(results)}")
    print(f"  {RED}{BOLD}PHISHING{RESET}  : {len(phishing)}")
    print(f"  {YELLOW}SUSPECT{RESET}   : {len(suspect)}")
    print(f"  {GREEN}LEGITIME{RESET}  : {len(legit)}")
    print(f"  Erreurs    : {len(errors)}")
    print(f"{'='*50}")

    if phishing:
        print(f"\n  {RED}Emails suspects à bloquer :{RESET}")
        for r in phishing:
            score = r.get("score", "?")
            print(f"    [{score}/100] {r.get('filename')} — {r.get('sender', '')}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python batch_analyzer.py <dossier_emails/>")
        sys.exit(1)

    analyze_folder(sys.argv[1])

