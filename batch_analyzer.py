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
