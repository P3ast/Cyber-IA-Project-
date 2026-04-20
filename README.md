# Agent IA - Détection de Phishing

Agent de détection de phishing combinant **heuristiques ML** et **LLM local** (Ollama/Mistral).

## Stack technique
- Python 3.10+
- Ollama (LLM local, modèle Mistral)
- LangChain (orchestration de l'agent)
- python-whois (vérification âge domaine)
- Exegol (environnement isolé recommandé)

---

## Installation

### 1. Cloner et installer les dépendances
```bash
git clone <repo>
cd phishing-agent
pip install -r requirements.txt
```

### 2. Installer Ollama + télécharger Mistral
```bash
# Installer Ollama : https://ollama.com/download
ollama pull mistral
ollama serve   # Lance le serveur LLM local
```

---

## Utilisation

### Analyser un email unique
```bash
python agent.py samples/phishing_sample.eml
python agent.py samples/legit_sample.eml
```

### Analyser un dossier d'emails
```bash
python batch_analyzer.py samples/
```

---

## Architecture

```
Email brut (.eml)
      │
      ▼
email_parser.py       → extrait sujet, corps, en-têtes, pièces jointes
      │
      ▼
feature_extractor.py  → SPF/DMARC, URLs, keywords, âge domaine
      │
      ├──► Score ML (heuristiques, 40%)
      │
      └──► agent.py → LLM Ollama/Mistral (60%)
                │
                ▼
           report.py → Score final + verdict + recommandation
```

## Scores et verdicts

| Score | Verdict  | Signification                        |
|-------|----------|--------------------------------------|
| 0-30  | LEGITIME | Email probablement sûr               |
| 31-60 | SUSPECT  | À vérifier manuellement              |
| 61-100| PHISHING | Email malveillant, à bloquer         |

## Features analysées

| Feature              | Description                                     |
|----------------------|-------------------------------------------------|
| SPF                  | Vérification du serveur d'envoi autorisé        |
| DMARC                | Politique d'authentification du domaine         |
| Reply-To mismatch    | Réponse vers un domaine différent               |
| URLs suspectes       | TLD malveillants, IP dans l'URL, usurpation     |
| Mots-clés urgents    | "urgent", "bloqué", "vérifiez maintenant"...    |
| Âge du domaine       | Domaine créé récemment = suspect                |
| Pièces jointes       | Présence de fichiers joints                     |
| Analyse LLM          | Ton, contenu, cohérence de l'email              |

## Structure du projet

```
phishing-agent/
├── agent.py             # Agent principal
├── email_parser.py      # Parser .eml
├── feature_extractor.py # Extraction des indicateurs
├── report.py            # Génération des rapports
├── batch_analyzer.py    # Analyse en lot
├── requirements.txt
├── README.md
└── samples/
    ├── phishing_sample.eml
    └── legit_sample.eml
```
