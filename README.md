# 🔒 RansomEmu

> Framework d'émulation de ransomware intégré à **Exegol**, conçu pour tester la résilience des réseaux face à la propagation automatisée.

⚠️ **Usage autorisé uniquement** — Purple Team / Red Team avec autorisation écrite.

## ✨ Fonctionnalités

- **Reconnaissance automatisée** — BloodHound CE API, scan réseau, énumération AD
- **Agent LLM** — Analyse ML des configurations via Llama 3.1 (Ollama) + LangChain
- **Mouvement latéral** — SMB, WinRM, WMI via Impacket (adaptés dynamiquement par le LLM)
- **Simulation crypto** — Marquage de fichiers (aucun chiffrement réel)
- **Propagation contrôlée** — BFS/DFS avec scope guard et kill-switch
- **Reporting** — Timeline JSON/HTML des actions

## 🚀 Quick Start

### Avec Docker (recommandé)

```bash
# Cloner le repo
git clone <repo-url> && cd ransomemu

# Copier la config
cp .env.example .env

# Lancer
docker compose -f docker/docker-compose.yml up -d

# Utiliser
docker compose -f docker/docker-compose.yml exec ransomemu ransomemu --help
```

### Avec Exegol

```bash
# Copier dans my-resources
cp -r . ~/.exegol/my-resources/ransomemu/
cp exegol-resources/setup/load_user_setup.sh ~/.exegol/my-resources/setup/

# Redémarrer le container Exegol
exegol start <container>

# Utiliser
ransomemu --help
```

### Installation locale (dev)

```bash
python -m venv .venv
source .venv/bin/activate  # ou .venv\Scripts\activate sur Windows
pip install -e ".[dev]"
ransomemu --help
```

## 📋 Commandes

| Commande | Description |
|----------|-------------|
| `ransomemu scan` | Reconnaissance réseau et AD |
| `ransomemu plan` | Plan de propagation via LLM |
| `ransomemu run` | Simulation complète |
| `ransomemu report` | Génération du rapport |
| `ransomemu rollback` | Suppression des marqueurs |

## ⚙️ Configuration

Éditer `config/default.yml` ou utiliser les variables d'environnement (voir `.env.example`).

Options globales : `--dry-run`, `--scope`, `--model`, `--verbose`

## 🧪 Tests

```bash
pytest
```

## 🏗️ Architecture

```
ransomemu/
├── cli.py              # Point d'entrée Click
├── core/               # Config, logging, sécurité
├── agent/              # LLM (Ollama/LangChain)
├── modules/
│   ├── recon/          # BloodHound, scan réseau
│   ├── lateral/        # SMB, WinRM, WMI
│   ├── crypto/         # Simulation marquage
│   └── propagation/    # Engine BFS/DFS
└── reporting/          # JSON/HTML reports
```

## 📜 Licence

MIT — Usage responsable uniquement.
