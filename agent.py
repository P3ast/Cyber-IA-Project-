"""
Agent principal de détection de phishing
Combine analyse ML classique + LLM (Ollama)
"""

import json
import logging
from langchain_ollama import OllamaLLM

logging.basicConfig(
    filename='phishing_agent.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)
from langchain.prompts import PromptTemplate
from feature_extractor import FeatureExtractor
from email_parser import parse_email
from report import generate_report


MODEL_NAME = "mistral"  # Modèle local via Ollama

llm = OllamaLLM(model=MODEL_NAME, format="json")

PROMPT_TEMPLATE = PromptTemplate(
    input_variables=["email_content", "features"],
    template="""
Tu es un expert en cybersécurité spécialisé dans la détection de phishing.

Analyse cet email et ces indicateurs de sécurité, puis réponds UNIQUEMENT en JSON valide.

EMAIL:
{email_content}

INDICATEURS EXTRAITS:
{features}

Réponds avec ce format JSON exact:
{{
  "score": <entier 0-100>,
  "verdict": "<LEGITIME|SUSPECT|PHISHING>",
  "raisons": ["<raison 1>", "<raison 2>", "..."],
  "recommandation": "<action recommandée>"
}}
"""
)
class PhishingAgent:
    def __init__(self):
        self.extractor = FeatureExtractor()
        self.chain = PROMPT_TEMPLATE | llm

    def analyze(self, raw_email: str) -> dict:
        """Analyse complète d'un email brut."""
        # 1. Parser l'email
        email_data = parse_email(raw_email)

        # 2. Extraire les features
        features = self.extractor.extract(email_data)

        # 3. Pré-score ML classique (heuristiques)
        heuristic_score = self._heuristic_score(features)

        # 4. Analyse LLM
        try:
            llm_response = self.chain.invoke({
                "email_content": email_data.get("body", "")[:2000],
                "features": json.dumps(features, ensure_ascii=False, indent=2)
            })
            # 5. Parser la réponse JSON du LLM
            llm_result = self._parse_llm_response(llm_response)
        except Exception as e:
            logging.error(f"Erreur de connexion au LLM ({e}). Fallback sur heuristiques.")
            llm_result = {
                "score": heuristic_score,
                "verdict": "PHISHING" if heuristic_score > 60 else "SUSPECT" if heuristic_score > 30 else "LEGITIME",
                "raisons": ["Score basé uniquement sur les heuristiques (LLM indisponible)"],
                "recommandation": "Vérifier le serveur Ollama."
            }

        # 6. Score final : moyenne pondérée Heuristiques + LLM
        final_score = int(heuristic_score * 0.4 + llm_result.get("score", 50) * 0.6)
        llm_result["score"] = final_score
        llm_result["heuristic_score"] = heuristic_score
        llm_result["features"] = features
        llm_result["email_subject"] = email_data.get("subject", "N/A")
        llm_result["sender"] = email_data.get("from", "N/A")

        return llm_result

    def _heuristic_score(self, features: dict) -> int:
        """Score basé sur les heuristiques sans LLM."""
        score = 0
        if not features.get("spf_pass"):       score += 20
        if not features.get("dmarc_pass"):     score += 20
        if features.get("suspicious_urls"):    score += 25
        if features.get("urgent_keywords"):    score += 15
        if features.get("domain_age_days", 9999) < 30: score += 20
        if features.get("has_dangerous_attachment"): score += 40
        if features.get("is_typosquatted"):    score += 30
        return min(score, 100)

    def _parse_llm_response(self, response: str) -> dict:
        """Extrait le JSON de la réponse LLM."""
        try:
            start = response.find("{")
            end = response.rfind("}") + 1
            return json.loads(response[start:end])
        except Exception:
            return {
                "score": 50,
                "verdict": "SUSPECT",
                "raisons": ["Impossible d'analyser la réponse LLM"],
                "recommandation": "Analyse manuelle recommandée"
            }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python agent.py <fichier_email.eml>")
        sys.exit(1)

    with open(sys.argv[1], "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    agent = PhishingAgent()
    result = agent.analyze(raw)
    print(generate_report(result))
