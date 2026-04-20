"""
Agent principal de détection de phishing
Combine analyse ML classique + LLM (Ollama)
"""

import json
from langchain_ollama import OllamaLLM
from langchain.prompts import PromptTemplate
from feature_extractor import FeatureExtractor
from email_parser import parse_email
from report import generate_report


MODEL_NAME = "mistral"  # Modèle local via Ollama

llm = OllamaLLM(model=MODEL_NAME)

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
