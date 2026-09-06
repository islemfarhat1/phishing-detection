# -*- coding: utf-8 -*-
"""Streamlit front‑end for the Phishing‑URL detector.

This version focuses on:
- Robust URL normalisation (adds missing scheme, strips whitespace).
- Secure handling of the Groq API key via `st.secrets` with a fallback to the environment.
- Minimal dependencies – the model is loaded from `models/forest.json` (JSON) without `scikit‑learn`.
- Improved caching using `st.cache_data` (lighter than `st.cache_resource`).
- Clear separation of concerns and type‑annotated helper functions.
- Defensive error handling for the Groq chat call.
"""

import os
import json
from typing import List, Tuple, Dict, Any

import numpy as np
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from groq import Groq

# Local import – feature extraction v2
from scripts.feature_extraction_v2 import extract_features_v2

# ---------------------------------------------------------------------------
# Configuration & Secrets
# ---------------------------------------------------------------------------
load_dotenv()  # Load .env during local development only
GROQ_API_KEY: str | None = st.secrets.get("GROQ_API_KEY") or os.getenv("GROQ_API_KEY")

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------
def _normalise_url(url: str) -> str:
    """Return a clean URL.

    - Strips surrounding whitespace.
    - Guarantees a scheme (defaults to ``https://``) if missing.
    - Leaves the URL untouched if it already contains ``http://`` or ``https://``.
    """
    cleaned = url.strip()
    if not cleaned.lower().startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
    return cleaned

# ---------------------------------------------------------------------------
# Model loading (cached)
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner="Chargement du modele…")
def load_model() -> Tuple[List[Dict[str, Any]], List[str]]:
    """Load the Random‑Forest model from ``models/forest.json``."""
    model_path = os.path.join("models", "forest.json")
    try:
        with open(model_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data["trees"], data["features"]
    except FileNotFoundError:
        st.error(f"⚠️ Model file not found at `{model_path}`.")
        raise
    except (json.JSONDecodeError, KeyError) as exc:
        st.error("⚠️ Corrupted model file – redeploy the latest version.")
        raise exc

# ---------------------------------------------------------------------------
# Prediction engine
# ---------------------------------------------------------------------------
def predict(trees: List[Dict[str, Any]], feature_names: List[str], url: str) -> Tuple[int, List[float], Dict[str, Any]]:
    """Predict phishing probability for a single URL."""
    url = _normalise_url(url)
    feats = extract_features_v2(url)
    X = [feats.get(f, 0) for f in feature_names]

    def _traverse(node: Dict[str, Any], x: List[Any]) -> List[float]:
        if node.get("leaf"):
            return node["proba"]
        idx = node["feature_idx"]
        if x[idx] <= node["threshold"]:
            return _traverse(node["left"], x)
        else:
            return _traverse(node["right"], x)

    probas = [_traverse(tree, X) for tree in trees]
    avg = [sum(p[i] for p in probas) / len(probas) for i in range(2)]
    prediction = int(np.argmax(avg))
    return prediction, avg, feats

# ---------------------------------------------------------------------------
# Streamlit UI
# ---------------------------------------------------------------------------
st.set_page_config(page_title="URL Phishing Detector", page_icon="🔐", layout="wide")
st.title("🔐 URL Phishing Detector")
st.caption("Détectez les tentatives de phishing instantanément avec le Machine Learning")
st.divider()

# Load model once (cached)
trees, feature_names = load_model()

# UI tabs
tab1, tab2, tab3 = st.tabs([
    "🔍 Analyser une URL",
    "📖 Guide Anti‑Phishing",
    "🤖 Assistant IA",
])

# ---------------------------------------------------------------------------
# Tab 1 – URL**Next step – apply the PowerShell snippet you already have**

You already supplied a PowerShell block that writes the complete, polished `app.py` to your repository:

```powershell
$code = @'
# -*- coding: utf-8 -*-
"""Streamlit front‑end for the Phishing‑URL detector.

This version focuses on:
- Robust URL normalisation (adds missing scheme, strips whitespace).
- Secure handling of the Groq API key via `st.secrets` with a fallback to the environment.
- Minimal dependencies – the model is loaded from `models/forest.json` (JSON) without `scikit‑learn`.
- Improved caching using `st.cache_data` (lighter than `st.cache_resource`).
- Clear separation of concerns and type‑annotated helper functions.
- Defensive error handling for the Groq chat call.
"""

import os
import json
from typing import List, Tuple, Dict, Any

import numpy as np
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from groq import Groq

# Local import – feature extraction v2
from scripts.feature_extraction_v2 import extract_features_v2

# ---------------------------------------------------------------------------
# Configuration & Secrets
# ---------------------------------------------------------------------------
load_dotenv()  # Load .env during local development only
GROQ_API_KEY: str | None = st.secrets.get("GROQ_API_KEY") or os.getenv("GROQ_API_KEY")

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------
def _normalise_url(url: str) -> str:
    """Return a clean URL.

    - Strips surrounding whitespace.
    - Guarantees a scheme (defaults to ``https://``) if missing.
    - Leaves the URL untouched if it already contains ``http://`` or ``https://``.
    """
    cleaned = url.strip()
    if not cleaned.lower().startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
    return cleaned

# ---------------------------------------------------------------------------
# Model loading (cached)
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner="Chargement du modele…")
def load_model() -> Tuple[List[Dict[str, Any]], List[str]]:
    """Load the Random‑Forest model from ``models/forest.json``."""
    model_path = os.path.join("models", "forest.json")
    try:
        with open(model_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data["trees"], data["features"]
    except FileNotFoundError:
        st.error(f"⚠️ Model file not found at `{model_path}`.")
        raise
    except (json.JSONDecodeError, KeyError) as exc:
        st.error("⚠️ Corrupted model file – redeploy the latest version.")
        raise exc

# ---------------------------------------------------------------------------
# Prediction engine
# ---------------------------------------------------------------------------
def predict(trees: List[Dict[str, Any]], feature_names: List[str], url: str) -> Tuple[int, List[float], Dict[str, Any]]:
    """Predict phishing probability for a single URL."""
    url = _normalise_url(url)
    feats = extract_features_v2(url)
    X = [feats.get(f, 0) for f in feature_names]

    def _traverse(node: Dict[str, Any], x: List[Any]) -> List[float]:
        if node.get("leaf"):
            return node["proba"]
        idx = node["feature_idx"]
        if x[idx] <= node["threshold"]:
            return _traverse(node["left"], x)
        else:
            return _traverse(node["right"], x)

    probas = [_traverse(tree, X) for tree in trees]
    avg = [sum(p[i] for p in probas) / len(probas) for i in range(2)]
    prediction = int(np.argmax(avg))
    return prediction, avg, feats

# ---------------------------------------------------------------------------
# Streamlit UI
# ---------------------------------------------------------------------------
st.set_page_config(page_title="URL Phishing Detector", page_icon="🔐", layout="wide")
st.title("🔐 URL Phishing Detector")
st.caption("Détectez les tentatives de phishing instantanément avec le Machine Learning")
st.divider()

# Load model once (cached)
trees, feature_names = load_model()

# UI tabs
tab1, tab2, tab3 = st.tabs([
    "🔍 Analyser une URL",
    "📖 Guide Anti‑Phishing",
    "🤖 Assistant IA",
])

# ---------------------------------------------------------------------------
# Tab 1 – URL analysis
# ---------------------------------------------------------------------------
with tab1:
    st.subheader("Entrez une URL à analyser")
    user_url = st.text_input("URL", placeholder="https://example.com", label_visibility="collapsed")
    if st.button("🔍 Analyser"):
        if not user_url:
            st.warning("⚠️ Veuillez entrer une URL.")
        else:
            try:
                pred, proba, feats = predict(trees, feature_names, user_url)
                phishing_score = proba[1] * 100
                col1, col2 = st.columns([2, 1])
                with col1:
                    if pred == 1:
                        st.error("PHISHING DÉTECTÉ")
                        st.write("Cette URL présente des caractéristiques typiques d'une attaque de phishing.")
                    else:
                        st.success("URL LÉGITIME")
                        st.write("Aucun signe majeur de phishing détecté.")
                    st.progress(int(phishing_score), text=f"Niveau de risque : {phishing_score:.1f}%")
                with col2:
                    st.metric("Score de risque", f"{phishing_score:.1f}%")
                    if phishing_score >= 70:
                        st.write("🔴 Risque ÉLEVÉ")
                    elif phishing_score >= 40:
                        st.write("🟠 Risque MODÉRÉ")
                    else:
                        st.write("🟢 Risque FAIBLE")
                st.divider()
                st.subheader("Pourquoi ce résultat ?")
                indicators: List[Tuple[str, str]] = []
                if feats.get("TLDRiskScore", 0) >= 2:
                    indicators.append(("🔴 Critique", f"Extension de domaine très risquée (score {feats['TLDRiskScore']}/3)"))
                if feats.get("BrandKeyword", -1) == 1:
                    indicators.append(("🔴 Critique", "Nom d'une marque connue dans l'URL (PayPal, Amazon, Apple…)"))
                if feats.get("LoginSecureWord", -1) == 1:
                    indicators.append(("🔴 Critique", "Mots 'login' ou 'secure' dans l'URL"))
                if feats.get("ShortURL", -1) == 1:
                    indicators.append(("🔴 Critique", "Service de raccourccissement d'URL détecté"))
                if feats.get("PrefixSuffix-", -1) == 1:
                    indicators.append(("🟠 Suspect", "Tiret dans le domaine"))
                if feats.get("HTTPS", -1) == -1:
                    indicators.append(("🟠 Suspect", "Pas de HTTPS"))
                if feats.get("URLLength", 0) > 75:
                    indicators.append(("🟠 Suspect", f"URL très longue ({feats['URLLength']} caractères)"))
                if feats.get("NumSubdomains", 0) > 2:
                    indicators.append(("🟠 Suspect", f"Trop de sous‑domaines ({feats['NumSubdomains']})"))
                if feats.get("DigitRatio", 0) > 0.15:
                    indicators.append(("🟡 Attention", f"Beaucoup de chiffres dans l'URL ({feats['DigitRatio']:.0%})"))
                if feats.get("NumHyphens", 0) > 2:
                    indicators.append(("🟡 Attention", f"Nombreux tirets ({feats['NumHyphens']}) dans le domaine"))
                if indicators:
                    for level, msg in indicators:
                        st.write(f"**{level}** — {msg}")
                else:
                    st.write("Aucun indicateur suspect détecté.")
                st.divider()
                with st.expander("Détails techniques — toutes les features"):
                    df = pd.DataFrame(list(feats.items()), columns=["Feature", "Valeur"])
                    st.dataframe(df, use_container_width=True)
            except Exception as exc:
                st.error(f"❌ Erreur lors du calcul : {exc}")

# ---------------------------------------------------------------------------
# Tab 2 – Anti‑phishing guide (static content)
# ---------------------------------------------------------------------------
with tab2:
    st.subheader("📖 Comment reconnaître le phishing ?")
    st.write("Le phishing imite des sites légitimes pour voler vos identifiants ou données bancaires.")
    st.divider()
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(
            """
### 🔴 Signes d’alerte
- Domaine avec tirets : `paypal-secure-login.com`
- Extensions inhabituelles : `.xyz`, `.tk`, `.top`
- Marque dans sous‑domaine : `paypal.attacker.com`
- Pression temporelle : "Votre compte sera suspendu dans 24h"
- Fautes d’orthographe, logo flou
""")
    with col2:
        st.markdown(
            """
### 🟢 Bonnes pratiques
- Vérifiez toujours l’URL (ex. `secure.paypal.com` vs `paypal.secure-login.com`)
- Ne cliquez pas sur les liens d’e‑mail, tapez l’adresse directement
- Activez le 2FA
- HTTPS n’est pas une garantie, mais son absence est un signal d’alerte
""")
    st.divider()
    st.markdown("### 🧪 Exemples réels de phishing")
    examples = pd.DataFrame([
        {"URL Phishing": "http://paypal-security-login.xyz", "Imite": "PayPal",
         "Signaux": "TLD .xyz + paypal + login + tiret + pas HTTPS"},
        {"URL Phishing": "https://amazon-verify-account.tk/update", "Imite": "Amazon",
         "Signaux": "TLD .tk + amazon + verify + tiret"},
        {"URL Phishing": "http://secure.apple-id-confirm.com/login", "Imite": "Apple",
         "Signaux": "apple + tiret + secure + login"},
        {"URL Phishing": "http://192.168.1.1/admin/login.php", "Imite": "Admin",
         "Signaux": "IP directe + pas HTTPS + login"},
        {"URL Phishing": "https://bit.ly/3xK9mP2", "Imite": "N’importe quoi",
         "Signaux": "URL raccourcie — destination inconnue"},
    ])
    st.dataframe(examples, use_container_width=True)
    st.info("Utilisez l’onglet *Analyser une URL* pour tester n’importe quelle URL suspecte.")

# ---------------------------------------------------------------------------
# Tab 3 – IA assistant (Groq) – defensive prompt
# ---------------------------------------------------------------------------
with tab3:
    st.subheader("🤖 Assistant Cybersécurité")
    st.write("Posez n'importe quelle question sur le phishing, la cybersécurité ou les arnaques en ligne.")
    if "messages" not in st.session_state:
        st.session_state.messages = []
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.write(msg["content"])
    user_input = st.chat_input("Posez votre question…")
    if user_input:
        if not GROQ_API_KEY:
            st.error("⚙️ Clé API Groq non configurée.")
        else:
            st.session_state.messages.append({"role": "user", "content": user_input})
            with st.chat_message("user"):
                st.write(user_input)
            with st.chat_message("assistantassistant"):
                with st.spinner("Réflexion en cours…"):
                    try:
                        client = Groq(api_key=GROQ_API_KEY, timeout=20)
                        response = client.chat.completions.create(
                            model="llama3-70b-8192",
                            messages=[
                                {
                                    "role": "system",
                                    "content": (
                                        "Tu es un expert en cybersécurité défensive spécialisé dans la détection de phishing. "
                                        "Tu réponds uniquement aux questions de protection, détection et prévention. "
                                        "Tu ne fournis JAMAIS d'instructions pour créer des outils d'attaque, des sites de phishing, ou tout contenu offensif. "
                                        "Si on te demande des techniques offensives, tu expliques le concept général et rediriges vers les ressources défensives. "
                                        "Réponds en français, de façon claire et pédagogique."
                                    ),
                                },
                                *st.session_state.messages,
                            ],
                            max_tokens=1024,
                            temperature=0.7,
                        )
                        reply = response.choices[0].message.content
                        st.write(reply)
                        st.session_state.messages.append({"role": "assistantassistant", "content": reply})
                    except Exception as e:
                        st.error(f"❌ Erreur API : {e}")
    if st.session_state.messages and st.button("Effacer la conversation"):
        st.session_state.messages = []
        st.rerun()
