import os
import json
from typing import List, Tuple, Dict, Any
import numpy as np
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from groq import Groq
from scripts.feature_extraction_v2 import extract_features_v2

load_dotenv()

try:
    GROQ_API_KEY = st.secrets["GROQ_API_KEY"]
except Exception:
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")

def normalise_url(url):
    cleaned = url.strip()
    if not cleaned.lower().startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
    return cleaned

@st.cache_data(show_spinner="Chargement du modele...")
def load_model():
    with open("models/forest.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["trees"], data["features"]

def predict(trees, feature_names, url):
    url = normalise_url(url)
    feats = extract_features_v2(url)
    X = [feats.get(f, 0) for f in feature_names]
    def traverse(node, x):
        if node.get("leaf"):
            return node["proba"]
        if x[node["feature_idx"]] <= node["threshold"]:
            return traverse(node["left"], x)
        return traverse(node["right"], x)
    probas = [traverse(tree, X) for tree in trees]
    avg = [sum(p[i] for p in probas) / len(probas) for i in range(2)]
    return int(__import__("numpy").argmax(avg)), avg, feats

trees, feature_names = load_model()

st.set_page_config(page_title="URL Phishing Detector", page_icon="🔐", layout="wide")
st.title("🔐 URL Phishing Detector")
st.caption("Detectez les tentatives de phishing instantanement avec le Machine Learning")
st.divider()

tab1, tab2, tab3 = st.tabs(["🔍 Analyser une URL", "📖 Guide Anti-Phishing", "🤖 Assistant IA"])

with tab1:
    st.subheader("Entrez une URL a analyser")
    user_url = st.text_input("URL", placeholder="https://example.com", label_visibility="collapsed")
    if st.button("🔍 Analyser"):
        if not user_url:
            st.warning("Veuillez entrer une URL.")
        else:
            try:
                pred, proba, feats = predict(trees, feature_names, user_url)
                phishing_score = proba[1] * 100
                st.divider()
                col1, col2 = st.columns([2, 1])
                with col1:
                    if pred == 1:
                        st.error("PHISHING DETECTE")
                        st.write("Cette URL presente des caracteristiques typiques d une attaque de phishing.")
                    else:
                        st.success("URL LEGITIME")
                        st.write("Aucun signe majeur de phishing detecte.")
                    st.progress(int(phishing_score), text=f"Niveau de risque : {phishing_score:.1f}%")
                with col2:
                    st.metric("Score de risque", f"{phishing_score:.1f}%")
                    if phishing_score >= 70:
                        st.write("🔴 Risque ELEVE")
                    elif phishing_score >= 40:
                        st.write("🟠 Risque MODERE")
                    else:
                        st.write("🟢 Risque FAIBLE")
                st.divider()
                st.subheader("Pourquoi ce resultat ?")
                indicators = []
                if feats.get("TLDRiskScore", 0) >= 2:
                    indicators.append(("🔴 Critique", f"Extension de domaine tres risquee (score {feats['TLDRiskScore']}/3)"))
                if feats.get("BrandKeyword", -1) == 1:
                    indicators.append(("🔴 Critique", "Nom d une marque connue dans l URL (PayPal, Amazon, Apple...)"))
                if feats.get("LoginSecureWord", -1) == 1:
                    indicators.append(("🔴 Critique", "Mots login ou secure dans l URL"))
                if feats.get("ShortURL", -1) == 1:
                    indicators.append(("🔴 Critique", "Service de raccourcissement d URL detecte"))
                if feats.get("PrefixSuffix-", -1) == 1:
                    indicators.append(("🟠 Suspect", "Tiret dans le domaine"))
                if feats.get("HTTPS", -1) == -1:
                    indicators.append(("🟠 Suspect", "Pas de HTTPS"))
                if feats.get("URLLength", 0) > 75:
                    indicators.append(("🟠 Suspect", f"URL tres longue ({feats['URLLength']} caracteres)"))
                if feats.get("NumSubdomains", 0) > 2:
                    indicators.append(("🟠 Suspect", f"Trop de sous-domaines ({feats['NumSubdomains']})"))
                if feats.get("DigitRatio", 0) > 0.15:
                    indicators.append(("🟡 Attention", f"Beaucoup de chiffres ({feats['DigitRatio']:.0%})"))
                if feats.get("NumHyphens", 0) > 2:
                    indicators.append(("🟡 Attention", f"Nombreux tirets ({feats['NumHyphens']}) dans le domaine"))
                if indicators:
                    for niveau, msg in indicators:
                        st.write(f"**{niveau}** — {msg}")
                else:
                    st.write("Aucun indicateur suspect detecte.")
                st.divider()
                with st.expander("Details techniques — toutes les features"):
                    feat_df = pd.DataFrame(list(feats.items()), columns=["Feature", "Valeur"])
                    st.dataframe(feat_df, use_container_width=True)
            except Exception as e:
                st.error(f"Erreur : {e}")

with tab2:
    st.subheader("📖 Comment reconnaitre le phishing ?")
    st.write("Le phishing imite des sites legitimes pour voler vos identifiants ou donnees bancaires.")
    st.divider()
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### 🔴 Signes d alerte")
        st.markdown("""
**1. L URL est suspecte**
- Domaine avec tirets : paypal-secure-login.com
- Extension inhabituelle : .xyz .tk .top
- Marque dans sous-domaine : paypal.attacker.com

**2. La page vous presse**
- Votre compte sera suspendu dans 24h
- Urgence artificielle

**3. Les details ne collent pas**
- Fautes d orthographe
- Logo flou
        """)
    with col2:
        st.markdown("### 🟢 Bonnes pratiques")
        st.markdown("""
**1. Verifiez toujours l URL**
- secure.paypal.com = legitime
- paypal.secure-login.com = phishing

**2. Ne cliquez pas sur les liens des emails**
- Tapez l adresse directement

**3. Activez le 2FA**
- Meme si vos identifiants sont voles, le pirate ne peut pas se connecter

**4. HTTPS ne garantit pas la legitimite**
- Mais l absence de HTTPS est un signal d alarme
        """)
    st.divider()
    st.markdown("### 🧪 Exemples reels de phishing")
    examples = pd.DataFrame([
        {"URL": "http://paypal-security-login.xyz", "Imite": "PayPal", "Signaux": "TLD .xyz + paypal + login + tiret"},
        {"URL": "https://amazon-verify-account.tk/update", "Imite": "Amazon", "Signaux": "TLD .tk + amazon + verify"},
        {"URL": "http://secure.apple-id-confirm.com/login", "Imite": "Apple", "Signaux": "apple + secure + login"},
        {"URL": "http://192.168.1.1/admin/login.php", "Imite": "Admin", "Signaux": "IP directe + pas HTTPS"},
        {"URL": "https://bit.ly/3xK9mP2", "Imite": "Inconnu", "Signaux": "URL raccourcie"},
    ])
    st.dataframe(examples, use_container_width=True)
    st.info("Utilisez l onglet Analyser une URL pour tester n importe quelle URL suspecte.")

with tab3:
    st.subheader("🤖 Assistant Cybersecurite")
    st.write("Posez n importe quelle question sur le phishing ou la cybersecurite.")
    if "messages" not in st.session_state:
        st.session_state.messages = []
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.write(msg["content"])
    user_input = st.chat_input("Posez votre question...")
    if user_input:
        if not GROQ_API_KEY:
            st.error("Cle API Groq non configuree.")
        else:
            st.session_state.messages.append({"role": "user", "content": user_input})
            with st.chat_message("user"):
                st.write(user_input)
            with st.chat_message("assistant"):
                with st.spinner("Reflexion en cours..."):
                    try:
                        client = Groq(api_key=GROQ_API_KEY, timeout=20)
                        response = client.chat.completions.create(
                            model="llama-3.3-70b-versatile",
                            messages=[
                                {
                                    "role": "system",
                                    "content": (
                                        "Tu es un expert en cybersecurite defensif specialise dans la detection de phishing. "
                                        "Tu reponds uniquement aux questions de protection, detection et prevention. "
                                        "Tu ne fournis JAMAIS d instructions pour creer des outils d attaque ou des sites de phishing. "
                                        "Tu reponds en francais, de facon claire et pedagogique."
                                    )
                                },
                                *st.session_state.messages
                            ],
                            max_tokens=1024,
                            temperature=0.7
                        )
                        reply = response.choices[0].message.content
                        st.write(reply)
                        st.session_state.messages.append({"role": "assistant", "content": reply})
                    except Exception as e:
                        st.error(f"Erreur API : {e}")
    if st.session_state.messages:
        if st.button("Effacer la conversation"):
            st.session_state.messages = []
            st.rerun()
