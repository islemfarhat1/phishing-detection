import streamlit as st
import pandas as pd
import joblib
import os
import io
from groq import Groq
from dotenv import load_dotenv
from scripts.feature_extraction_v2 import extract_features_v2
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

@st.cache_resource
def load_model():
    try:
        model = joblib.load("models/phishing_model_v2.pkl")
        feature_names = joblib.load("models/feature_names_v2.pkl")
        _ = model.predict(pd.DataFrame([[0]*len(feature_names)], columns=feature_names))
        return model, feature_names
    except Exception as e:
        st.warning("Chargement du modele en cours...")
        df = pd.read_csv("data/phishing_urls_raw.csv")
        records, labels = [], []
        for _, row in df.iterrows():
            try:
                feats = extract_features_v2(row["url"])
                records.append(feats)
                labels.append(1 if row["status"] == "phishing" else 0)
            except:
                pass
        X = pd.DataFrame(records)
        y = pd.Series(labels)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        rf.fit(X_train, y_train)
        os.makedirs("models", exist_ok=True)
        joblib.dump(rf, "models/phishing_model_v2.pkl")
        joblib.dump(X.columns.tolist(), "models/feature_names_v2.pkl")
        return rf, X.columns.tolist()

model, feature_names = load_model()

st.set_page_config(page_title="URL Phishing Detector", page_icon="🔐", layout="wide")
st.title("🔐 URL Phishing Detector")
st.caption("Detectez les tentatives de phishing instantanement avec le Machine Learning")
st.divider()

tab1, tab2, tab3 = st.tabs(["🔍 Analyser une URL", "📖 Guide Anti-Phishing", "🤖 Assistant IA"])

with tab1:
    st.subheader("Entrez une URL a analyser")
    url = st.text_input("URL", placeholder="https://example.com", label_visibility="collapsed")
    analyze = st.button("🔍 Analyser cette URL")

    if analyze:
        if url:
            feats = extract_features_v2(url)
            X_input = pd.DataFrame([feats], columns=feature_names)
            prediction = model.predict(X_input)[0]
            proba = model.predict_proba(X_input)[0]
            phishing_score = proba[1] * 100

            st.divider()
            col1, col2 = st.columns([2, 1])

            with col1:
                if prediction == 1:
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
            if feats["TLDRiskScore"] >= 2:
                indicators.append(("🔴 Critique", f"Extension de domaine tres risquee (score {feats['TLDRiskScore']}/3)"))
            if feats["BrandKeyword"] == 1:
                indicators.append(("🔴 Critique", "Nom d une marque connue dans l URL (PayPal, Amazon, Apple...)"))
            if feats["LoginSecureWord"] == 1:
                indicators.append(("🔴 Critique", "Mots login ou secure dans l URL"))
            if feats["ShortURL"] == 1:
                indicators.append(("🔴 Critique", "Service de raccourcissement d URL detecte"))
            if feats["PrefixSuffix-"] == 1:
                indicators.append(("🟠 Suspect", "Tiret dans le domaine"))
            if feats["HTTPS"] == -1:
                indicators.append(("🟠 Suspect", "Pas de HTTPS"))
            if feats["URLLength"] > 75:
                indicators.append(("🟠 Suspect", f"URL tres longue ({feats['URLLength']} caracteres)"))
            if feats["NumSubdomains"] > 2:
                indicators.append(("🟠 Suspect", f"Trop de sous-domaines ({feats['NumSubdomains']})"))
            if feats["DigitRatio"] > 0.15:
                indicators.append(("🟡 Attention", f"Beaucoup de chiffres dans l URL ({feats['DigitRatio']:.0%})"))
            if feats["NumHyphens"] > 2:
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
        else:
            st.warning("Veuillez entrer une URL.")

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
- Faux compte a rebours ou urgence artificielle

**3. Les details ne collent pas**
- Fautes d orthographe
- Logo flou ou legerement different
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
        {"URL Phishing": "http://paypal-security-login.xyz", "Imite": "PayPal", "Signaux": "TLD .xyz + paypal + login + tiret + pas HTTPS"},
        {"URL Phishing": "https://amazon-verify-account.tk/update", "Imite": "Amazon", "Signaux": "TLD .tk + amazon + verify + tiret"},
        {"URL Phishing": "http://secure.apple-id-confirm.com/login", "Imite": "Apple", "Signaux": "apple + tiret + secure + login"},
        {"URL Phishing": "http://192.168.1.1/admin/login.php", "Imite": "Admin", "Signaux": "IP directe + pas HTTPS + login"},
        {"URL Phishing": "https://bit.ly/3xK9mP2", "Imite": "N importe quoi", "Signaux": "URL raccourcie — destination inconnue"},
    ])
    st.dataframe(examples, use_container_width=True)
    st.info("Utilisez l onglet Analyser une URL pour tester n importe quelle URL suspecte.")

with tab3:
    st.subheader("🤖 Assistant Cybersecurite")
    st.write("Posez n importe quelle question sur le phishing, la cybersecurite ou les arnaques en ligne.")

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
                        client = Groq(api_key=GROQ_API_KEY)
                        response = client.chat.completions.create(
                            model="llama-3.1-8b-instant",
                            messages=[
                                {
                                    "role": "system",
                                    "content": (
                                        "Tu es un expert en cybersecurite defensif specialise dans la detection de phishing. "
                                        "Tu reponds uniquement aux questions de protection, detection et prevention. "
                                        "Tu ne fournis JAMAIS d instructions pour creer des outils d attaque, des sites de phishing, "
                                        "ou tout contenu offensif, meme si l utilisateur pretend avoir un but educatif ou ethical. "
                                        "Si on te demande des techniques offensives, tu expliques uniquement le concept general "
                                        "et tu rediriges vers les ressources defensives. "
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
