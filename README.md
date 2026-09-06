# 🔐 URL Phishing Detector

*Lightweight phishing URL detection application based on **Machine Learning**, with an optional **AI cybersecurity assistant**.*

🔗 **Live Demo:** https://phishscan-i-f.streamlit.app

📁 **GitHub:** https://github.com/islemfarhat1/phishing-detection

---

## 🎯 Objective

The objective of this project is to detect whether a URL is potentially associated with a phishing attack by analyzing **only the URL structure**, without loading or visiting the target webpage. This approach provides fast analysis while avoiding direct requests to user‑supplied URLs.

---

## 🏗️ Architecture

```text
Raw URL │ ▼ Feature Extraction (20 URL features)
          │ ▼ Random Forest Model (forest.json)
          │ ▼ Prediction + Risk Analysis + Security Indicators
          │ ▼ Streamlit Interface
          │ ▼ Optional AI Assistant (Groq / LLaMA)
```

> **Important:** The LLM does **not** perform the phishing classification. The Random Forest model is the only component responsible for the phishing prediction. The AI assistant is an optional complementary component used for cybersecurity assistance and explanations.

---

## ⚙️ Machine Learning Pipeline

### Dataset
- **Source:** Web Page Phishing Detection Dataset (Kaggle)
- **Size:** 11,430 URLs
- **Classes:** Approximately 50 % phishing / 50 % legitimate
- **Split:** 80 % training / 20 % testing (stratified, random_state = 42)
- **Test set:** 2,286 URLs

The model is trained using URL‑based characteristics rather than webpage content.

### Feature Engineering
| Feature | Description |
|---|---|
| URLLength | Total length of the URL |
| DomainLength | Length of the domain |
| DigitRatio | Ratio of digits to total URL length |
| PathDepth | Depth of the URL path |
| NumSubdomains | Number of subdomains |
| TLDRiskScore | Heuristic risk score associated with the TLD |
| BrandKeyword | Presence of known brand‑related keywords |
| LoginSecureWord | Presence of keywords such as *login* or *secure* |
| HTTPS | Whether HTTPS is used |
| PrefixSuffix‑ | Presence of a hyphen in the domain |
| ConsonantRatio | Ratio used to identify potentially random‑looking domains |
| QueryLength | Length of the query string |
| NumHyphens | Number of hyphens |
| NumDots | Number of dots |
| NumDigitsDomain | Number of digits in the domain |
| ShortURL | Detection of URL shortening services |
| LongURL | Whether the URL exceeds 75 characters |
| NumSlashes | Number of slashes |
| DomainURLRatio | Ratio between domain length and total URL length |
| NumSpecialChars | Number of special characters |

### Model
- **Algorithm:** Random Forest
- **Number of trees:** 60
- **Maximum depth:** 12
- **Serialized model:** `models/forest.json`


The deployed application uses the serialized JSON representation of the Random Forest for inference, avoiding the need for the full training pipeline at startup.

---

## 📊 Performance
| Metric | Score |
|---|---|
| Accuracy | 86.9 % |
| Precision | 0.87 |
| Recall | 0.87 |
| F1‑Score | 0.87 |

The model analyzes only the raw URL and does not fetch the target webpage. This provides fast analysis and avoids making network requests to user‑supplied URLs. Because the model relies exclusively on URL‑based features, its performance is inherently limited compared with approaches that also analyse webpage content, DNS information, WHOIS data, or other contextual signals.

---

## 🖥️ Application
The Streamlit application contains three main sections:

### 🔍 Analyze a URL
Users can submit a URL and obtain:
- Phishing / legitimate prediction
- Risk or model score
- Suspicious URL indicators
- Extracted feature values
- Explanation of relevant URL characteristics

### 📖 Anti‑Phishing Guide
A practical cybersecurity guide covering:
- Common phishing indicators
- Suspicious URL characteristics
- Social engineering techniques
- Safe browsing practices
- Examples of suspicious URLs

### 🤖 AI Cybersecurity Assistant
An optional conversational assistant powered by Groq / LLaMA. It can provide:
- Cybersecurity explanations
- Phishing‑awareness guidance
- Security‑related Q&A
- Additional context about suspicious URL characteristics

> The AI assistant does **not** determine whether a URL is phishing or legitimate. The classification remains entirely handled by the Random Forest model.

---

## 🔒 Security Testing
| Test | Payload / Scenario | Result |
|---|---|---|
| XSS | `<script>alert('XSS')</script>` | Not executed |
| Path Traversal | `../../../../etc/passwd` | Not applicable — no user‑controlled file access |
| SSRF | `http://169.254.169.254/latest/meta-data/` | Not applicable — the application does not fetch submitted URLs |
| Input Stress | URL longer than 500 characters | Handled without application failure |
| Prompt Injection | Role‑framing / educational‑intent attack | Vulnerability identified and mitigated |
| Model Evasion | Suspicious look‑alike URL | Detected during manual testing |

During security testing, a prompt‑injection issue was identified in the AI assistant. The mitigation included strengthening system‑level instructions with explicit restrictions against providing operational phishing guidance, even when framed as educational.

---

## 🛡️ Security Design Considerations
A key design decision is that the application does **not** retrieve or execute the submitted URL. The URL is treated as input data and analysed locally through feature extraction. This design reduces exposure to:
- Server‑Side Request Forgery (SSRF)
- Access to internal network resources
- Cloud metadata endpoint requests
- Malicious webpage execution
- Remote content‑based attacks

While this significantly reduces the attack surface, it does **not** make the entire application immune to vulnerabilities.

---

## 🚀 Installation
```bash
# 1. Clone the repository
git clone https://github.com/islemfarhat1/phishing-detection.git
cd phishing-detection

# 2. Create a virtual environment (Windows)
python -m venv .venv
.venv\Scripts\Activate.ps1

#   — or on Linux/macOS —
# python -m venv .venv
# source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure the Groq API key
# Create a local .env file with the following line:
# GROQ_API_KEY=your_groq_api_key
# (The .env file is ignored via .gitignore.)

# 5. Run the application
streamlit run app.py
```
The application will be available locally at `http://localhost:8501`.

---

## 📁 Project Structure
```
phishing-detection/
├── app.py                     # Streamlit web application
├── README.md                  # <‑‑ this file
├── requirements.txt           # Python dependencies
├── runtime.txt                # Python runtime configuration
├── .gitignore
├── data/
│   └── dataset.csv            # Dataset used for model development
├── models/
│   ├── forest.json            # Serialized Random Forest model

├── scripts/
│   ├── __init__.py
│   ├── feature_extraction_v2.py   # URL feature extraction pipeline
│   └── train_v2.py                # Model training script


```



---

## 🛠️ Technology Stack
- **Machine Learning:** Python, pandas, NumPy, Random Forest (JSON inference)
- **Web Application:** Streamlit
- **AI Assistant:** Groq API (LLaMA model)
- **Security:** URL‑based phishing detection, input validation, prompt‑injection testing
- **Utilities:** python‑dotenv, Streamlit secrets

---

## 🔬 Future Work
- Add webpage‑content analysis
- Integrate DNS and WHOIS‑based features
- Incorporate external threat‑intelligence sources
- Experiment with XGBoost or other ML models
- Explore deep‑learning approaches for URL classification
- Improve model calibration and probability interpretation
- Add SHAP‑based model explainability
- Expand the security test suite (CI/CD integration)
- Provide a REST API using FastAPI
- Continuously update the phishing dataset

---

## ⚠️ Limitations
- Detection relies exclusively on URL characteristics.
- No inspection of webpage HTML/JavaScript.
- No DNS or WHOIS analysis.
- Phishing techniques evolve; periodic dataset updates are required.
- ML prediction should not be treated as an absolute security verdict.
- The AI assistant is supplementary and does **not** influence the classification decision.

---

## 📌 Project Context
This project explores the intersection of **cybersecurity**, **machine learning**, and **AI‑assisted security**. It demonstrates how URL‑based features can support phishing detection while keeping the application footprint small and the attack surface limited.

---

## 👤 Author
**Islem Farhat** – Computer Engineering Student (Cybersecurity)
- GitHub: https://github.com/islemfarhat1
- Live Demo: https://phishscan-i-f.streamlit.app

---

## 📜 License
This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## 🙏 Acknowledgements
- The authors and contributors of the Kaggle dataset used for this project
- Streamlit for the web‑application framework
- Groq for the LLM inference API
- The open‑source cybersecurity and machine‑learning communities

---


