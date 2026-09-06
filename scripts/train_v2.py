import pandas as pd
from pathlib import Path
from pathlib import Path
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix
import joblib
import sys
import os

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = BASE_DIR / "data" / "dataset.csv"
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = BASE_DIR / "data" / "dataset.csv"
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)

# Ajouter le dossier scripts au path pour importer feature_extraction_v2
sys.path.append(os.path.dirname(__file__))
from feature_extraction_v2 import extract_features_v2

# ── 1. Charger le dataset ────────────────────────────────────────
print("Chargement du dataset...")
df = pd.read_csv(DATASET_PATH)
print(f"  Shape: {df.shape}")
print(f"  Labels: {df['status'].value_counts().to_dict()}")

# ── 2. Extraire les features sur toutes les URLs ─────────────────
print("\nExtraction des features (peut prendre 1-2 minutes)...")

records = []
labels = []
errors = 0

for i, row in df.iterrows():
    try:
        feats = extract_features_v2(row['url'])
        records.append(feats)
        labels.append(1 if row['status'] == 'phishing' else 0)
    except Exception as e:
        errors += 1

    if (i + 1) % 1000 == 0:
        print(f"  {i+1}/{len(df)} URLs traitées...")

print(f"  Extraction terminée. Erreurs ignorées: {errors}")

# ── 3. Créer le DataFrame features ──────────────────────────────
X = pd.DataFrame(records)
y = pd.Series(labels)

print(f"\nFeatures extraites: {X.shape[1]}")
print(f"Noms des features: {X.columns.tolist()}")

# ── 4. Train/Test split ─────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\nTrain: {X_train.shape}, Test: {X_test.shape}")

# ── 5. Entraîner Random Forest ──────────────────────────────────
print("\nEntraînement Random Forest...")
rf = RandomForestClassifier(n_estimators=60, max_depth=12, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)

# ── 6. Évaluation ───────────────────────────────────────────────
y_pred = rf.predict(X_test)
acc = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
cm = confusion_matrix(y_test, y_pred)

print(f"\n{'='*40}")
print(f"  Accuracy : {acc:.4f} ({acc*100:.2f}%)")
print(f"  F1 Score : {f1:.4f}")
print(f"  Confusion Matrix:")
print(f"    TN={cm[0,0]}  FP={cm[0,1]}")
print(f"    FN={cm[1,0]}  TP={cm[1,1]}")
print(f"{'='*40}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

# ── 7. Test sur paypal-security-login.xyz ───────────────────────
print("\nTest sur URL suspecte...")
test_url = "https://paypal-security-login.xyz"
feats_test = extract_features_v2(test_url)
X_test_url = pd.DataFrame([feats_test])
pred = rf.predict(X_test_url)[0]
proba = rf.predict_proba(X_test_url)[0]
label = "PHISHING" if pred == 1 else "LEGITIMATE"
print(f"  URL: {test_url}")
print(f"  Prédiction: {label}")
print(f"  Confiance phishing: {proba[1]*100:.1f}%")

# ── 8. Sauvegarder le modèle ────────────────────────────────────

joblib.dump(rf, MODELS_DIR / "phishing_model_v2.pkl")

# Sauvegarder aussi la liste des features (important pour l'app)
feature_names = X.columns.tolist()
joblib.dump(feature_names, MODELS_DIR / "feature_names_v2.pkl")

print(f"\nModèle sauvegardé: models/phishing_model_v2.pkl")
print(f"Features sauvegardées: models/feature_names_v2.pkl")
print("Terminé ✅")
# ── Export vers forest.json (pour deploiement sans scikit-learn) ─────────────
from sklearn.tree import _tree
import json as _json
import numpy as _np

def tree_to_dict(tree):
    t = tree.tree_
    def recurse(node):
        if t.feature[node] == _tree.TREE_UNDEFINED:
            values = t.value[node][0].tolist()
            return {'leaf': True, 'value': int(_np.argmax(values)), 'proba': [v/sum(values) for v in values]}
        return {'feature_idx': int(t.feature[node]), 'threshold': float(t.threshold[node]),
                'left': recurse(int(t.children_left[node])), 'right': recurse(int(t.children_right[node]))}
    return recurse(0)

forest_export = [tree_to_dict(est) for est in rf.estimators_]
export = {'trees': forest_export, 'features': feature_names}
with open(MODELS_DIR / "forest.json", "w", encoding="utf-8") as f:
    _json.dump(export, f)

import os
size = os.path.getsize('models/forest.json') / 1024 / 1024
print(f'forest.json exporte : {size:.2f} MB')
print('Pipeline complet termine.')
