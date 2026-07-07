import re
from urllib.parse import urlparse, parse_qs

BRAND_KEYWORDS = [
    "paypal", "bank", "secure", "login", "account", "verify",
    "update", "signin", "confirm", "amazon", "apple", "microsoft",
    "password", "ebay", "netflix", "google", "facebook"
]

SUSPICIOUS_TLDS = {
    ".xyz": 3, ".tk": 3, ".ml": 3, ".ga": 3, ".cf": 3, ".gq": 3,
    ".top": 2, ".club": 2, ".online": 2, ".click": 2,
    ".info": 1, ".biz": 1
}

SPECIAL_CHARS = ["@", "-", "_", "=", "?", "&", "%"]
VOWELS = set("aeiouAEIOU")


def extract_features_v2(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query

    features = {}

    # ── Features binaires utiles (importance > 1%) ──────────────
    features["LongURL"]         = 1 if len(url) > 75 else -1
    features["ShortURL"]        = 1 if any(s in url for s in ["bit.ly","tinyurl","goo.gl","t.co"]) else -1
    features["PrefixSuffix-"]   = 1 if "-" in domain else -1
    features["HTTPS"]           = 1 if parsed.scheme == "https" else -1
    features["BrandKeyword"]    = 1 if any(b in url.lower() for b in BRAND_KEYWORDS) else -1
    features["LoginSecureWord"] = 1 if ("login" in url.lower() or "secure" in url.lower()) else -1

    # ── Features continues (les plus importantes) ────────────────
    features["URLLength"]       = len(url)
    features["DomainLength"]    = len(domain)
    features["NumHyphens"]      = domain.count('-')
    features["NumDots"]         = url.count('.')
    features["NumDigitsDomain"] = sum(c.isdigit() for c in domain)
    features["NumSubdomains"]   = max(domain.count('.') - 1, 0)
    features["PathDepth"]       = path.count('/')
    digit_count                 = sum(c.isdigit() for c in url)
    features["DigitRatio"]      = round(digit_count / len(url), 3) if len(url) > 0 else 0

    # ── Nouvelles features continues (remplacent les binaires nuls) ─

    # 1. Score de risque du TLD (0-3 selon dangerosité)
    tld_score = 0
    for tld, score in SUSPICIOUS_TLDS.items():
        if domain.endswith(tld):
            tld_score = score
            break
    features["TLDRiskScore"]    = tld_score

    # 2. Nombre total de caractères spéciaux dans l'URL
    features["NumSpecialChars"] = sum(url.count(c) for c in SPECIAL_CHARS)

    # 3. Ratio consonnes/longueur du domaine (domaines random = ratio bizarre)
    letters = [c for c in domain.lower() if c.isalpha()]
    consonants = [c for c in letters if c not in VOWELS]
    features["ConsonantRatio"]  = round(len(consonants) / len(letters), 3) if letters else 0

    # 4. Longueur de la query string
    features["QueryLength"]     = len(query)

    # 5. Nombre de slashes dans l'URL complète
    features["NumSlashes"]      = url.count('/')

    # 6. Ratio longueur domaine / longueur URL
    features["DomainURLRatio"]  = round(len(domain) / len(url), 3) if len(url) > 0 else 0

    return features


# ── Test ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_urls = [
        "https://paypal-security-login.xyz",
        "https://www.google.com",
        "http://192.168.1.1/login@secure.com",
        "https://amazon-verify-account.tk/update?user=1234&confirm=true"
    ]

    for url in test_urls:
        print(f"\nURL : {url}")
        feats = extract_features_v2(url)
        for k, v in feats.items():
            print(f"  {k}: {v}")
        print(f"  → TOTAL : {len(feats)} features")