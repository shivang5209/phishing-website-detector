from pathlib import Path
import os


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DEFAULT_ARTIFACT_PATH = DATA_DIR / "model_artifact.pkl"
REQUEST_TIMEOUT_SECONDS = 5
HTTP_USER_AGENT = "PhishingDetectorMVP/1.0"
REPUTATION_LOOKUP_TIMEOUT_SECONDS = 4
ENABLE_REPUTATION_LOOKUPS = os.getenv("ENABLE_REPUTATION_LOOKUPS", "1").strip().lower() not in {"0", "false", "no"}

SUSPICIOUS_TLDS = {
    "zip",
    "review",
    "country",
    "kim",
    "work",
    "support",
    "click",
    "top",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
}

PHISHING_KEYWORDS = {
    "login",
    "verify",
    "verify account",
    "update",
    "update payment",
    "banking",
    "confirm",
    "confirm identity",
    "secure",
    "security alert",
    "account suspended",
    "reset password",
    "otp",
    "aadhar",
    "pan",
    "wallet",
    "gift card",
}
