"""
Security & Credential Management Utility for CyberVision.
Provides robust secret decoding, environment variable resolution, and offline fallback.
Supports raw strings, 'base64:...' prefixes, and obfuscated fallback decoding.
"""

import os
import base64
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# Obfuscated runtime credentials (fallback when env is not explicitly set)
_ENCODED_DEFAULTS = {
    "ABUSEIPDB_API_KEY": "NmYyM2YyY2UxMDZlYTQ1YTMxMDc5OGU3NDkzM2NiOWFjNmM1MjU1ZTVhZDMwZTViZjhhYTQyMGUzZmE2YTcwZjA4YjMzMWYyZTEwN2Q4MmY=",
    "ALIENVAULT_OTX_API_KEY": "NjBkOGU3Njk0MTUzYjk3OGMyMWFmZGM2Njk4MzQ1YmVlNmY4N2JmYjdhOTNjZGQxOTZiYTU1MTliOWJmMTMzNQ==",
    "VIRUSTOTAL_API_KEY": "Y2YzMzQ2ODg3ZTY5NDliOTI0MWM4NjI0YzM4ZmUzNTM3MmQzMTI2NzA3Y2Y1Y2Q2MDk3YmM2MTg3YWFiZTcyYg==",
    "GREYNOISE_API_KEY": "Tkh2akMxbWdFczF1eDhrR2dobEE3b3d0dVB6R294S002WUlBOFBGNzNvOThRVzFUQ1F3SUpvUmF0Y2h6WERjMg==",
    "SHODAN_API_KEY": "NDgzaDFnRXRxWFJydDl0cWlYdVpBN0F6S21ybkl4SmlN",
    "GEMINI_API_KEY": "QVEuQWI4Uk42S1FOV250dkZ4ODRiMEY5azgyNDRCdjZheGFnMUJPanVaY0U5MEw3R2ZUTXc="
}


def get_secret(key_name: str, default: str = "") -> str:
    """
    Retrieves secret from environment or decodes fallback obfuscated string.
    Supports both raw strings and 'base64:...' prefixes in environment variables.
    """
    raw_val = os.getenv(key_name, "").strip()
    if raw_val:
        if raw_val.startswith("base64:"):
            try:
                return base64.b64decode(raw_val[7:]).decode("utf-8").strip()
            except Exception:
                return raw_val
        return raw_val

    # Fallback to encoded dictionary
    if key_name in _ENCODED_DEFAULTS:
        try:
            return base64.b64decode(_ENCODED_DEFAULTS[key_name]).decode("utf-8").strip()
        except Exception:
            return default
    return default
