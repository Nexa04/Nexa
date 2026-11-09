
import re

# -------------------------
# Nexa Threat Detector
# -------------------------

def analyze_message(message_text: str):
    """
    Rule-based message analysis.
    Returns threat_type, risk_level, and confidence.
    """

    text = message_text.lower().strip()
    text = re.sub(r"\s+", " ", text)

    # -------------------------
    # Blackmail Detection
    # -------------------------
    blackmail_patterns = [
        r"\bpay me\b",
        r"\bsend (?:me )?money\b",
        r"\bgive me money\b",
        r"\bi will expose you\b",
        r"\bi(?:'|’)ll expose you\b",
        r"\bi will post your photos\b",
        r"\bi will share your photos\b",
        r"\bsend me money or\b",
        r"\bif you don.t pay\b",
        r"\bpay me or i will\b",
        r"\botherwise i will expose\b",
        r"\bi will leak your photos\b",
        r"\bi will leak your pictures\b",
    ]

    # -------------------------
    # Threat Detection
    # -------------------------
    threat_patterns = [
        r"\bi will hurt you\b",
        r"\bi(?:'|’)ll hurt you\b",
        r"\bi am going to hurt you\b",
        r"\bi'm going to hurt you\b",
        r"\bi will kill you\b",
        r"\bi(?:'|’)ll kill you\b",
        r"\bi am going to kill you\b",
        r"\bi'm going to kill you\b",
        r"\bi will beat you\b",
        r"\bi will attack you\b",
        r"\byou will regret this\b",
        r"\bi know where you live\b",
        r"\bi will find you\b",
        r"\bi will make you pay\b",
    ]

    # -------------------------
    # Grooming Detection
    # -------------------------
    grooming_patterns = [
        r"\bkeep this secret\b",
        r"\bdon.t tell your parents\b",
        r"\bdon.t tell anyone\b",
        r"\bsend me a private photo\b",
        r"\bsend me a picture of yourself\b",
        r"\bmeet me alone\b",
        r"\byou are mature for your age\b",
        r"\bthis is our little secret\b",
        r"\bdon.t tell your mom\b",
        r"\bdon.t tell your dad\b",
    ]

    # -------------------------
    # Harassment Detection
    # -------------------------
    harassment_patterns = [
        r"\bidiot\b",
        r"\bstupid\b",
        r"\bloser\b",
        r"\bshut up\b",
        r"\byou are ugly\b",
        r"\byou are worthless\b",
        r"\byou are pathetic\b",
        r"\bnobody likes you\b",
    ]

    # -------------------------
    # Match Patterns
    # -------------------------
    def matches(patterns):
        return any(re.search(pattern, text) for pattern in patterns)

    # Check blackmail first
    if matches(blackmail_patterns):
        return {
            "threat_type": "blackmail",
            "risk_level": "high_risk",
            "confidence": 95.0
        }

    # Check threats
    if matches(threat_patterns):
        return {
            "threat_type": "threat",
            "risk_level": "high_risk",
            "confidence": 95.0
        }

    # Check grooming
    if matches(grooming_patterns):
        return {
            "threat_type": "grooming",
            "risk_level": "high_risk",
            "confidence": 90.0
        }

    # Check harassment
    if matches(harassment_patterns):
        return {
            "threat_type": "harassment",
            "risk_level": "suspicious",
            "confidence": 85.0
        }

    # No pattern matched
    return {
        "threat_type": "safe",
        "risk_level": "safe",
        "confidence": 100.0
    }
