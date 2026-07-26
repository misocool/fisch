
# give breaches a sccore (higher = more risk)
def score_breach(breach):
    score = 0

    # Recency: newer breaches score higher
    try:
        year = int(breach.get("year", 0))
        score += max(0, year - 2015)  # more recent = more points
    except (ValueError, TypeError):
        pass

    # Data richness: more exposed fields = more useful
    exposed = breach.get("exposed", [])
    score += len(exposed)

    # High-value fields worth extra weight
    high_value_fields = ["Phone numbers", "Passwords", "Dates of birth", "Geographic locations"]
    for field in high_value_fields:
        if field in exposed:
            score += 3

    # Password risk: plaintext/easy-to-crack is more at risk
    risk = breach.get("password_risk", "")
    if risk == "plaintext":
        score += 5
    elif risk == "easytocrack":
        score += 3

    return score


def generate_phishing_example(profile):
    breaches = profile.get("services", [])
    
    if not breaches or not profile.get("top_breach"):
        return {
            "pretext": "generic",
            "subject": "Account Security Notice",
            "sender": "Security Team (no-reply@account-security.com)",
            "example": "We noticed unusual activity on your account. Please verify your identity.",
            "techniques": ["Generic urgency"],
            "information_used": ["Email address only"],
            "note": "No breach data found — minimal personalisation possible."
        }

    top = profile["top_breach"]
    breach_name = top["name"]
    sender_domain = breach_name.lower().replace(" ", "")
    city = profile["location"].get("city") if profile["location"] else "your area"

    # Infer device string from fingerprint platform
    platform = profile.get("device", {}).get("platform", "")
    if "Mac" in platform:
        device_str = "a macOS device"
    elif "Win" in platform:
        device_str = "a Windows device"
    elif "iPhone" in platform or "iPad" in platform:
        device_str = "an iOS device"
    elif "Android" in platform:
        device_str = "an Android device"
    else:
        device_str = None

    # --- Paragraph 1: Opening ---
    paragraph_1 = f"We are reaching out regarding your {breach_name} account."

    # --- Paragraph 2: Location + device ---
    if city and city != "your area" and device_str:
        paragraph_2 = (
            f"Our systems detected access from {city} on {device_str} "
            f"that did not match your previous activity."
        )
    elif city and city != "your area":
        paragraph_2 = (
            f"Our systems detected access from {city} "
            f"that did not match your previous activity."
        )
    elif device_str:
        paragraph_2 = (
            f"Our systems detected access from {device_str} "
            f"that did not match your previous activity."
        )
    else:
        paragraph_2 = (
            "Our systems detected unusual access that did not match your previous activity."
        )

    # --- Paragraph 3: Exposure details (grouped into one flowing paragraph) ---
    exposure_sentences = []

    if profile["plaintext_breach"]:
        pname = profile["plaintext_breach"]["name"]
        if pname == breach_name:
            exposure_sentences.append(
                f"Our records indicate your {breach_name} password was exposed in plaintext — "
                f"if you reuse this password elsewhere, those accounts may also be at risk."
            )
        else:
            exposure_sentences.append(
                "Password data associated with your account was exposed and may be in circulation."
            )
    elif profile["has_passwords"]:
        exposure_sentences.append(
            "Password data associated with your account was exposed and may be in circulation."
        )

    if profile["has_dob"]:
        exposure_sentences.append(
            "Personal identifiers including date of birth were also exposed, "
            "which may be used to bypass account recovery questions."
        )

    if profile["has_phone"]:
        exposure_sentences.append(
            "As your phone number was included in the exposed data, "
            "you may also receive SMS-based follow-up attempts."
        )

    paragraph_3 = " ".join(exposure_sentences) if exposure_sentences else ""

    # --- Paragraph 4: Call to action ---
    paragraph_4 = (
        "Please verify your account details immediately to prevent further exposure"
    )

    # Join non-empty paragraphs
    paragraphs = [p for p in [paragraph_1, paragraph_2, paragraph_3, paragraph_4] if p]
    example_text = "\n\n".join(paragraphs)

    # --- Pretext selection ---
    if profile["has_passwords"] and profile["plaintext_breach"]:
        pretext_type = "credential_alert"
        subject = f"Urgent: Your {breach_name} credentials may be compromised"
        sender = f"{breach_name} Security (security@{sender_domain}-alerts.com)"
    elif profile["has_social"]:
        pretext_type = "social_notification"
        subject = f"New activity detected on your {breach_name} profile"
        sender = f"{breach_name} Notifications (notify@{sender_domain}.com)"
    elif profile["has_dob"] or profile["has_location"]:
        pretext_type = "data_broker_scam"
        subject = "Your personal information was found online"
        sender = "Privacy Protection Service (privacy@data-protect-alert.com)"
    elif profile["has_phone"]:
        pretext_type = "billing_alert"
        subject = f"Action required on your {breach_name} account"
        sender = f"{breach_name} Support (support@{sender_domain}.com)"
    else:
        pretext_type = "generic_security"
        subject = f"{breach_name} Security Notice"
        sender = f"{breach_name} Security (security@{sender_domain}.com)"

    # --- Dynamic information_used ---
    information_used = [f"{breach_name} breach ({top['year']})"]
    if city and city != "your area":
        information_used.append(f"Location: {city}")
    if device_str:
        information_used.append(f"Device type: {device_str}")
    if profile["has_passwords"]:
        information_used.append("Exposed password data")
    if profile["has_phone"]:
        information_used.append("Exposed phone number")
    if profile["has_dob"]:
        information_used.append("Exposed date of birth")
    if profile["breach_count"] > 1:
        information_used.append(f"{profile['breach_count']} total breaches")

    return {
        "pretext": pretext_type,
        "subject": subject,
        "sender": sender,
        "example": example_text,
        "techniques": ["Authority impersonation", "Urgency", "Fear of account compromise"],
        "information_used": information_used,
        "note": f"Selected '{pretext_type}' — '{breach_name}' scored highest. "
                f"Email assembled from {len(exposure_sentences) + 3} conditional blocks."
    }