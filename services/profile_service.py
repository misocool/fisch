from services.phishing_service import score_breach

def build_attacker_profile(breach_info, device, location):
    exposed = set()

    for breach in breach_info["breaches"]:
        exposed.update(breach["exposed"])

    profile =  {
        "services": [ b["name"] for b in breach_info["breaches"] ],
        "breach_count": breach_info["breach_count"],
        "risk_score": breach_info["risk_score"],
        "device": device,
        "location": location,
        "exposed_fields": list(exposed)
    }

    profile["inferences"] = infer_information(profile)

    breaches = breach_info.get("breaches", [])

    if breaches:
        scored = [(score_breach(b), b) for b in breaches]
        scored.sort(key=lambda x: x[0], reverse=True)
        profile["top_breach"] = scored[0][1]
        profile["most_recent_breach"] = max(
            breaches, key=lambda b: int(b.get("year", 0))
        )
    else:
        profile["top_breach"] = None
        profile["most_recent_breach"] = None

    # Boolean convenience flags for the email generator
    profile["has_passwords"] = "Passwords" in exposed
    profile["has_phone"] = "Phone numbers" in exposed
    profile["has_dob"] = "Dates of birth" in exposed
    profile["has_location"] = "Geographic locations" in exposed
    profile["has_social"] = "Social media profiles" in exposed
    profile["plaintext_breach"] = next(
        (b for b in breaches if b.get("password_risk") == "plaintext"), None
    )

    # Timezone-based region inference
    timezone = device.get("timezone", "")
    if "Australia" in timezone:
        profile["region_inference"] = "Australia"
    elif "America" in timezone:
        profile["region_inference"] = "North America"
    elif "Europe" in timezone:
        profile["region_inference"] = "Europe"
    elif "Asia" in timezone:
        profile["region_inference"] = "Asia"
    else:
        profile["region_inference"] = None

    return profile

def infer_information(profile):
    inferred = []

    # empty string if returned nothing
    platform = profile["device"].get("platform", "")
    browser = profile["device"].get("userAgent", "")

    combined = browser + " " + platform

    # Operating system
    if "Android" in combined:
        inferred.append("Victim likely uses Android")

    elif "iPhone" in combined:
        inferred.append("Victim likely uses iOS")

    elif "Macintosh" in combined:
        inferred.append("Victim likely uses macOS")

    elif "Windows" in combined:
        inferred.append("Victim likely uses Windows")


    # Browser
    if "Chrome" in browser:
        inferred.append("Victim likely uses Google Chrome")

    elif "Firefox" in browser:
        inferred.append("Victim likely uses Firefox")

    elif "Safari" in browser:
        inferred.append("Victim likely uses Safari")

    return inferred



