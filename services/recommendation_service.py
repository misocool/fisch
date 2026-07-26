def generate_recommendations(profile):
    recommendations = []
    exposed = profile["exposed_fields"]
    breaches = profile.get("top_breach", {})
    breach_count = profile["breach_count"]
    services = profile.get("services", [])

    # No breaches
    if breach_count == 0:
        recommendations.append({
            "level": "low",
            "type": "general",
            "title": "Continue monitoring exposure",
            "description": "No known breaches were detected for this email address. Continue monitoring your exposure regularly and practising good security habits."
        })
        return recommendations

    # Plaintext password exposure — most severe
    if profile.get("plaintext_breach"):
        pname = profile["plaintext_breach"]["name"]
        recommendations.append({
            "level": "high",
            "type": "issue",
            "title": f"Your password from {pname} was exposed in plaintext",
            "description": f"The {pname} breach exposed your password without any encryption, meaning your exact password is publicly known. If you use this password on any other service, those accounts are immediately at risk. Change this password everywhere it has been used and switch to a unique password for every account going forward."
        })

    elif "Passwords" in exposed:
        recommendations.append({
            "level": "high",
            "type": "issue",
            "title": "Exposed passwords detected across your breaches",
            "description": f"Password data was found in one or more of your {breach_count} breaches. Even hashed passwords can be cracked offline with modern tools. You should change passwords on all services associated with this email address, particularly if you reuse passwords across multiple accounts."
        })

    # Multiple breaches
    if breach_count >= 3:
        service_list = ", ".join(services[:3])
        recommendations.append({
            "level": "high",
            "type": "issue",
            "title": f"Your email appeared in {breach_count} separate breaches",
            "description": f"Appearing in {breach_count} breaches (including {service_list}) significantly increases your risk profile. Each breach adds another piece of information an attacker can use — combining data across breaches allows for highly personalised attacks even when individual exposures seem minor. Enable multi-factor authentication on all important accounts immediately."
        })

    elif breach_count > 0:
        recommendations.append({
            "level": "medium",
            "type": "issue",
            "title": "Enable multi-factor authentication",
            "description": "Your email has appeared in a known breach. Even if your password has been changed, enabling MFA ensures that a stolen password alone is not enough to access your accounts."
        })

    # Phone number exposure
    if "Phone numbers" in exposed:
        recommendations.append({
            "level": "medium",
            "type": "issue",
            "title": "Your phone number was exposed — watch for SMS phishing",
            "description": "Your phone number appeared in at least one breach. Attackers use exposed phone numbers to send convincing SMS phishing messagesthat impersonate banks, delivery services, or government agencies. Be skeptical of any unexpected text message asking you to click a link or provide information, even if it appears to know personal details about you."
        })

    # Date of birth exposure
    if "Dates of birth" in exposed:
        recommendations.append({
            "level": "medium",
            "type": "issue",
            "title": "Your date of birth was exposed — account recovery is at risk",
            "description": "Your date of birth was found in a breach. This information is commonly used as a verification factor for account recovery — meaning an attacker who knows your date of birth may be able to reset passwords or bypass identity checks on financial and government accounts. Review the security questions and recovery options on your most important accounts."
        })

    # Social media exposure
    if "Social media profiles" in exposed:
        recommendations.append({
            "level": "medium",
            "type": "issue",
            "title": "Social media profile data was exposed",
            "description": "Social media profile information was found in at least one breach. This gives attackers insight into the platforms you use, making impersonation attempts more convincing. Be cautious of unexpected friend requests, direct messages, or notifications from familiar looking accounts."
        })

    # Geographic location exposure
    if "Geographic locations" in exposed:
        recommendations.append({
            "level": "low",
            "type": "issue",
            "title": "Your location data was exposed",
            "description": "Geographic location information appeared in at least one breach. While location data alone is relatively low risk, combined with other exposed information it can be used to make phishing attempts appear more legitimate by referencing your approximate area."
        })

    return recommendations