def generate_recommendations(profile):

    recommendations = []

    exposed = profile["exposed_fields"]


    # No breaches
    if profile["breach_count"] == 0:

        recommendations.append({

            "level": "low",

            "type": "general",

            "title": "Continue monitoring exposure",

            "description":
            "No known breaches were detected. Continue monitoring your exposure and practising good security habits."

        })

        return recommendations



    if "Passwords" in exposed:

        recommendations.append({

            "level": "high",

            "type": "issue",

            "title": "Change exposed passwords",

            "description":
            "Password information appeared in a breach. Change affected passwords and avoid reuse."

        })



    if "Phone numbers" in exposed:

        recommendations.append({

            "level": "medium",

            "type": "issue",

            "title": "Watch for SMS phishing",

            "description":
            "Your phone number was exposed and may be used for targeted scams."

        })



    if "Dates of Birth" in exposed:

        recommendations.append({

            "level": "medium",

            "type": "issue",

            "title": "Protect identity information",

            "description":
            "Birth dates can be used in identity verification attacks."

        })



    if profile["breach_count"] >= 3:

        recommendations.append({

            "level": "high",

            "type": "issue",

            "title": "Enable MFA",

            "description":
            "Multiple breaches increase the risk of account compromise."

        })


    return recommendations