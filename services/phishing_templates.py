def credential_theft_template(profile):

    service = (
        profile["services"][0]
        if profile["services"]
        else "online service"
    )

    city = (
        profile["location"].get("city")
        if profile["location"]
        else "your area"
    )


    return {

        "scenario": "Credential theft simulation",


        "techniques": [
            "Authority impersonation",
            "Urgency",
            "Fear of account compromise"
        ],


        "information_used": [
            "Previous breach exposure",
            "Known service usage",
            "Approximate location"
        ],


        "sender":
            f"{service} Security Team",


        "subject":
            "Unusual account activity detected",


        "example":
            f"""
Hello,

This is a cybersecurity awareness simulation.

An attacker who knew that your {service} account
information appeared in a previous breach could
attempt to impersonate the service and create
a fake security warning.

The attacker may reference details such as your
location ({city}) to make the message appear
more convincing.

[Simulation only]
""",


        "explanation":
            "This attack relies on stolen credentials and trust in a familiar service."

    }




def sms_phishing_template(profile):

    city = (
        profile["location"].get("city")
        if profile["location"]
        else "your area"
    )


    return {

        "scenario": "SMS phishing simulation",


        "techniques": [
            "Personalisation",
            "Urgency",
            "Trust exploitation"
        ],


        "information_used": [
            "Exposed phone number",
            "Location information"
        ],


        "sender":
            "Account Support Team",


        "subject":
            "Important account notification",


        "example":
            f"""
Hello,

This cybersecurity simulation demonstrates how
attackers may use an exposed phone number to
send personalised messages.

A message may reference details such as your
region ({city}) to appear more legitimate.

The goal is to create urgency and encourage
the victim to respond without verifying the sender.

[Simulation only]
""",


        "explanation":
            "Phone numbers exposed in breaches can be used for targeted scam attempts."

    }




def identity_impersonation_template(profile):

    return {

        "scenario": "Identity impersonation simulation",


        "techniques": [
            "Social engineering",
            "Trust building",
            "Information matching"
        ],


        "information_used": [
            "Personal identifiers",
            "Public information"
        ],


        "sender":
            "Verification Service",


        "subject":
            "Identity verification request",


        "example":
            """
Hello,

This cybersecurity simulation demonstrates how
attackers may combine publicly available personal
information to appear trustworthy.

Information such as names, dates of birth,
or other identifiers can help create convincing
social engineering attempts.

[Simulation only]
""",


        "explanation":
            "Personal information can increase credibility during impersonation attempts."

    }




def generic_security_template(profile):

    return {

        "scenario": "Generic phishing simulation",


        "techniques": [
            "Authority impersonation",
            "Urgency"
        ],


        "information_used": [
            "Email address exposure"
        ],


        "sender":
            "Security Notification Team",


        "subject":
            "Security notification",


        "example":
            """
Hello,

This cybersecurity simulation demonstrates a
generic phishing attempt.

Without additional exposed information, attackers
have fewer opportunities to personalise their
messages.

[Simulation only]
""",


        "explanation":
            "Attackers typically rely on personal information to increase credibility."

    }