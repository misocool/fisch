from dataclasses import asdict

from xposedornot import XposedOrNot

xon = XposedOrNot()

# simplify analystics given from xposedornot
def simplify_breach_data(raw_data):
    metrics = raw_data.get("metrics", {})
    risk_list = metrics.get("risk", [])
    risk_info = risk_list[0] if risk_list else {}

    breaches = raw_data.get("breaches_details", [])
    simplified_breaches = []
    for b in breaches:
        simplified_breaches.append({
            "name": b.get("breach"),
            "year": b.get("xposed_date"),
            "exposed": b.get("xposed_data", "").split(";"),
            "password_risk": b.get("password_risk")
        })

    return {
        "risk_score": risk_info.get("risk_score"),
        "risk_label": risk_info.get("risk_label"),
        "breach_count": raw_data.get("breaches_count", 0),
        "breaches": simplified_breaches
    }

def check_email(email):
    try:
        result = xon.breach_analytics(email)
        raw_data = asdict(result)
        return simplify_breach_data(raw_data)
    except AttributeError:
        print(f"No breaches found for {email}, or library error handling empty result")
        return {
            "risk_score": 0,
            "risk_label": "None found",
            "breach_count": 0,
            "breaches": []
        }
    