from flask import Flask, render_template, request
import ipapi
from services.breach_service import check_email
from services.fingerprint_service import save_fingerprint, get_latest_fingerprint
from services.phishing_service import generate_phishing_example
from database import init_db
from services.recommendation_service import generate_recommendations
from services.profile_service import build_attacker_profile

init_db()

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/results")
def results():
    return render_template("results.html")


@app.route("/attacker")
def attacker():
    return render_template("attacker.html")


@app.route("/fingerprint")
def fingerprint():
    return render_template("fingerprint.html")


@app.route("/defence")
def defence():
    return render_template("defence.html")

# collect fingerprint data from browser
@app.route("/collect", methods=["POST"])
def collect():
    save_fingerprint(request.get_json())

    print("Received and saved fingerprint data to database:")
    return {"status": "received"} 


# given an email, check for breaches and return te data back
@app.route("/check", methods=["POST"])
def check():
    data = request.get_json()
    email = data.get("email")

    user_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    if user_ip:
        user_ip = user_ip.split(",")[0].strip()

    if user_ip in ("127.0.0.1", "::1"):
        user_ip = None

    geo_data = ipapi.location(ip=user_ip) if user_ip else None

    # xposed api crashes when there are no breaches and u try to get(), so need to wrap around try except
    breach_info = check_email(email)

    fingerprint = get_latest_fingerprint()

    profile = build_attacker_profile(breach_info, fingerprint, {"city": geo_data.get("city"), "region": geo_data.get("region")})

    phishing = generate_phishing_example(profile)

    recommendations = generate_recommendations(profile)
    
    combined = {
        "location" : {
            "city" : geo_data.get("city"),
            "region": geo_data.get("region"),
            "country": geo_data.get("country")
        },
        "device": {
            "browser": fingerprint.get("userAgent"),
            "platform": fingerprint.get("platform"),
            "screen": fingerprint.get("screenResolution"),
            "timezone": fingerprint.get("timezone")
        },
        "breach_info": breach_info,
        "phishing_example": phishing,
        "profile": profile,
        "recommendations": recommendations,
    }
    return combined

if __name__ == "__main__":
    app.run(debug=True)