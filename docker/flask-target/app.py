from flask import Flask, request
import requests as req

app = Flask(__name__)


@app.route("/")
def home():
    return "flask-target v1.0 running\n"


# VULN: SSRF - fetches arbitrary URLs supplied by user
@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return "provide ?url=<target>", 400
    try:
        r = req.get(url, timeout=5)
        return r.text
    except Exception as e:
        return str(e), 500


# VULN: reflects user input without sanitization (XSS demo)
@app.route("/echo")
def echo():
    msg = request.args.get("msg", "")
    return f"<html><body>{msg}</body></html>"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
