
from flask import Flask, render_template, request, jsonify
from analyzer.scanner import scan_url

app = Flask(__name__)

# Limit incoming request payload
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


# Security headers
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    return response


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    if not request.is_json:
        return jsonify({
            "error": "Content-Type must be application/json"
        }), 415

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Invalid JSON request"
        }), 400

    url = data.get("url")

    if not isinstance(url, str):
        return jsonify({
            "error": "URL must be a string"
        }), 400

    url = url.strip()

    if not url:
        return jsonify({
            "error": "Please enter a URL"
        }), 400

    if len(url) > 4096:
        return jsonify({
            "error": "URL exceeds the supported length"
        }), 400

    result = scan_url(url)
    return jsonify(result)


@app.errorhandler(413)
def request_too_large(error):
    return jsonify({
        "error": "Request payload is too large"
    }), 413


if __name__ == "__main__":
    app.run(debug=False)
