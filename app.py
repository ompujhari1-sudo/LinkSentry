from flask import Flask, render_template, request, jsonify
from analyzer.scanner import scan_url

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please enter a URL"}), 400

    result = scan_url(url)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)