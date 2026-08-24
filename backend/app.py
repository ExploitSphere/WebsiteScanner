from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse

from scanner import scan_website
from port_scanner import scan_ports

app = Flask(__name__)
CORS(app)


@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json() or {}

    url = data.get("url", "").strip().replace(" ", "")

    if not url:
        return jsonify({
            "success": False,
            "message": "Please enter a website URL."
        })

    # Automatically add https:// if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        # Website Scan
        website_result = scan_website(url)

        # Extract domain for Port Scan
        domain = urlparse(url).hostname

        # Remove www. if present
        if domain and domain.startswith("www."):
            domain = domain[4:]

        # Network Port Scan
        port_result = scan_ports(domain)

        return jsonify({

            "success": True,

            "website": website_result,

            "ports": port_result

        })

    except Exception as e:

        return jsonify({

            "success": False,

            "message": str(e)

        })


if __name__ == "__main__":
    app.run(debug=True)