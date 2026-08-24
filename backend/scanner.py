import requests
import time
import socket
import whois
import ssl
from urllib.parse import urlparse


def scan_website(url):

    result = {}

    url = url.strip().replace(" ", "")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result["url"] = url

    # ---------------- RESPONSE ----------------

    try:

        start = time.perf_counter()

        response = requests.get(
            url,
            timeout=10,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        end = time.perf_counter()

        response_time = round(end - start, 3)

        result["reachable"] = True
        result["status_code"] = response.status_code
        result["response_time"] = response_time

    except Exception as e:

        return {
            "reachable": False,
            "error": str(e)
        }

    # ---------------- HTTPS ----------------

    result["https"] = response.url.startswith("https://")

    # ---------------- DOMAIN ----------------

    domain = urlparse(response.url).netloc

    result["domain"] = domain

    # ---------------- DNS ----------------

    try:

        ip = socket.gethostbyname(domain)

        result["ip_address"] = ip

    except Exception:

        result["ip_address"] = "Unable to Resolve"

    # ---------------- SERVER ----------------

    server = response.headers.get("Server")

    if server:
        result["server"] = server
    else:
        result["server"] = "Hidden"

    # ---------------- SECURITY HEADERS ----------------

    headers_to_check = [

        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permission-Policy"

    ]

    found_headers = []
    missing_headers = []
    score = 0

    for header in headers_to_check:

        if header in response.headers:

            found_headers.append(header)

            score += 1

        else:

            missing_headers.append(header)

    result["security_score"] = score
    result["headers_found"] = found_headers
    result["headers_missing"] = missing_headers

    # ---------------- ROBOTS ----------------

    try:

        robots_url = url.rstrip("/") + "/robots.txt"

        res = requests.get(
            robots_url,
            timeout=5,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        if res.status_code == 200:

            result["robots"] = True
            result["robots_url"] = robots_url

        else:

            result["robots"] = False
            result["robots_url"] = ""

    except Exception:

        result["robots"] = False
        result["robots_url"] = ""

    # ---------------- SITEMAP ----------------

    try:

        sitemap_url = url.rstrip("/") + "/sitemap.xml"

        res = requests.get(
            sitemap_url,
            timeout=5,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        if res.status_code == 200:

            result["sitemap"] = True
            result["sitemap_url"] = sitemap_url

        else:

            result["sitemap"] = False
            result["sitemap_url"] = ""

    except Exception:

        result["sitemap"] = False
        result["sitemap_url"] = ""

    # ---------------- REDIRECT CHECK ----------------

    try:

        res = requests.get(
            url,
            allow_redirects=True,
            timeout=10,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        redirects = []

        if len(res.history):

            for redirect in res.history:

                redirects.append({
                    "status_code": redirect.status_code,
                    "url": redirect.url
                })

        result["redirects"] = redirects

    except Exception:

        result["redirects"] = []

    # ---------------- WHOIS ----------------

    try:

        info = whois.whois(domain)

        creation = info.get("creation_date")
        expiry = info.get("expiration_date")

        if isinstance(creation, list):
            creation = creation[0]

        if isinstance(expiry, list):
            expiry = expiry[0]

        result["whois"] = {
            "registrar": info.get("registrar"),
            "creation_date": str(creation),
            "expiration_date": str(expiry)
        }

    except Exception:

        result["whois"] = {
            "registrar": "Not Available",
            "creation_date": "Not Available",
            "expiration_date": "Not Available"
        }

    # ---------------- COOKIES ----------------

    cookie_list = []

    try:

        for cookie in response.cookies:

            rest = getattr(cookie, "_rest", {})

            cookie_list.append({

                "name": cookie.name,

                "secure": cookie.secure,

                "httponly": "HttpOnly" in rest

            })

    except Exception:

        pass

    result["cookies"] = cookie_list

    # ---------------- SSL CERTIFICATE ----------------

    ssl_info = {}

    try:

        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:

            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                cert = ssock.getpeercert()

                if cert:

                    issuer = []

                    for item in cert.get("issuer", []):

                        issuer.append(item)

                    ssl_info = {

                        "available": True,

                        "issuer": issuer,

                        "expiry": cert.get("notAfter")

                    }

                else:

                    ssl_info = {

                        "available": False

                    }

    except Exception:

        ssl_info = {

            "available": False

        }

    result["ssl"] = ssl_info

    # ---------------- FINAL RESULT ----------------

    return result