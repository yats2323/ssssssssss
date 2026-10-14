"""FRAMECUT revoked-list server for Render.

Serves the signed revoked_list.txt that the app downloads, and accepts new lists from
the license generator. A list is only stored if its RSA signature verifies against your
public key, so a wrong or tampered upload can never lock all customers out.

Environment variables:
  ADMIN_TOKEN   secret the generator sends when uploading (Render can generate it)
  LIC_PUB_XML   the public key, exactly the $script:LicPubXml value from the app
  DATA_DIR      folder that survives restarts (the Render disk mount, e.g. /var/data)
"""
import base64
import hmac
import os
import re
import xml.etree.ElementTree as ET

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import Flask, Response, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024  # lists are tiny; refuse anything big

DATA_DIR = os.environ.get("DATA_DIR", "./data")
LIST_PATH = os.path.join(DATA_DIR, "revoked_list.txt")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
ID_RE = re.compile(r"^[0-9a-f]{64}$")


def _b64(s):
    return base64.b64decode(s)


def _b64url(s):
    s = s.replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _public_key():
    root = ET.fromstring(os.environ["LIC_PUB_XML"])
    n = int.from_bytes(_b64(root.findtext("Modulus")), "big")
    e = int.from_bytes(_b64(root.findtext("Exponent")), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


def verify_list(text):
    """Same rules as the app: FCR1 header, SIG line, signature over the ids joined by \\n."""
    lines = [ln.strip() for ln in text.replace("\r", "").split("\n") if ln.strip()]
    if len(lines) < 2 or lines[0] != "FCR1":
        return "list must start with FCR1"
    sig_line = next((ln for ln in lines if ln.startswith("SIG ")), None)
    if not sig_line:
        return "list has no SIG line"
    ids = [ln for ln in lines if ID_RE.match(ln)]
    try:
        _public_key().verify(
            _b64url(sig_line[4:]),
            "\n".join(ids).encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return "signature does not match your public key"
    except Exception as ex:  # bad base64, missing LIC_PUB_XML, ...
        return "could not verify: %s" % ex
    return None


def _plain(body, status=200):
    r = Response(body, status=status, mimetype="text/plain")
    r.headers["Cache-Control"] = "no-store"
    return r


@app.get("/healthz")
def healthz():
    return _plain("ok")


@app.get("/revoked_list.txt")
def get_list():
    try:
        with open(LIST_PATH, "r", encoding="utf-8") as f:
            return _plain(f.read())
    except FileNotFoundError:
        return _plain("no list uploaded yet", 503)


@app.route("/admin/revoked_list", methods=["PUT", "POST"])
def put_list():
    auth = request.headers.get("Authorization", "")
    expected = "Bearer " + ADMIN_TOKEN
    if not ADMIN_TOKEN or not hmac.compare_digest(auth.encode(), expected.encode()):
        return _plain("unauthorized", 401)
    text = request.get_data(as_text=True)
    problem = verify_list(text)
    if problem:
        return _plain("rejected: " + problem, 400)
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = LIST_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text.replace("\r\n", "\n"))
    os.replace(tmp, LIST_PATH)  # atomic: readers never see a half-written list
    return _plain("stored")
