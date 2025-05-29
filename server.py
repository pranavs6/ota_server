from flask import Flask, request, abort, jsonify, Response
import os
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

FIRMWARE_DIR = os.path.join(os.path.dirname(__file__), 'firmware')

PASS1 = "ireallyneedtheupdate"            
KEY_ONE_STRING = "itisactuallymemakingtherequest"  
NONCE = "121231231"
URL2 = "https://dawg.com/file_link"

@app.route('/firmware/<version>', methods=['GET'])
def firmware_endpoint(version):
    """
    Instead of streaming the raw .bin, read it into memory,
    Base64-encode it, and return a text/plain response containing
    the Base64 payload.
    """
    filename = f"{version}.bin"
    filepath = os.path.join(FIRMWARE_DIR, filename)
    if not os.path.isfile(filepath):
        abort(404, description="Firmware version not found")

    # read & base64-encode
    with open(filepath, 'rb') as f:
        data = f.read()
    b64 = base64.b64encode(data).decode('ascii')

    # stream back as plain text
    return Response(b64, mimetype='text/plain')

def decrypt_auth_pass(b64_cipher: str, passphrase: str) -> str:
    data = base64.b64decode(b64_cipher)
    key = hashlib.sha256(passphrase.encode()).digest()
    nonce = data[:12]
    ct_and_tag = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct_and_tag, None).decode('utf-8')

@app.route('/ota_req', methods=['POST'])
def submit():
    # 1) grab encrypted pass + requested version
    enc = request.form.get('auth_pass')
    version = request.form.get('version')
    if not enc or not version:
        abort(400, description="Missing auth_pass or version")

    # 2) decrypt just the plaintext
    try:
        decrypted = decrypt_auth_pass(enc, KEY_ONE_STRING)
    except Exception:
        abort(400, description="Decryption failed")

    # 3) verify
    if decrypted != PASS1:
        abort(401, description="Unauthorized")

    # 4) return your static NONCE and URL2
    return jsonify({
        "Nonce": NONCE,
        "url": URL2
    }), 200


if __name__ == '__main__':
    # Run on all interfaces, port 8000
    app.run(host='localhost', port=8000)

