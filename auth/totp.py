import pyotp
import qrcode
import io
import base64

def generate_totp_secret():
    return pyotp.random_base32()

def get_totp_uri(secret, username):
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="IDS Dashboard"
    )

def generate_qr_code(secret, username):
    uri = get_totp_uri(secret, username)
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{encoded}"

def verify_totp(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)
