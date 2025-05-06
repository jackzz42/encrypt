from flask import Flask, request, render_template, send_file
import base64
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256
from werkzeug.utils import secure_filename
from io import BytesIO

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ========= Custom Mapping (non-overlapping and safe) =========
custom_map = {
    'A': '[c1]', 'B': '[B2]', 'C': '[C3]', 'D': '[D4]', 'E': '[E5]',
    'F': '[F6]', 'G': '[G7]', 'H': '[H8]', 'I': '[I9]', 'J': '[J0]',
    'K': '[i1]', 'L': '[L2]', 'M': '[d3]', 'N': '[g4]', 'O': '[O5]',
    'P': '[P6]', 'Q': '[Q7]', 'R': '[R8]', 'S': '[S9]', 'T': '[T0]',
    'U': '[U1]', 'V': '[V2]', 'W': '[W3]', 'X': '[X4]', 'Y': '[55]',
    'Z': '[s]', 'a': '[a1]', 'b': '[x2]', 'c': '[c3]', 'd': '[d4]',
    'e': '[e5]', 'f': '[f6]', 'g': '[g7]', 'h': '[h8]', 'i': '[i9]',
    'j': '[j0]', 'k': '[k1]', 'l': '[l2]', 'm': '[m3]', 'n': '[n4]',
    'o': '[o5]', 'p': '[p6]', 'q': '[q7]', 'r': '[r8]', 's': '[b9]',
    't': '[t0]', 'u': '[u1]', 'v': '[v2]', 'w': '[w3]', 'x': '[x4]',
    'y': '[y5]', 'z': '[z6]', ' ': '[ssvp]'
}

reverse_custom_map = {v: k for k, v in custom_map.items()}

# ========= Padding Utilities =========
def pad(data):
    length = 16 - (len(data) % 16)
    return data + bytes([length]) * length

def unpad(data):
    return data[:-data[-1]]

# ========= Custom Encryption Layer =========
def custom_encrypt(data):
    text = data.decode(errors='ignore')
    result = ''.join(custom_map.get(c, c) for c in text)
    return result.encode()

def custom_decrypt(data):
    text = data.decode(errors='ignore')
    for token, char in reverse_custom_map.items():
        text = text.replace(token, char)
    return text.encode()

# ========= AES Layer =========
def aes_encrypt(data, password):
    key = sha256(password.encode()).digest()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data))
    return base64.b64encode(iv + encrypted)

def aes_decrypt(data, password):
    try:
        key = sha256(password.encode()).digest()
        raw = base64.b64decode(data)
        iv = raw[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(raw[16:]))
        return decrypted
    except Exception as e:
        raise ValueError("Decryption failed. Ensure the password is correct and the data is valid.") from e

# ========= Routes =========
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    text = request.form['text']
    password = request.form['password']
    if not text or not password:
        return "Text and password are required!", 400
    custom = custom_encrypt(text.encode())
    encrypted = aes_encrypt(custom, password)
    return render_template('index.html', result=encrypted.decode(), copied=True)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_text = request.form['encrypted_text']
    password = request.form['password']
    if not encrypted_text or not password:
        return "Encrypted text and password are required!", 400
    try:
        decrypted = aes_decrypt(encrypted_text.encode(), password)
        plain = custom_decrypt(decrypted)
        return render_template('index.html', result=plain.decode(), copied=False)
    except Exception as e:
        return render_template('index.html', result=f"Decryption failed: {e}", copied=False)

@app.route('/encrypt_file', methods=['POST'])
def encrypt_file():
    file = request.files.get('file')
    password = request.form.get('password')
    if not file or not password:
        return "File and password are required!", 400
    filename = secure_filename(file.filename)
    file_data = file.read()
    custom = custom_encrypt(file_data)
    encrypted = aes_encrypt(custom, password)
    encrypted_filename = filename + '.enc'
    return send_file(BytesIO(encrypted), as_attachment=True, download_name=encrypted_filename)

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    file = request.files.get('file')
    password = request.form.get('password')
    if not file or not password:
        return "File and password are required!", 400
    filename = secure_filename(file.filename)
    file_data = file.read()
    try:
        decrypted = aes_decrypt(file_data, password)
        plain = custom_decrypt(decrypted)
        if filename.endswith('.enc'):
            original_filename = filename[:-4]
        else:
            original_filename = 'decrypted_' + filename
        return send_file(BytesIO(plain), as_attachment=True, download_name=original_filename)
    except Exception as e:
        return f"Decryption failed: {e}", 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)



