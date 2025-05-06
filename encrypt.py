from flask import Flask, render_template, request, send_file
from cryptography.fernet import Fernet
from io import BytesIO
import os

app = Flask(__name__)
key = Fernet.generate_key()
cipher = Fernet(key)

@app.route('/', methods=['GET', 'POST'])
def index():
    result_text = None
    download_file = None
    filename = None
    mode = None

    if request.method == 'POST':
        mode = request.form.get('mode')
        text = request.form.get('text')
        file = request.files.get('file')

        if text:
            if mode == 'encrypt':
                result_text = cipher.encrypt(text.encode()).decode()
            elif mode == 'decrypt':
                try:
                    result_text = cipher.decrypt(text.encode()).decode()
                except Exception:
                    result_text = "❌ Invalid decryption input or key"
        elif file:
            file_data = file.read()
            original_filename = file.filename

            if mode == 'encrypt':
                encrypted_data = cipher.encrypt(file_data)
                download_file = BytesIO(encrypted_data)
                filename = original_filename + '.enc'
            elif mode == 'decrypt':
                try:
                    decrypted_data = cipher.decrypt(file_data)
                    # Strip .enc and return original file
                    filename = original_filename.replace('.enc', '_decrypted')
                    download_file = BytesIO(decrypted_data)
                except Exception:
                    result_text = "❌ Failed to decrypt file. Possibly invalid key or corrupted data."

            if download_file:
                return send_file(download_file, as_attachment=True, download_name=filename)

    return render_template('index.html', result=result_text, mode=mode) 


 if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)



