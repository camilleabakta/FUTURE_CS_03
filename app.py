import os
from flask import Flask, request, render_template, send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# GÉNÉRATION DE LA CLÉ
KEY = b'Sixteen byte key' # La clé doit faire 16, 24 ou 32 octets

def encrypt_file(file_path):
    # On lit le fichier original
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Création du vecteur d'initialisation (IV) et chiffrement
    cipher = AES.new(KEY, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    
    # On sauvegarde : IV + Contenu Chiffré
    with open(file_path + ".enc", 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphertext)
    
    # On supprime le fichier original non chiffré par sécurité
    os.remove(file_path)

def decrypt_file(enc_file_path):
    with open(enc_file_path, 'rb') as f:
        iv = f.read(16) # Les 16 premiers octets sont l'IV
        ciphertext = f.read()
    
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    original_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    return original_data

@app.route('/')
def index():
    # Liste les fichiers chiffrés dans le dossier
    files = [f for f in os.listdir(UPLOAD_FOLDER) if f.endswith('.enc')]
    return render_template('index.html', files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'Aucun fichier', 400
    file = request.files['file']
    if file.filename == '':
        return 'Aucun fichier sélectionné', 400
    
    # Sauvegarde temporaire
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)
    
    # Chiffrement
    encrypt_file(file_path)
    
    return 'Fichier téléchargé et chiffré avec succès ! <a href="/">Retour</a>'

@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    
    try:
        decrypted_data = decrypt_file(file_path)
        
        # On renvoie le fichier déchiffré à la volée (sans le stocker sur le disque)
        # On retire l'extension .enc pour le nom de téléchargement
        original_name = filename.replace('.enc', '')
        
        from io import BytesIO
        return send_file(
            BytesIO(decrypted_data),
            as_attachment=True,
            download_name=original_name
        )
    except Exception as e:
        return f"Erreur de déchiffrement : {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)