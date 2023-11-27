from flask import Flask, request, jsonify,send_file
from scipy.io import wavfile
import numpy as np
import matplotlib.pyplot as plt
import sounddevice as sd

from bson.binary import Binary
import random
import string
from Crypto.Cipher import AES
from Crypto.Cipher import _create_cipher
import Crypto.Util._raw_api
from Crypto.Hash import SHA512
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask_cors import CORS
import pymongo

from pymongo import DESCENDING
app = Flask(__name__)
CORS(app)

MONGODB_URI = "mongodb+srv://gowtham02:gowtham02@cluster0.u5laxtt.mongodb.net/?retryWrites=true&w=majority"
client = pymongo.MongoClient(MONGODB_URI)
db = client["secure_voice_transfer"]

def int_to_32bit_hex_string(num):
    hex_string = format(num, '032x')  # Convert to 32-character hexadecimal
    return hex_string

@app.route('/upload', methods=['POST'])
def upload():
   
    number = request.form.get('number')
    
   
    uploaded_file = request.files['file']
    contents = uploaded_file.read()
    print(contents)
    hasher = SHA512.new()
    hasher.update(contents)  # Use the original 'contents' variable before encryption
    original_hash = hasher.digest()
    shared_secret=int(number)
    hex_key = int_to_32bit_hex_string(shared_secret)
    aes_key = hex_key

    # Convert the derived AES key to a 32-character string representation
    
    AES_KEY=aes_key

    AES_IV = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(16))
    aes_keys_collection = db["aes_keys"]
    key_document = {
        "AES_KEY": AES_KEY,
        "AES_IV": AES_IV,
        "original_hash": Binary(original_hash)
    }

    aes_keys_collection.insert_one(key_document)

    encryptor = AES.new(AES_KEY.encode("utf-8"), AES.MODE_CFB, AES_IV.encode("utf-8"))
    encrypted_audio = encryptor.encrypt(contents)
    encrypted_audio_collection = db["encrypted_audio_data"]
    audio_document = {
    "encrypted_audio": Binary(encrypted_audio)
    }
    encrypted_audio_collection.insert_one(audio_document)

    return ''

@app.route('/download', methods=['POST'])
def download():
    aes_keys_collection = db["aes_keys"]
    audio_collection = db["encrypted_audio_data"]
    key_document = aes_keys_collection.find_one(sort=[("createdAt", DESCENDING)])

    number = request.json.get('number')

    shared_secret=int(number)
    hex_key = int_to_32bit_hex_string(shared_secret)
    aes_key = hex_key

    # Convert the derived AES key to a 32-character string representation
    
    AES_KEY1=aes_key
    AES_KEY=key_document["AES_KEY"]
    print(AES_KEY)
    print(AES_KEY1)
    AES_IV = key_document["AES_IV"]
    #retrieve Encrypted Audio Data from MongoDB
    audio_document = audio_collection.find_one()
    encrypted_audio = audio_document["encrypted_audio"]
    decryptor = AES.new(AES_KEY.encode("utf-8"), AES.MODE_CFB, AES_IV.encode("utf-8"))
    decrypted_audio = decryptor.decrypt(encrypted_audio)
    with open('decrypted_audio_file.wav', 'wb') as fd:
        fd.write(decrypted_audio)
    #verify integrity
    original_hash = key_document["original_hash"]
    hasher_decrypt = SHA512.new()
    hasher_decrypt.update(decrypted_audio)
    decrypted_hash = hasher_decrypt.digest()
    integrity_status=""
    if original_hash == decrypted_hash:
        integrity_status="Integrity verified: Audio file remains unchanged."
    else:
        integrity_status="Integrity compromised: Audio file has been tampered with."
        print(integrity_status)
    return send_file('decrypted_audio_file.wav', as_attachment=True)




if __name__ == '__main__':
    app.run(debug=True,port=5000)
