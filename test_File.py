import json
from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from base64 import b64decode
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from random import random
import pickle


def grab_rsa_key():
    rsa_key_file = open('project2/public.pem', 'r')
    #rsa_public_key= RSA.import_key(rsa_key_file.read())
    lines = rsa_key_file.readlines()[1:-1]
    rsa_key=""
    for x in lines:
        rsa_key=rsa_key+x
    rsa_key_bytes=bytes(rsa_key, 'utf-8')
    return rsa_key_bytes

def make_aes_key():
    aes_key=get_random_bytes(16)
    return aes_key


def make_session_key():
    session_key=get_random_bytes(16)
    return session_key

def encrypt_with_aes(aes_key,thing_to_encrypt):
    print(thing_to_encrypt)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = aes_cipher.encrypt(pad(thing_to_encrypt, AES.block_size))
    iv = b64encode(aes_cipher.iv).decode('utf-8')
    ciphertext = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv': iv, 'ciphertext': ciphertext})
    return result

def decrypt_with_aes(AES_key,encrypted_message):
    b64 = json.loads(encrypted_message)
    iv = b64decode(b64['iv'])
    ciphertext=b64decode(b64['ciphertext'])
    cipher=AES.new(AES_key,AES.MODE_CBC,iv)
    plaintext=unpad(cipher.decrypt(ciphertext),16)
    print(plaintext)

def make_rsa_files():
    key = RSA.generate(2048)
    #write out private key
    private_key = key.export_key()
    file_out=open("private.pem","wb")
    file_out.write(private_key)
    #write out public key
    public_key=key.publickey().export_key()
    file_out = open("public.pem", "wb")
    file_out.write(public_key)


def encrypt_with_rsa():
    public_key = RSA.import_key(open("public.pem").read())
    session_key=make_session_key()
    print(session_key)
    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    print(enc_session_key)
    return(enc_session_key)

def decrypt_with_rsa(enc_session_key):
    #take in private key
    private_key = RSA.import_key(open("private.pem").read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    print(session_key)


def parse_json_iv(AES_key,encrypted_message):
    b64 = json.loads(encrypted_message)
    iv = b64decode(b64['iv'])
    return iv

def parse_json_ct(AES_key, encrypted_message):
    b64 = json.loads(encrypted_message)
    ciphertext=b64decode(b64['ciphertext'])
    return ciphertext


if __name__ == '__main__':

    session_key=make_session_key()
    aes_key=make_aes_key()
    encrypted_message=encrypt_with_aes(aes_key,session_key)
    print(encrypted_message)
    decrypt_with_aes(aes_key,encrypted_message)
    #make_rsa_files()
    encrypted_session_key=encrypt_with_rsa()
    decrypt_with_rsa(encrypted_session_key)
    print(int(random() * 100))