"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names: Chris Kardaras, Charlie Bourland, Sam Brin



"""

import socket
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
import hashlib

host = "localhost"
port = 10001


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    # TODO: Implement this function
    private_key = RSA.import_key(open("../private.pem").read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(session_key)
    return session_key
    


# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
    # TODO: Implement this function
    message=pickle.loads(client_message)
    b64 = json.loads(message)
    iv = b64decode(b64['iv'])
    ciphertext=b64decode(b64['ciphertext'])
    cipher=AES.new(session_key,AES.MODE_CBC,iv)
    plaintext=unpad(cipher.decrypt(ciphertext),16)
    return plaintext


# Encrypt a message using the session key
def encrypt_message(message, session_key):
    # TODO: Implement this function
    aes_cipher = AES.new(session_key, AES.MODE_CBC)
    ct_bytes = aes_cipher.encrypt(pad(message, AES.block_size))
    iv = b64encode(aes_cipher.iv).decode('utf-8')
    ciphertext = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv': iv, 'ciphertext': ciphertext})
    pickled = pickle.dumps(result)
    return pickled


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if bytes(line[0],'utf-8') == user:
                full_pass=password.decode('utf-8')+line[1]
                # TODO: Generate the hashed password
                hashed_password = (hashlib.sha256(full_pass.encode('utf-8'))).hexdigest()
                return (hashed_password == line[2])
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                # TODO: Decrypt message from client
                plaintext = decrypt_message(ciphertext_message,plaintext_key)
                login=plaintext.split()
                user=login[0]
                password=login[1]
                if(verify_hash(user,password)==False):
                    mymessage = b"This is not a valid login"
                else:
                    mymessage=b"This is a valid login"


                # TODO: Split response from user into the username and password
                
                # TODO: Encrypt response to client

                ciphertext_response=encrypt_message(mymessage,plaintext_key)


                # Send encrypted response
                send_message(connection, ciphertext_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
