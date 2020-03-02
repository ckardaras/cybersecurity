"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:



"""
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


import socket
import os


host = "localhost"
port = 10001

# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)


# TODO: Generate a cryptographically random AES key
# make session key
def generate_key():
    aes_session_key = get_random_bytes(16)  # make aes session key
    return aes_session_key

# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    # TODO: Implement this function
    # Encrypt the session key with the public RSA key

    public_key = RSA.import_key(open("../public.pem").read())

    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    return enc_session_key


    
    
    
   



# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    # TODO: Implement this function

    aes_cipher = AES.new(session_key, AES.MODE_CBC)
    ct_bytes = aes_cipher.encrypt(pad(message, AES.block_size))
    iv = b64encode(aes_cipher.iv).decode('utf-8')
    ciphertext = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv': iv, 'ciphertext': ciphertext})

    return result


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    # TODO: Implement this function
    b64 = json.loads(message)
    iv = b64decode(b64['iv'])
    ciphertext=b64decode(b64['ciphertext'])
    cipher=AES.new(session_key,AES.MODE_CBC,iv)
    plaintext=unpad(cipher.decrypt(ciphertext),16)
    
    return plaintext


# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # TODO: Encrypt message and send to server
        cipher = encrypt_message(message,key)
        send_message(sock,cipher)

        


        # TODO: Receive and decrypt response from server

        response = receive_message(sock)

        print(decrypt_message(response,key))

    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
