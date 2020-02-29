"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:



"""
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

import socket
import os


host = "localhost"
port = 10001
Server_Pub = 'AAAAB3NzaC1yc2EAAAADAQABAAABgQDVhkkpCrt+EjveHi8kQQThYJ4PpR7lXAQ68pFdN4PaBVoqUdcTxrmXDYbEHXCGiksveuHoNW8fpmw6qKggZ/SmlD6jGCVLW1TgKjn390IVENKz0PFJ3Wpr2q90y2MK6GqahduW3GBjFCz7yDXF+qCr4FRwrwYlIWkNNYqdDsdb1t4eJ08LuOtfkt7LIh45USgKsaE0a+ewNpQp9MBNx4keGcZSk1xMwSQnajqwBiFEw7SwoxPMza0FevNE3frC7eUCcYWhpFkAfsoBbu1JEiYtr/yQ/mpMLhkMeJNlEtz5NohEC8wpFgq8DBk0rVKrKBbaQZERXJxTQ62+POZtp8qaMxqCB38ka6WaGHFu+FnqDY/2Tid3LMdh6OXMIJReTfX8i7OghyREzb9yu2iBPrb+u+Q4odBW/Tj3zq2i0DCJEf9p+Mj19YKjLXIFr8w78xpJJmYnqDeUf0TA2a7zj25/CrDwXGDnUiSzbfvaR3ElSHIa/SVeG7VwrYHc57jACUE='


# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)


# TODO: Generate a cryptographically random AES key
def generate_key():
    # TODO: Implement this function
    return os.urandom(16)


# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    # TODO: Implement this function

    Pub_key = RSA.import_key(open("public.pem").read())
    
    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(Pub_key)
    return cipher_rsa.encrypt(session_key)



# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    # TODO: Implement this function

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)
    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]

    pass


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    # TODO: Implement this function
    pass


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

        # TODO: Receive and decrypt response from server
    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
