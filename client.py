from requests import session
# import tensorflow as tf
import socket
import cv2
import time
import numpy as np
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
import random
import threading

#----------GLOBAL VARIABLES---------- 
HEADER = 64
KEY_SIZE = 16
PORT = 5050 #??
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
# SERVER = "169.254.155.73"
SERVER = "192.168.56.102"
ADDR = (SERVER, PORT)
#----------END GLOBAL VARIABLES---------- 

#----------FUNCTION DEF----------
def send(msg, session_key):
    timestamp = int(time.time()).to_bytes(4, 'big')

    cipher_aes = AES.new(session_key, AES.MODE_CTR)
    cipher_text = cipher_aes.encrypt(timestamp + msg)

    payload = cipher_aes.nonce + cipher_text
    payload_length = len(payload)

    send_length = str(payload_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))

    client.send(send_length)
    client.send(payload)


def send_key(enc_session_key):
    msg_length = len(enc_session_key)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(enc_session_key)

def check_eye():
    global SHOULD_CHECK_EYE 
    while True:
        time.sleep(2)
        SHOULD_CHECK_EYE = True
#----------END FUNCTION DEF----------


#----------CONN SERVER----------
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)
#----------END CONN SERVER----------


#----------KEY EXCH----------
# Generate a secret key and send to server
session_key = get_random_bytes(AES.block_size)

server_pubkey_file = open('public.pem')
server_pubkey = RSA.import_key(server_pubkey_file.read())
server_pubkey_file.close()

cipher_rsa = PKCS1_OAEP.new(server_pubkey)
enc_session_key = cipher_rsa.encrypt(session_key)

send_key(enc_session_key)
#----------END KEY EXCH----------


#----------OPEN CAM----------
cap = cv2.VideoCapture(0)  # 0 is self facing
if not cap.isOpened():
    raise IOError("Cannot open webcam")
#----------END OPEN CAM----------

while True:
    time.sleep(3)

    # debug code
    # img = cv2.imread("stock.jpeg")
    _, img = cap.read()

    cv2.imshow("hi", img)

    key = cv2.waitKey(1)
    if key == ord('s'):
        time.sleep(10)
    elif key == ord('r'):
        strike = 0
        print("Manual override")
    elif key == ord('q'):
        break
    else:
        pass
    _, img_flattened =  cv2.imencode(".jpg", img)
    img_bytes = img_flattened.tobytes()

    send(img_bytes, session_key)

    msg_length = client.recv(HEADER).decode(FORMAT)
    if msg_length:
        msg_length = int(msg_length)
        msg = client.recv(msg_length, socket.MSG_WAITALL)
        if len(msg) == 17: # nonce + message
            r_cipher = AES.new(session_key, AES.MODE_CTR, nonce=msg[:8])
            plaintext = r_cipher.decrypt(msg[8:])
            print(f"the timestamp is {int.from_bytes(plaintext[:4], 'big')}")
            print(f"the plaintext from server is: {plaintext[4:]}")