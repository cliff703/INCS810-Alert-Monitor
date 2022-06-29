from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
# from Crypto.Cipher import AES, PKCS_1OAEP
from Crypto.Cipher import AES
import cv2
import matplotlib.pyplot as plt
import numpy as np
from Crypto.Util.Padding import pad, unpad
import time


# data = "I met ailiens in UFO.  Here's the map.".encode('utf-8')
# file_out = open("encrypted_data.bin", "wb")

# server_public_key = RSA.import_key(open("receiver.pem").read())
# sesson_key = get_random_bytes(16)

# cipher_rsa = PKCS_1OAEP.new(server_public_key)
# enc_session_key = cipher_rsa.encrypt(sesson_key)

img = cv2.imread("close_eye.jpg")
cv2.imshow("hi", img)
cv2.waitKey(0)
cv2.destroyAllWindows()

_, x = cv2.imencode(".jpg", img)
y = x.tobytes()
print(f"len of plaintext is {len(y)} bytes")

key = get_random_bytes(16)

cipher = AES.new(key, AES.MODE_CTR)
nonce = cipher.nonce
print(len(nonce))
ciphertext = cipher.encrypt(y)

d_cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
plaintext = d_cipher.decrypt(ciphertext)

img_d = np.frombuffer(plaintext, dtype=np.uint8)

img_d = cv2.imdecode(img_d, cv2.IMREAD_COLOR)

cv2.imshow("hi", img_d)
cv2.waitKey(0)
cv2.destroyAllWindows()