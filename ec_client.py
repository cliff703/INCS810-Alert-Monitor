# from requests import session
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
#from playsound import playsound
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, BestAvailableEncryption, load_pem_public_key, load_pem_private_key, NoEncryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#----------GLOBAL VARIABLES---------- 
HEADER = 64
KEY_SIZE = 16
PORT = 5050 # connect to server listening
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
#SERVER = "169.254.171.19"
SERVER = "192.168.56.1"
#SERVER = "10.0.0.145" #New home code
ADDR = (SERVER, PORT)
SIGN_LEN = 114
LOCAL_WARNING = 'sounds/local_warning.wav'
#----------END GLOBAL VARIABLES---------- 

#----------FUNCTION DEF----------
def send(msg, session_key):
    timestamp = int(time.time()).to_bytes(4, 'big')

    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()

    cipher_text = encryptor.update(timestamp + msg) + encryptor.finalize()
    #cipher_aes = AES.new(session_key, AES.MODE_CTR)
    #cipher_text = cipher_aes.encrypt(timestamp + msg)

    payload = nonce + cipher_text
    payload_length = len(payload)

    send_length = str(payload_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))

    client.send(send_length)
    client.send(payload)


def check_eye(cap, client, session_key):
    global keep_going
    while keep_going:
        for i in range(5, 1, -1):
            print(f"sending in {i} seconds.")
            time.sleep(1)

        ret, img = cap.read()
        if ret:
            _, img_flattened =  cv2.imencode(".jpg", img)
            img_bytes = img_flattened.tobytes()
            
            print(f"sending: {img_bytes[:10]}")
            # send away the picture with encryption
            send(img_bytes, session_key)
        else:
            print(f"Reading from webcam failed")



def wait_server(client, session_key):
    global keep_going
    while keep_going:
        msg_length = client.recv(HEADER).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length)
            msg = client.recv(msg_length, socket.MSG_WAITALL)
            print(f"raw msg received is {msg}")
            if len(msg) == 25: # nonce + enc(timestamp + message)
                #create the decryptor
                nonce = msg[:16]
                cipher = Cipher(algorithms.AES(session_key), modes.CTR(nonce))
                decryptor = cipher.decryptor()

                ciphertext = msg[16:]
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()

                msg_timestamp = int.from_bytes(plaintext[:4], 'big')
                print(f"the timestamp is {msg_timestamp}")

                current_timestamp = int(time.time())

                if current_timestamp - msg_timestamp < 3:

                    print(f"the plaintext from server is: {plaintext[4:]}")
                    if plaintext[4:] == b'sleep':
                        #os.system("mpg123 "+LOCAL_WARNING)
                        print('*****sleeping********')
                    elif plaintext[4:] == b'awake':
                        print('*****all is well********')
                        #do nothing
                    else:
                        print(f"Unknown decision from server: {plaintext}")
            else:
                print(f"Unknown message: {msg}")

def do_dh(client, c_priv_key, s_pub_key):
    session_key = b''
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    
    public_key_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    signature_bytes = c_priv_key.sign(public_key_bytes) # signature is always 114 bytes


    payload = signature_bytes + public_key_bytes
    payload_length = len(payload)

    send_length = str(payload_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))

    client.send(send_length)
    client.send(payload)

    msg_length = client.recv(HEADER).decode(FORMAT)
    if msg_length:
        msg_length = int(msg_length)
        msg = client.recv(msg_length, socket.MSG_WAITALL)
        assert len(msg) == 329, f"length of recv msg is {len(msg)}"

        signature = msg[:SIGN_LEN]
        dh_pub_key = msg[SIGN_LEN:]

        try:
            s_pub_key.verify(signature, dh_pub_key)
            print(signature)
            print(dh_pub_key)
            print("key signature successful")
        except Exception as e:
            print(e)
            print("Server's DH public key verification failed")
            client.close()
            return e
        else:
            # commence DH here.
            # reconstruct other party's public key into object
            peer_public_key = load_pem_public_key(dh_pub_key)

            # calculate the share key
            shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

            # derive the key
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)

    return session_key 

#----------END FUNCTION DEF----------


#----------LOAD SIGNATURE PRIV AND PUB KEY----------
while True:
    user_in = input("Enter 1 to login.  Enter 2 to initialize or change password. > ")
    if user_in == '1':
        
        user_input_pwd = bytes(input("Please enter password: > "), 'utf-8')
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(user_input_pwd)
        user_input_hash = digest.finalize()
        
        with open('pwd_hash.pwd', 'rb') as hash_file:
            old_pwd_hash = hash_file.read()
        
        if old_pwd_hash == user_input_hash:
            print("password is correct!!!!")
            
            # load the private key file with the input password
            with open('./keys/c_priv_key_file.pem', 'rb') as key_file:
                c_priv_key = load_pem_private_key(key_file.read(), user_input_pwd)
            
            try:
                with open("./keys/s_pub_key_file.pem", 'rb') as key_file:
                    s_pub_key = load_pem_public_key(key_file.read())
                print("public key successfully loaded from file")
            except Exception as e:
                print(e)
                print("server's public key cannot be loaded")
                break
            
            # start the connection here
            print("start conn")
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(ADDR)
            print("fin start conn")

            # do key exchange
            session_key = do_dh(client, c_priv_key, s_pub_key)

            # start the capture loop here

            #----------OPEN CAM----------
            try:
                cap = cv2.VideoCapture(0)  # 0 is self facing
                if not cap.isOpened():
                    raise IOError("Cannot open webcam")
                    exit()
            except IOError:
                print("Problem starting webcam")
            #----------END OPEN CAM----------
            else:
                # Wait for webcam to start up
                time.sleep(5)
                keep_going = True

                check_send_recv_alert_thread = threading.Thread(target=check_eye, args=(cap, client, session_key), daemon=True)
                check_send_recv_alert_thread.start()

                wait_server_thread = threading.Thread(target=wait_server, args=(client, session_key), daemon=True)
                wait_server_thread.start()

                while True:
                    ret, frame = cap.read()
                    #print(f"ret is {ret}")
                    if ret:
                        cv2.imshow("Alertness Monitor", frame)
                        key = cv2.waitKey(1)
                        if key == ord('q'):
                            keep_going = False
                            break


            finally:
                print("releasing resources")
                client.close()
                cap.release()
                cv2.destroyAllWindows()
                break
        else:
            print("password is wrong!!!!")
        
    elif user_in == '2':
        try: 
            hash_file =  open('pwd_hash.pwd', 'rb')
        
        except Exception as e:
            new_password = bytes(input("Password hash does not exist, please enter new password in printable ascii. > "), 
                    'utf-8')
            digest = hashes.Hash(hashes.SHA256())
            digest.update(new_password)
            pwd_hash = digest.finalize()
            
            with open('pwd_hash.pwd', 'wb') as hash_file:
                hash_file.write(pwd_hash)
            
            with open('./keys/c_priv_key_file.pem', 'rb') as key_file:
                c_priv_key = load_pem_private_key(key_file.read(), new_password)
                
            temp1 = c_priv_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, 
                    BestAvailableEncryption(new_password))
            print(f"the enc private key is {temp1}")
            
            temp2= c_priv_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, 
                    NoEncryption())
            print(f"the private key in plaintexst is {temp2}")
            
            with open('./keys/c_priv_key_file.pem', 'wb') as key_file:
                key_file.write(temp1)
            
            
        else:
            
            user_input_pwd_1 = bytes(input("Please enter old password. > "), 'utf-8')
            user_input_pwd_2 = bytes(input("Please enter old password again. > "), 'utf-8')
            if user_input_pwd_1 == user_input_pwd_2:
                                
                old_pwd_hash = hash_file.read()
                hash_file.close()
                
                digest = hashes.Hash(hashes.SHA256())
                digest.update(user_input_pwd_1)
                user_input_hash = digest.finalize()
                
                if old_pwd_hash == user_input_hash:

                    user_input_new_pwd = bytes(input("Pwds correct.  Please enter new password. > "), 
                            'utf-8')
                    digest = hashes.Hash(hashes.SHA256())
                    digest.update(user_input_new_pwd)
                    new_pwd_hash = digest.finalize()
                    
                    with open('pwd_hash.pwd', 'wb') as hash_file:
                        hash_file.write(new_pwd_hash)
                    
                    with open('./keys/c_priv_key_file.pem', 'rb') as key_file:
                        c_priv_key = load_pem_private_key(key_file.read(), user_input_pwd_1)
                
                    temp = c_priv_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, 
                            BestAvailableEncryption(user_input_new_pwd))
                    print(f"new enc private key is {temp}")
                    
                    with open('./keys/c_priv_key_file.pem', 'wb') as key_file:
                        key_file.write(temp)
                    
                else:
                    print("You have entered a wrong password.")

            else:
                print("Passwords does not match.  Please try again.")
    elif user_in == '3':
        print("user wants to exit")
        break
                                   
            
            

# start old code


'''

#----------OPEN CAM----------
try:
    cap = cv2.VideoCapture(0)  # 0 is self facing
    if not cap.isOpened():
        raise IOError("Cannot open webcam")
        exit()
except IOError:
    print("Problem starting webcam")
#----------END OPEN CAM----------
else:
    # Wait for webcam to start up
    time.sleep(5)
    keep_going = True

    check_send_recv_alert_thread = threading.Thread(target=check_eye, args=(cap, client, session_key), daemon=True)
    check_send_recv_alert_thread.start()

    wait_server_thread = threading.Thread(target=wait_server, args=(client, session_key), daemon=True)
    wait_server_thread.start()

    while True:
        ret, frame = cap.read()
        #print(f"ret is {ret}")
        if ret:
            cv2.imshow("Alertness Monitor", frame)
            key = cv2.waitKey(1)
            if key == ord('q'):
                keep_going = False
                break


finally:
    print("releasing resources")
    client.close()
    cap.release()
    cv2.destroyAllWindows()
'''
