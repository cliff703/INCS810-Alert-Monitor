from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, BestAvailableEncryption, load_pem_public_key, load_pem_private_key, NoEncryption

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import socket, os, threading, time

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad

import numpy as np
import cv2
import tensorflow as tf

from playsound import playsound

HEADER = 64
PORT = 5050
# SERVER = socket.gethostbyname(socket.gethostname()) # find self ip automatically
# SERVER = '169.254.171.19' # using small router
# SERVER = '10.0.0.145' # using home router
SERVER = '192.168.56.1'
ADDR = (SERVER, PORT) # (str, int)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SESSION_KEY = b''
WARNING_THRESHOLD = 5 
DECISION_THRESHOLD = 0.2
SIGN_LEN = 114
AES_BLOCK_SIZE = 16



def send(conn, msg, session_key):
    timestamp = int(time.time()).to_bytes(4, 'big')

    # cipher_aes = AES.new(session_key, AES.MODE_CTR)
    # cipher_text = cipher_aes.encrypt(timestamp + msg)
    # start the encryptor
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()

    cipher_text = encryptor.update(timestamp + msg) + encryptor.finalize()

    payload = nonce + cipher_text
    payload_length = len(payload)

    send_length = str(payload_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))

    conn.send(send_length)
    conn.send(payload)


def find_biggest_eyes_index(eyes):
    eye_area = [w*h for (x,y,w,h) in eyes]
    print(eye_area)
    large_a, large_b, large_a_index, large_b_index = 0,0,0,0
    
    for i in range(len(eye_area)):
        if eye_area[i] >= large_b:
            large_a = large_b
            large_a_index = large_b_index
            
            large_b = eye_area[i]
            large_b_index = i
        elif eye_area[i] >= large_a:
            large_a = eye_area[i]
            large_a_index = i
    
    return (large_a_index, large_b_index)

def detect_eyes(face_img, classifier):
    gray_frame = cv2.cvtColor(face_img, cv2.COLOR_BGR2GRAY)
    eyes = classifier.detectMultiScale(gray_frame) # detect eyes
    print("\n--------------------------------------------------")
    print(f"return from haas eyes cascade is {eyes}")
    print(f"return from haas eyes cascade has len {len(eyes)}")
    print(f"return from haas eyes cascade has type {type(eyes)}")
    width = np.size(face_img, 1)
    height = np.size(face_img, 0)

    left_eye = None
    right_eye = None

    if len(eyes) > 0:
        upper_face_eyes = []

        for (x, y, w, h) in eyes:
            print("eyes are uppered")
            if y < height / 2:
                upper_face_eyes.append((x,y,w,h))

        # from here on we only work with upper_face_eyes
        if len(upper_face_eyes) >= 2:
            a, b = find_biggest_eyes_index(upper_face_eyes)

            lx,ly,lw,lh = upper_face_eyes[a]
            rx,ry,rw,rh = upper_face_eyes[b]
            left_eye = face_img[ly:ly+lh, lx:lx+lw]
            right_eye = face_img[ry:ry+rh, rx:rx+rw]
            upper_face_eyes = [upper_face_eyes[a], upper_face_eyes[b]]
            print("eyes are trimmed")
        elif len(upper_face_eyes) == 1:
            #print(upper_face_eyes)
            lx,ly,lw,lh = upper_face_eyes[0]
            left_eye = face_img[ly:ly+lh, lx:lx+lw]

        for (x,y,w,h) in upper_face_eyes:
            print(f"upper_face_eyes: {upper_face_eyes}")
            print(f"will draw {len(upper_face_eyes)} rects")
            cv2.rectangle(face_img, (x,y),(x+w,y+h),(0,255,0), 2)
        print("\n--------------------------------------------------")
    
    return left_eye, right_eye

def detect_faces(whole_img, classifier):
    gray_frame = cv2.cvtColor(whole_img, cv2.COLOR_BGR2GRAY)
    faces = classifier.detectMultiScale(gray_frame, 1.3, 5)
    if len(faces) > 1:  # More than 1 face detected
        biggest = (0, 0, 0, 0)
        for face in faces:
            if face[3] > biggest[3]:
                biggest = face
        np.expand_dims(biggest, 0)
    
    elif len(faces) == 1:  # Only 1 face detected
        biggest = faces
    else: # No face detected
        return None
    
    if biggest.ndim == 1:
        print(biggest)

    # if biggest.ndim < 2:
    #     return None
    # else:
    for (x,y,w,h) in biggest:
        color_frame = whole_img[y:y+h, x:x+w]
        cv2.rectangle(whole_img, (x,y),(x+w,y+h),(255,0,0), 2)
    
    return color_frame

def handle_client(conn, addr, AES_key):
    print(f"[NEW CONNECTION] {conn.getpeername()} connected.") # could be get peername, or just addr

    # new_model_1 = tf.keras.models.load_model("models/trained_model_for_810.h5") 
    new_model_1 = tf.keras.models.load_model("models/frozen_trained_model_for_810.h5") 
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_eye.xml')
    
    connected = True
    strike = 0
    eye_states = []

    while connected:
        msg_length = conn.recv(HEADER).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length)
            if msg_length:
                #get the nonce
                nonce = conn.recv(AES_BLOCK_SIZE)
                print(f"nonce is {nonce}")

                # get the ciphertext
                msg_length -= AES_BLOCK_SIZE 
                msg = b''
                while msg_length >= 4096:
                    msg = msg + conn.recv(4096, socket.MSG_WAITALL)
                    msg_length -= 4096
                msg = msg + conn.recv(msg_length, socket.MSG_WAITALL)

                cipher = Cipher(algorithms.AES(AES_key), modes.CTR(nonce))
                # cipher_aes = AES.new(SESSION_KEY, AES.MODE_CTR, nonce=nonce)
                # plaintext = cipher_aes.decrypt(msg)
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(msg) + decryptor.finalize()

                msg_timestamp = int.from_bytes(plaintext[:4], 'big')
                current_timestamp = int(time.time())
                print(f"message is timestamped at {msg_timestamp}")
                print(f"current time is {current_timestamp}")
                print(f"time difference is {current_timestamp - msg_timestamp} seconds")
                #original = unpad(plaintext, AES.block_size)
                if current_timestamp - msg_timestamp < 3:
                    img_d_flattened = np.frombuffer(plaintext[4:], dtype=np.uint8)
                    img_d_recovered = cv2.imdecode(img_d_flattened, cv2.IMREAD_COLOR)
                    cv2.imshow("The decrypted image", img_d_recovered)
                    key = cv2.waitKey(1)
                    if key == ord('q'):
                        cv2.destroyAllWindows()
                        break

                    face = detect_faces(img_d_recovered, face_cascade)
                    # if face is None:
                    #     print("NO FACE")
                    #     strike += 1
                        #playsound("sounds/noface.mp3")

                    if face is not None:
                        cv2.imshow("the face", face)
                        key = cv2.waitKey(1)
                        if key == ord('q'):
                            cv2.destroyAllWindows()
                            break
                        left_eye, right_eye = detect_eyes(face, eye_cascade)
                        cv2.imshow("the face", face)
                        key = cv2.waitKey(1)
                        if key == ord('q'):
                            cv2.destroyAllWindows()
                            break

                        if left_eye is None and right_eye is None: # no eyes are detected from the face
                            #playsound('sounds/noeyes.mp3')
                            print("NO EYES, STRIKE!")
                            strike += 1

                        else:
                            if left_eye is not None:
                                #playsound('sounds/lefteye.mp3')

                                final_image = cv2.resize(left_eye, (224, 224))
                                final_image = np.expand_dims(final_image, axis=0)
                                final_image = final_image / 255
                                print(f"**********left eye decision value is {new_model_1.predict(final_image)[0][0]}")
                                eye_states.append(new_model_1.predict(final_image)[0][0] <= DECISION_THRESHOLD)
                            if right_eye is not None:
                                #playsound('sounds/righteye.mp3')
                                final_image = cv2.resize(right_eye, (224, 224))
                                final_image = np.expand_dims(final_image, axis=0)
                                final_image = final_image / 255
                                print(f"**********right eye decision value is {new_model_1.predict(final_image)[0][0]}")
                                eye_states.append(new_model_1.predict(final_image)[0][0] <= DECISION_THRESHOLD)
                                print(f"eye state is {eye_states}")
                            if not any(eye_states): # all detected eyes closed
                                playsound('sounds/strike.mp3')
                                strike += 1
                                eye_states = []
                                print("strike given")
                            print(f"Total Strike is {strike}")
                            if any(eye_states): # not all eyes closed
                                playsound('sounds/reset.mp3')
                                print("at least one eye is open, resetting strike")
                                strike = 0
                                eye_states = []

                    else: # no face detected
                        print("NO FACE")
                        strike += 1
                    if strike >= WARNING_THRESHOLD:
                        strike = 0
                        # play a local warning
                        # send alert message to client
                        send(conn, b'sleep', AES_key)
                        playsound('sounds/rest_area_warning.mp3')
                    else:
                        # send reply to client
                        send(conn, b'awake', AES_key)
                    # cv2.imshow("The decrypted image", face)
                    # cv2.destroyAllWindows()
                else:
                    print("message timestamp failed.")
                    send(conn, b'stamp', AES_key)
            #elif msg.decode() == DISCONNECT_MESSAGE:
                #connected = False
    conn.close()


def start(server, s_priv_key, c_pub_key):
    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while True:
        conn, addr = server.accept()  # conn-new socket object; addr-address of the other side; this line will block
        AES_key = do_dh(conn, s_priv_key, c_pub_key)
        thread = threading.Thread(target=handle_client, args=(conn, addr, AES_key))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}") # minus 1 due to this thread that listens


def do_dh(conn, s_priv_key, c_pub_key):
    AES_key = b''
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    public_key_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    print(public_key_bytes)
    signature_bytes = s_priv_key.sign(public_key_bytes) #signature is always 114 bytes

    payload = signature_bytes + public_key_bytes
    payload_length = len(payload)

    send_length = str(payload_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))

    conn.send(send_length)
    conn.send(payload)

    msg_length = conn.recv(HEADER).decode(FORMAT)
    if msg_length:
        msg_length = int(msg_length)
        msg = conn.recv(msg_length, socket.MSG_WAITALL)
        assert len(msg) == 329, f"length of recv msg is {len(msg)}"

        signature = msg[:SIGN_LEN]
        dh_pub_key = msg[SIGN_LEN:]

        try:
            c_pub_key.verify(signature, dh_pub_key)
        except Exception as e:
            print(e)
            print("Client's DH public key verification failed")
            conn.close()
            return e
        else:
            # comment DH here.
            # reconstruct other party's public key into object
            peer_public_key = load_pem_public_key(dh_pub_key)
            shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
            AES_key = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)

    return AES_key

if __name__ == "__main__":
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
                with open('.\keys\s_priv_key_file.pem', 'rb') as key_file:
                    s_priv_key = load_pem_private_key(key_file.read(), user_input_pwd)
                try:
                    with open(".\keys\c_pub_key_file.pem", 'rb') as key_file:
                        c_pub_key = load_pem_public_key(key_file.read())
                except Exception as e:
                    print(e)
                    print("loading client's public key from file failed.")
                    break
                
                # start TCP connection here
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.bind(ADDR)
                print("[STARTING] server is starting...")
                start(server, s_priv_key, c_pub_key)
            else:
                print("password is wrong!!!!")
            
        elif user_in == '2':
            try: 
                hash_file =  open('pwd_hash.pwd', 'rb')
            
            except Exception as e:
                new_password = bytes(input("Password hash does not exist, please enter new password in printable ascii. > "), 'utf-8')
                digest = hashes.Hash(hashes.SHA256())
                digest.update(new_password)
                pwd_hash = digest.finalize()
                
                with open('pwd_hash.pwd', 'wb') as hash_file:
                    hash_file.write(pwd_hash)
                
                with open('.\keys\s_priv_key_file.pem', 'rb') as key_file:
                    s_priv_key = load_pem_private_key(key_file.read(), new_password) # user entered pwd must match key pwd
                    
                temp1 = s_priv_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(new_password))
                print(f"the enc private key is {temp1}")
                
                temp2 = s_priv_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
                print(f"the private key in plaintexst is {temp2}")
                
                with open('.\keys\s_priv_key_file.pem', 'wb') as key_file:
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

                        user_input_new_pwd = bytes(input("Pwds correct.  Please enter new password. > "), 'utf-8')
                        digest = hashes.Hash(hashes.SHA256())
                        digest.update(user_input_new_pwd)
                        new_pwd_hash = digest.finalize()
                        
                        with open('pwd_hash.pwd', 'wb') as hash_file:
                            hash_file.write(new_pwd_hash)
                        
                        with open('.\keys\s_priv_key_file.pem', 'rb') as key_file:
                            s_priv_key = load_pem_private_key(key_file.read(), user_input_pwd_1)
                    
                        temp = s_priv_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(user_input_new_pwd))
                        print(f"new enc private key is {temp}")
                        
                        with open('.\keys\s_priv_key_file.pem', 'wb') as key_file:
                            key_file.write(temp)
                        
                    else:
                        print("You have entered a wrong password.")

                else:
                    print("Passwords does not match.  Please try again.")
        elif user_in == '3':
            print("user wants to exit")
            break
                                    
                
                
