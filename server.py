import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad
import numpy as np
import cv2
import tensorflow as tf
import time
from playsound import playsound


HEADER = 64
PORT = 5050
SERVER = socket.gethostbyname(socket.gethostname()) # find self ip automatically
# SERVER = '169.254.171.19' # using small router
# SERVER = '10.0.0.145' # using home router
ADDR = (SERVER, PORT) # (str, int)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SESSION_KEY = b''
WARNING_THRESHOLD = 10
DECISION_THRESHOLD = 0.2


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)
def send(conn, msg, session_key):
    timestamp = int(time.time()).to_bytes(4, 'big')

    cipher_aes = AES.new(session_key, AES.MODE_CTR)
    cipher_text = cipher_aes.encrypt(timestamp + msg)

    payload = cipher_aes.nonce + cipher_text
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

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {conn.getpeername()} connected.") # could be get peername, or just addr

    # new_model_1 = tf.keras.models.load_model("models/trained_model_for_810.h5") 
    new_model_1 = tf.keras.models.load_model("models/frozen_trained_model_for_810.h5") 
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    print(face_cascade)
    eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_eye.xml')
    
    connected = True
    strike = 0
    eye_states = []

    while connected:
        msg_length = conn.recv(HEADER).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length)
            if msg_length == 256: #message is a enc_session_key
                enc_session_key = conn.recv(msg_length)

                private_key_file = open('keys/private.pem')
                private_key = RSA.import_key(private_key_file.read())

                cipher_rsa = PKCS1_OAEP.new(private_key)
                SESSION_KEY = cipher_rsa.decrypt(enc_session_key)
            else:

                nonce = conn.recv(8)
                print(f"nonce is {nonce}")

                msg_length -= 8 
                msg = b''
                while msg_length >= 4096:
                    msg = msg + conn.recv(4096, socket.MSG_WAITALL)
                    msg_length -= 4096
                msg = msg + conn.recv(msg_length, socket.MSG_WAITALL)
                cipher_aes = AES.new(SESSION_KEY, AES.MODE_CTR, nonce=nonce)
                plaintext = cipher_aes.decrypt(msg)

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
                    if face is None:
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
                        strike += 1
                    if strike >= WARNING_THRESHOLD:
                        strike = 0
                        # play a local warning
                        # send alert message to client
                        send(conn, b'sleep', SESSION_KEY)
                        playsound('sounds/rest_area_warning.mp3')
                    else:
                        # send reply to client
                        send(conn, b'awake', SESSION_KEY)
                    # cv2.imshow("The decrypted image", face)
                    # cv2.destroyAllWindows()
                else:
                    print("message timestamp failed.")
                    send(conn, b'stamp', SESSION_KEY)
            #elif msg.decode() == DISCONNECT_MESSAGE:
                #connected = False
    conn.close()


def start():
    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while True:
        conn, addr = server.accept()  # conn-new socket object; addr-address of the other side; this line will block
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}") # minus 1 due to this thread that listens

print("[STARTING] server is starting...")
start()
