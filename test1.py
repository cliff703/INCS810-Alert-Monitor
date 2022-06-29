import cv2
import numpy as np

def detect_eyes(face_img, classifier):
    gray_frame = cv2.cvtColor(face_img, cv2.COLOR_BGR2GRAY)
    eyes = classifier.detectMultiScale(gray_frame) # detect eyes
    width = np.size(face_img, 1)
    height = np.size(face_img, 0)

    left_eye = None
    right_eye = None

    for (x, y, w, h) in eyes:
        if y > height / 2:
            pass
        else:
            cv2.rectangle(face_img, (x,y),(x+w,y+h),(0,255,0), 2)
            eyecenter = x + (w / 2)
            if eyecenter < width * 0.5:
                left_eye = face_img[y:y+h, x:x+w]
            else:
                right_eye = face_img[y:y+h, x:x+w]
    
    return left_eye, right_eye

def detect_faces(whole_img, classifier):
    gray_frame = cv2.cvtColor(whole_img, cv2.COLOR_BGR2GRAY)
    faces = classifier.detectMultiScale(gray_frame, 1.3, 5)
    if len(faces) > 1:  # More than 1 face detected
        biggest = (0, 0, 0, 0)
        for face in faces:
            if face[3] > biggest[3]:
                biggest = face
    
    elif len(faces) == 1:  # Only 1 face detected
        biggest = faces
    else: # No face detected
        return None
    
    for (x,y,w,h) in biggest:
        color_frame = whole_img[y:y+h, x:x+w]
        cv2.rectangle(whole_img, (x,y),(x+w,y+h),(255,0,0), 2)
    
    return color_frame

face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
                                      
eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_eye.xml')

img = cv2.imread("close_eye.jpg")

face = detect_faces(img, face_cascade)
left_eye, right_eye = detect_eyes(face, eye_cascade)

cv2.imshow('my_image', img)
cv2.waitKey(0)
cv2.destroyAllWindows()