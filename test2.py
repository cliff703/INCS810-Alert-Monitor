import cv2

cap = cv2.VideoCapture(0)
while True:
    ret, frame = cap.read()

    cv2.imshow("Hi", frame)

    if cv2.waitKey(1) == ord('q'):  # 1ms
        break

cap.release()
cv2.destroyAllWindows()