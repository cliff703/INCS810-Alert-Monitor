from gtts import gTTS
tts = gTTS("Left eye detected")
tts_1 = gTTS("right eye detected")
tts.save("lefteye.mp3")
tts_1.save("righteye.mp3")