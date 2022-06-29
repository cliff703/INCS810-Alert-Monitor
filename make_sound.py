from gtts import gTTS
import playsound
import os

s = "whoop whoop! wake up! whoop whoop"
warning = gTTS(s)
warning.save("local_warning.wav")

s = "warning!  Operating pilot is asleep"
warning = gTTS(s)
warning.save("remote_warning.wav")

s = 'manual override!'
warning = gTTS(s)
warning.save("override.wav")

s = "snooze"
warning = gTTS(s)
warning.save("snooze.wav")

