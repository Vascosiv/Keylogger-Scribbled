from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk
from pynput.keyboard import Key, Listener
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import subprocess
import os

class Keylogger:
    def __init__(self):
        self.count = 0
        self.keys = []
        self.key = get_random_bytes(16)
        self.iv = get_random_bytes(16)
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        self.listener = None
        self.dumkey_process = None

    def on_press(self, key):
        if self.dumkey_process is not None:
            self.keys.append(key)
            self.count += 1
            print("{0} pressed".format(key))

            if self.count >= 1:
                self.count = 0
                self.keys = []

    def on_release(self, key):
        if key == Key.esc:
            self.stop_keylogger()
            return False

    def start_keylogger(self):
        self.listener = Listener(on_press=self.on_press, on_release=self.on_release)
        self.listener.start()

        # Start dumkey.py as a separate process with encryption enabled
        self.dumkey_process = subprocess.Popen(["python", "c:\\Users\\User\\Desktop\\CODE\\PROJECT\\KEYLOGGER\\Keylogger Scribbled\\dumkey\\dumkey.py", "encrypt"])

    def stop_keylogger(self):
        if self.listener is not None:
            self.listener.stop()
            self.listener.join()

        # Terminate the dumkey.py process
        if self.dumkey_process is not None:
            self.dumkey_process.kill()
            self.dumkey_process.wait()
            self.dumkey_process = None

def open_manual_window():
    manual_window = Toplevel()
    manual_window.title("User Manual")
    manual_window.geometry("700x500")
    manual_window.configure(bg="white")

    manual_label = Label(manual_window, text="Information:", font=("Arial", 14))
    manual_label.pack(pady=5)

    manual_text = Text(manual_window, width=75, height=10)
    manual_text.pack(pady=5)

    manual_text.insert(END, "Welcome to Keylogger Scribbled! This Keylogger Scribbled tool is use to act as a last defense mechanism to protect your data from Keylogger that might be installed in your device.")
                       #This is the user manual for the Keylogger Scribbled application. Please follow the instructions below to use the application properly.

    manual_list = Listbox(manual_window, width=110, height=10)
    manual_list.pack(pady=5)

    manual_items = [
        "Scanning: Scan possible keylogger file and if exist, user can terminate the process.",
        "Start Encryption: Start the encryption function to encrypt(using AES) the output stored if there's outlooked Keylogger",
        "Stop Encryption: Stop the encryption process",
    ]

    for item in manual_items:
        manual_list.insert(END, item)

def detect_keylogger():
    keyloggers = [
        "keylogger1.exe",
        "keylogger2.exe",
        "dumkey.py",
        "dumkey.exe",
        "keylog.py",
        "keylog.exe",
        "keyloggerdemo.exe",
        "KeyboardMonitoring.jar",
        "InputTracker.pu",
        "KeystrokeLogExa.c",
        # Add more keyloggers to this list as needed
    ]
    
    result = subprocess.run(["tasklist"], capture_output=True, text=True)
    running_processes = result.stdout.lower()
    
    for keylogger in keyloggers:
        if keylogger.lower() in running_processes:
            return keylogger
    
    return None

def terminate_keylogger():
    keylogger_process = detect_keylogger()
    if keylogger_process:
        os.system(f"taskkill /F /IM {keylogger_process}")
        messagebox.showinfo("Keylogger Terminated", "Keylogger has been terminated.")
    else:
        messagebox.showinfo("Keylogger Not Found", "No keylogger process found.")

def stop_encryption(keylogger):
    keylogger.stop_keylogger()
    messagebox.showinfo("Encryption Stopped", "Encryption process has been stopped.")

def show_detection_result():
    keylogger_process = detect_keylogger()
    if keylogger_process:
        result = messagebox.askquestion("Keylogger Detected", "A keylogger has been detected. Do you want to terminate it?")
        if result == 'yes':
            terminate_keylogger()
    else:
        messagebox.showinfo("Keylogger Detection Result", "No Keylogger Detected.")

root = Tk()
root.title('Keylogger Scribbled')
root.geometry("1000x600")
root.configure(bg="black")

# Load the image
image = PhotoImage(file="C:\\Users\\User\\Desktop\\CODE\\PROJECT\\KEYLOGGER\\Keylogger Scribbled\\image.png")

# Create a label and set the image
image_label = Label(root, image=image, bg="black")
image_label.config(height=85, width=90)
image_label.pack(side=TOP, pady=1)
#root.iconbitmap("C:\\Users\\User\\Desktop\\CODE\\PROJECT\KEYLOGGER\\Keylogger Scribbled\\images\\icon2.ico")'''

app_title = Label(root, text="Keylogger Scribbled", font=("Arial",35), bg="black", fg="white")
app_title.pack(side=TOP, pady=20)

'''button_home = Button(root, text="HOME", height=2, width=130)
button_home.pack(side=TOP)'''

button_manual = Button(root, text="User Manual", height=3, width=50, command=open_manual_window)
button_manual.pack(side=TOP, pady=25)

keylogger = Keylogger()

button_scan = Button(root, text="Scanning", height=3, width=50, command=show_detection_result)
button_scan.pack(side=TOP, pady=25)

button_crypt = Button(root, text="Start Encryption", height=3, width=50, command=keylogger.start_keylogger)
button_crypt.pack(side=TOP, pady=25)

button_quit = Button(root, text="Stop Encryption", height=3, width=15, command=lambda: stop_encryption(keylogger))
button_quit.pack(side=TOP, pady=10)

root.mainloop()