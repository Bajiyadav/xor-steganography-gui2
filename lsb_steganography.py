import cv2
import numpy as np
from tqdm import tqdm
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk

# ====================== Encryption Helpers ======================

def xor_encrypt_decrypt(message, key):
    return ''.join(chr(ord(c) ^ key) for c in message)

def get_capacity(image):
    return image.shape[0] * image.shape[1] * 3 // 8

# ====================== Encoding ======================

def encode_message_gui(img_path, secret_message, key):
    image = cv2.imread(img_path)
    if image is None:
        messagebox.showerror("Error", "Could not load image!")
        return None

    encrypted_msg = xor_encrypt_decrypt(secret_message, key)
    max_bytes = get_capacity(image)
    if len(encrypted_msg) > max_bytes:
        messagebox.showerror("Error", "Message too long to embed in image!")
        return None

    message_binary = ''.join(format(ord(char), '08b') for char in encrypted_msg)
    message_binary += '1111111111111110'  # End marker

    encoded_image = np.copy(image)
    data_index = 0

    for row in tqdm(encoded_image, desc="Encoding", unit="row"):
        for pixel in row:
            for c in range(3):
                if data_index < len(message_binary):
                    pixel[c] = (pixel[c] & 0xFE) | int(message_binary[data_index])
                    data_index += 1

    with open("encrypted_message.txt", "w") as f:
        f.write(encrypted_msg)

    with open("encrypted_binary.txt", "w") as f:
        f.write(message_binary)

    output_path = "encoded_output.png"
    cv2.imwrite(output_path, encoded_image)
    return output_path

# ====================== Decoding ======================

def decode_message_gui(img_path, key):
    image = cv2.imread(img_path)
    if image is None:
        messagebox.showerror("Error", "Could not load image!")
        return None

    message_binary = ''
    for row in tqdm(image, desc="Decoding", unit="row"):
        for pixel in row:
            for c in range(3):
                message_binary += str(pixel[c] & 1)

    message = ''
    for i in range(0, len(message_binary), 8):
        byte = message_binary[i:i+8]
        if byte == '11111111' and message_binary[i+8:i+16] == '11111110':
            break
        try:
            message += chr(int(byte, 2))
        except:
            break

    decrypted = xor_encrypt_decrypt(message, key)
    return decrypted

# ====================== GUI ======================

class StegoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("XOR LSB Steganography")
        self.image_path = None

        self.label = tk.Label(root, text="No image loaded")
        self.label.pack()

        self.canvas = tk.Canvas(root, width=300, height=300)
        self.canvas.pack()

        self.load_btn = tk.Button(root, text="\U0001F4C1 Load Image", command=self.load_image)
        self.load_btn.pack()

        self.msg_entry = tk.Entry(root, width=40)
        self.msg_entry.pack()
        self.msg_entry.insert(0, "Enter secret message")

        self.key_entry = tk.Entry(root, width=20)
        self.key_entry.pack()
        self.key_entry.insert(0, "123")

        self.encode_btn = tk.Button(root, text="\U0001F510 Encode & Save", command=self.encode)
        self.encode_btn.pack()

        self.decode_btn = tk.Button(root, text="\U0001F50D Decode Message", command=self.decode)
        self.decode_btn.pack()

        self.result_label = tk.Label(root, text="")
        self.result_label.pack()

    def load_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.jpg")])
        if path:
            self.image_path = path
            self.label.config(text=f"Loaded: {path.split('/')[-1]}")
            img = Image.open(path).resize((300, 300))
            self.tkimg = ImageTk.PhotoImage(img)
            self.canvas.create_image(150, 150, image=self.tkimg)

    def encode(self):
        if not self.image_path:
            messagebox.showerror("Error", "No image loaded.")
            return
        msg = self.msg_entry.get()
        try:
            key = int(self.key_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Key must be a number.")
            return
        path = encode_message_gui(self.image_path, msg, key)
        if path:
            self.label.config(text=f"Saved as: {path.split('/')[-1]}")
            img = Image.open(path).resize((300, 300))
            self.tkimg = ImageTk.PhotoImage(img)
            self.canvas.create_image(150, 150, image=self.tkimg)

    def decode(self):
        if not self.image_path:
            messagebox.showerror("Error", "No image loaded.")
            return
        try:
            key = int(self.key_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Key must be a number.")
            return
        msg = decode_message_gui(self.image_path, key)
        if msg:
            self.result_label.config(text=f"\U0001F513 Decoded: {msg}")
        else:
            self.result_label.config(text="\u274C No message found or wrong key")

# ====================== Main App ======================

if __name__ == "__main__":
    root = tk.Tk()
    app = StegoGUI(root)
    root.mainloop()
