import cv2
import numpy as np
from cryptography.fernet import Fernet
import os
import logging
import hashlib
import base64

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_key(password, salt=b'some_fixed_salt'):
    """Generate a key from the password using PBKDF2."""
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(key)

def encrypt_message(message, password):
    logging.debug("Encrypting message.")
    key = generate_key(password)
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    logging.debug(f"Encrypted message: {encrypted_message}")
    return encrypted_message

def decrypt_message(encrypted_message, password):
    logging.debug("Decrypting message.")
    key = generate_key(password)
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    logging.debug(f"Decrypted message: {decrypted_message}")
    return decrypted_message

def encode_message(image_path, message, output_folder):
    logging.info("Starting to encode message into image.")
    password = input("Enter passcode for encryption: ")
    encrypted_message = encrypt_message(message, password)
    
    binary_message = ''.join(format(byte, '08b') for byte in encrypted_message) + '1111111111111110'
    logging.debug(f"Binary message length: {len(binary_message)}")

    image = cv2.imread(image_path)
    if image is None:
        logging.error(f"Unable to open image at {image_path}. Please check the file path.")
        return None

    pixels = np.array(image)

    index = 0
    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):
                if index < len(binary_message):
                    pixels[i, j, k] = (pixels[i, j, k] & ~1) | int(binary_message[index])
                    index += 1

    input_filename = os.path.basename(image_path)
    output_filename = f"encoded_{input_filename.split('.')[0]}.png"
    output_path = os.path.join(output_folder, output_filename)

    success = cv2.imwrite(output_path, pixels)
    if not success:
        logging.error(f"Unable to save the encoded image to {output_path}.")
        return None

    logging.info(f"Encoding completed successfully! Saved to {output_path}")
    return output_path

def decode_message(image_path, password):
    logging.info("Starting to decode message from image.")
    image = cv2.imread(image_path)
    if image is None:
        logging.error(f"Unable to open encoded image at {image_path}. Please check the file path.")
        return None

    pixels = np.array(image)

    binary_message = ""
    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):
                binary_message += str(pixels[i, j, k] & 1)

    bytes_list = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
    encrypted_message = bytearray(int(byte, 2) for byte in bytes_list if int(byte, 2) != 0)

    if not encrypted_message:
        logging.error("No encrypted message found in the image.")
        return None

    logging.debug(f"Extracted encrypted message length: {len(encrypted_message)}")

    try:
        decrypted_message = decrypt_message(bytes(encrypted_message), password)
        return decrypted_message
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        return None

if __name__ == "__main__":
    image_path = input("Enter the path to the input image: ")
    output_folder = input("Enter the output folder path (leave empty for default): ")
    if not output_folder.strip():
        output_folder = os.path.join(os.getcwd(), "default_output")
        logging.info(f"No output folder specified. Using default: {output_folder}")

    os.makedirs(output_folder, exist_ok=True)

    secret_message = input("Enter the secret message: ")
    encoded_image_path = encode_message(image_path, secret_message, output_folder)

    if encoded_image_path:
        decryption_passcode = input("Enter passcode for decryption: ")
        decoded_message = decode_message(encoded_image_path, decryption_passcode)
        print("Decoded message:", decoded_message)
