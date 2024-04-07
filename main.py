from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
import base64
from PIL import Image

# Function to generate a key from a password
def generate_key(password):
    password = password.encode()
    salt = b'salt_'  # Change this to your own salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

# Function to encrypt an image
def encrypt_image(input_image_path, output_image_path, key):
    with open(input_image_path, 'rb') as f:
        image_data = f.read()

    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(image_data)

    with open(output_image_path, 'wb') as f:
        f.write(encrypted_data)

# Main program
password = "YourPasswordHere"
key = generate_key(password)

input_image_path = "input_image.jpg"
output_image_path = "encrypted_image.jpg"

encrypt_image(input_image_path, output_image_path, key)
