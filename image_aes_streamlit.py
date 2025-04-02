import streamlit as st
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from PIL import Image, UnidentifiedImageError
import io
import base64
import numpy as np
import zlib
import re

# Track failed attempts
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
LOCKOUT_LIMIT = 3  # Lock after 3 incorrect attempts

# Function to derive encryption key
def derive_key(password: str, salt: bytes = b'static_salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Password validation function
def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not any(char.isupper() for char in password):
        return "Password must contain at least one uppercase letter."
    if not any(char.islower() for char in password):
        return "Password must contain at least one lowercase letter."
    if not any(char.isdigit() for char in password):
        return "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character (!@#$%^&* etc)."
    return None  # Password is valid

# Function to embed an image inside another using LSB
def embed_image(cover_img, secret_img):
    cover_pixels = np.array(cover_img)
    cover_capacity = cover_pixels.size * 3  

    # Convert secret image to bytes and compress
    secret_bytes_io = io.BytesIO()
    secret_img.save(secret_bytes_io, format="PNG")
    secret_bytes = secret_bytes_io.getvalue()
    compressed_bytes = zlib.compress(secret_bytes)  # Compress before embedding

    # Convert compressed bytes to Base64 and then binary
    secret_b64 = base64.b64encode(compressed_bytes).decode()
    secret_bin = ''.join(format(ord(char), '08b') for char in secret_b64)

    # Append EOF marker
    eof_marker = '1111111111111110'
    secret_bin += eof_marker

    # Check if it fits in cover image
    if len(secret_bin) > cover_capacity:
        st.error("Secret image is too large! Resize and try again.")
        return None

    # Flatten and embed data
    flat_cover = cover_pixels.flatten()
    for i in range(len(secret_bin)):
        flat_cover[i] = (flat_cover[i] & ~1) | int(secret_bin[i])

    print(f"Compressed secret size: {len(compressed_bytes)} bytes")
    print(f"Embedded {len(secret_bin)} bits into cover image.")

    return Image.fromarray(flat_cover.reshape(cover_pixels.shape))


# Function to extract a hidden image
def extract_image(cover_image):
    cover_array = np.array(cover_image)
    flat_cover = cover_array.flatten()

    # Extract LSBs and convert to binary
    extracted_bits = ''.join(str(bit) for bit in (flat_cover & 1))

    # Find EOF marker
    eof_marker = '1111111111111110'
    eof_index = extracted_bits.find(eof_marker)

    if eof_index == -1:
        st.error("No hidden image found!")
        return None

    # Keep only valid bits before EOF
    extracted_bits = extracted_bits[:eof_index]

    # Convert binary back to Base64 string
    extracted_chars = [chr(int(extracted_bits[i:i+8], 2)) for i in range(0, len(extracted_bits), 8)]
    extracted_b64 = ''.join(extracted_chars)

    try:
        compressed_bytes = base64.b64decode(extracted_b64)
        extracted_bytes = zlib.decompress(compressed_bytes)  # Decompress data

        extracted_image = Image.open(io.BytesIO(extracted_bytes))
        extracted_image.load()
        return extracted_image
    except Exception as e:
        st.error(f"Extraction failed! Error: {e}")
        return None


# Encrypt Image Function
def encrypt_image(image_bytes, password):
    cipher = Fernet(derive_key(password))
    return cipher.encrypt(image_bytes)

# Decrypt Image Function
def decrypt_image(encrypted_data, password):
    try:
        cipher = Fernet(derive_key(password))
        decrypted_data = cipher.decrypt(encrypted_data)
        decrypted_image = Image.open(io.BytesIO(decrypted_data))

        # Extract the hidden image
        extracted_image = extract_image(decrypted_image)

        return decrypted_image, extracted_image
    except Exception:
        return None, None  # Indicate failure


# Streamlit UI
st.title("Image Steganography with Encryption & Password Protection")

menu = st.sidebar.radio("Select an Option", ["Encrypt Image", "Decrypt Image"])

if menu == "Encrypt Image":
    st.subheader("Upload a Cover Image")
    base_image = st.file_uploader("Choose an Image", type=["png", "jpg", "jpeg"])

    if base_image:
        st.subheader("Upload a Secret Image")
        secret_image = st.file_uploader("Upload Second Image", type=["png", "jpg", "jpeg"])

    password = st.text_input("Enter a Password for Encryption", type="password")

    if password:
        validation_error = validate_password(password)
        if validation_error:
            st.error(validation_error)

    if base_image and secret_image and password and not validation_error:
        base_img = Image.open(base_image).convert("RGB")
        secret_img = Image.open(secret_image).convert("RGB")

        embedded_img = embed_image(base_img, secret_img)

        if embedded_img:
            image_bytes = io.BytesIO()
            embedded_img.save(image_bytes, format="PNG")
            encrypted_data = encrypt_image(image_bytes.getvalue(), password)

            st.success("Encryption successful!")
            st.image(embedded_img, caption="Stego Image with Hidden Data")
            st.download_button("Download Encrypted File", encrypted_data, "encrypted_image.enc")

elif menu == "Decrypt Image":
    if st.session_state.failed_attempts >= LOCKOUT_LIMIT:
        st.error("Too many failed attempts! You are locked out.")
    else:
        st.subheader("Upload Encrypted File")
        encrypted_file = st.file_uploader("Choose an Encrypted File", type=["enc"])
        password = st.text_input("Enter the Decryption Password", type="password")

        if encrypted_file and password:
            encrypted_data = encrypted_file.read()
            decrypted_image, extracted_image = decrypt_image(encrypted_data, password)

            if decrypted_image:
                st.success("Decryption successful!")
                st.image(decrypted_image, caption="Decrypted Cover Image")

                if extracted_image:
                    st.image(extracted_image, caption="Extracted Hidden Image")
                    extracted_img_bytes = io.BytesIO()
                    extracted_image.save(extracted_img_bytes, format="PNG")
                    st.download_button("Download Extracted Image", extracted_img_bytes.getvalue(), "extracted_image.png")

                st.session_state.failed_attempts = 0  # Reset on success
            else:
                st.session_state.failed_attempts += 1
                attempts_left = LOCKOUT_LIMIT - st.session_state.failed_attempts
                if attempts_left > 0:
                    st.error(f"Incorrect password! {attempts_left} attempts remaining.")
                else:
                    st.error("Too many failed attempts! You are now locked out.")
