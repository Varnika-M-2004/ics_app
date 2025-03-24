import os
import streamlit as st
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from PIL import Image
import io
import base64
import json
import datetime
import re

# Store failed attempts in session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Function to check password strength
def is_valid_password(password):
    if (len(password) >= 8 and 
        re.search(r'[A-Z]', password) and 
        re.search(r'[a-z]', password) and 
        re.search(r'[0-9]', password) and 
        re.search(r'[@$!%*?&]', password)):
        return True
    return False

# Function to derive encryption key from user password
def derive_key(password: str, salt: bytes = b'static_salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt Image Function with Metadata
def encrypt_image(image, password):
    cipher = Fernet(derive_key(password))
    image_bytes = image.getvalue()
    metadata = {
        "timestamp": str(datetime.datetime.now()),
        "size": len(image_bytes),
        "format": image.type,
    }
    metadata_json = json.dumps(metadata).encode()
    encrypted_metadata = cipher.encrypt(metadata_json)
    encrypted_data = cipher.encrypt(image_bytes)
    return encrypted_metadata + b"||" + encrypted_data  # Combine metadata and encrypted image

# Decrypt Image Function with Lockout Mechanism
def decrypt_image(encrypted_data, password):
    if st.session_state.failed_attempts >= 3:
        st.error("Too many failed attempts. Access denied!")
        return None, None

    try:
        cipher = Fernet(derive_key(password))
        metadata_encrypted, image_encrypted = encrypted_data.split(b"||", 1)
        metadata_json = cipher.decrypt(metadata_encrypted).decode()
        metadata = json.loads(metadata_json)
        decrypted_data = cipher.decrypt(image_encrypted)
        st.session_state.failed_attempts = 0  # Reset failed attempts on success
        return decrypted_data, metadata
    except:
        st.session_state.failed_attempts += 1  # Increment failed attempts
        remaining_attempts = 3 - st.session_state.failed_attempts
        if remaining_attempts > 0:
            st.warning(f"Incorrect password! {remaining_attempts} attempts remaining.")
        else:
            st.error("Too many failed attempts. Access denied!")
        return None, None

# Streamlit UI
st.title("Image Encryption & Decryption App")

# Sidebar Menu
menu = st.sidebar.radio("Select an Option", ["Encrypt Image", "Decrypt Image"])

if menu == "Encrypt Image":
    st.subheader("Upload an Image to Encrypt")
    uploaded_image = st.file_uploader("Choose an Image", type=["png", "jpg", "jpeg"])
    password = st.text_input("Enter a Password for Encryption", type="password")

    if uploaded_image is not None and password:
        if not is_valid_password(password):
            st.error("Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character.")
        else:
            st.image(uploaded_image, caption="Original Image", use_column_width=True)
            encrypted_data = encrypt_image(uploaded_image, password)
            st.success("Image Encrypted Successfully!")

            # Provide download button for encrypted image
            st.download_button(
                label="Download Encrypted File",
                data=encrypted_data,
                file_name="encrypted_image.enc",
                mime="application/octet-stream"
            )
    elif uploaded_image is not None:
        st.warning("Please enter a password to encrypt the image.")

elif menu == "Decrypt Image":
    st.subheader("Upload an Encrypted File to Decrypt")
    uploaded_file = st.file_uploader("Choose an Encrypted File", type=["enc"])
    password = st.text_input("Enter the Decryption Password", type="password")

    if uploaded_file is not None and password:
        encrypted_data = uploaded_file.read()
        decrypted_data, metadata = decrypt_image(encrypted_data, password)

        if decrypted_data is not None:
            decrypted_image = Image.open(io.BytesIO(decrypted_data))
            st.image(decrypted_image, caption="Decrypted Image", use_column_width=True)

            # Display Metadata
            st.write("Image Metadata")
            st.json(metadata)

            # Provide download button for decrypted image
            buf = io.BytesIO()
            decrypted_image.save(buf, format="PNG")
            byte_data = buf.getvalue()

            st.download_button(
                label="Download Decrypted Image",
                data=byte_data,
                file_name="decrypted_image.png",
                mime="image/png"
            )
    elif uploaded_file is not None:
        st.warning("Please enter a password to decrypt the image.")
