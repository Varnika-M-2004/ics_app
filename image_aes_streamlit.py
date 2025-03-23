import os
import streamlit as st
from cryptography.fernet import Fernet
from PIL import Image
import io

# Generate or load encryption key
KEY_FILE = "secret.key"

def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return Fernet(key)

cipher = generate_key()

# Streamlit UI
st.title("Image Encryption & Decryption App")

# Encrypt Image Function
def encrypt_image(image):
    image_bytes = image.getvalue()
    encrypted_data = cipher.encrypt(image_bytes)
    return encrypted_data

# Decrypt Image Function
def decrypt_image(encrypted_data):
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data

# Sidebar Menu
menu = st.sidebar.radio("Select an Option", ["Encrypt Image", "Decrypt Image"])

if menu == "Encrypt Image":
    st.subheader("Upload an Image to Encrypt")
    uploaded_image = st.file_uploader("Choose an Image", type=["png", "jpg", "jpeg"])

    if uploaded_image is not None:
        st.image(uploaded_image, caption="Original Image", use_column_width=True)
        encrypted_data = encrypt_image(uploaded_image)
        st.success("Image Encrypted Successfully!")

        # Provide download button for encrypted image
        st.download_button(
            label="Download Encrypted File",
            data=encrypted_data,
            file_name="encrypted_image.enc",
            mime="application/octet-stream"
        )

elif menu == "Decrypt Image":
    st.subheader("Upload an Encrypted File to Decrypt")
    uploaded_file = st.file_uploader("Choose an Encrypted File", type=["enc"])

    if uploaded_file is not None:
        encrypted_data = uploaded_file.read()
        try:
            decrypted_data = decrypt_image(encrypted_data)
            decrypted_image = Image.open(io.BytesIO(decrypted_data))
            st.image(decrypted_image, caption="Decrypted Image", use_column_width=True)

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
        except:
            st.error("Invalid Encryption File! Please upload a valid encrypted file.")

