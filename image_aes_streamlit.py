import streamlit as st
import numpy as np
import io
import zlib
import base64
from PIL import Image

def embed_image(cover_img, secret_img):
    cover_pixels = np.array(cover_img, dtype=np.int16)  # Changed to int16 for safe operations
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

    # Flatten the cover image array
    flat_cover = cover_pixels.flatten()  

    # Debugging: Check min/max values before modifying
    print(f"Before embedding: min={flat_cover.min()}, max={flat_cover.max()}")

    for i in range(len(secret_bin)):
        old_value = flat_cover[i]
        bit_to_embed = int(secret_bin[i])

        # Embed the bit safely
        new_value = (old_value & ~1) | bit_to_embed

        # ✅ Ensure new value stays within uint8 range (0-255)
        if new_value < 0 or new_value > 255:
            print(f"Warning! Overflow at index {i}: {new_value}")
            new_value = np.clip(new_value, 0, 255)  # Fix overflow

        flat_cover[i] = new_value  # Assign safely

    # Debugging: Check min/max values after modifying
    print(f"After embedding: min={flat_cover.min()}, max={flat_cover.max()}")

    # Convert back to image
    return Image.fromarray(flat_cover.reshape(cover_pixels.shape).astype(np.uint8))
