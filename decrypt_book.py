import hashlib

editor_key = (
    "0f52285008e030067d12d0da7c626c526db530f7"  # Replace with actual editor key
)
reader_key = (
    "45515d56a5c6d89d2c9055e96b5270755d2189be"  # Replace with actual reader key
)


def get_hash(algorithm, data):
    if algorithm == "sha1":
        return hashlib.sha1(data.encode()).hexdigest()
    elif algorithm == "md5":
        return hashlib.md5(data.encode()).hexdigest()
    return None


def compute_key_for_file(file_key):
    key_for_file = None
    try:
        sha1 = "sha1"
        key_for_file = (
            get_hash(sha1, file_key)
            + get_hash(sha1, editor_key)
            + get_hash(sha1, reader_key)
        )
        return (
            key_for_file[10:22]
            + key_for_file[109:120]  # 12 characters
            + key_for_file[85:96]  # 11 characters
            + key_for_file[39:46]  # 11 characters
            + key_for_file[31:39]  # 7 characters
            + key_for_file[0:10]  # 8 characters
            + key_for_file[46:58]  # 10 characters
            + key_for_file[58:71]  # 12 characters
            + key_for_file[71:81]  # 13 characters
            + key_for_file[96:109]  # 10 characters
            + key_for_file[81:85]  # 13 characters
            + key_for_file[22:31]  # 4 characters
        )  # 9 characters
    except Exception as ex:
        print(f"An error occurred: {ex}")
    return key_for_file


def compute_hash_for_key(key):
    try:
        md5 = "md5"
        return get_hash(md5, key)
    except Exception as ex:
        print(f"An error occurred: {ex}")
    return None


# Example usage:
file_key = "9782090347463_extrait"
computed_key = compute_key_for_file(file_key)
print(computed_key)

# key = "your_key"
computed_hash = compute_hash_for_key(computed_key)
# print(computed_hash)


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os


def get_crypto_stream(input_stream, password):
    if input_stream is None:
        raise ValueError("input cannot be empty")
    if not password:
        raise ValueError("password cannot be empty")

    # Derive key and IV from the password
    iv = password[:16].encode("utf-8")  # Use the first 16 bytes of the password
    key = password.encode(
        "utf-8"
    )  # Use the full password as IV (not recommended for production)

    # Create AES cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = b""
    while True:
        chunk = input_stream.read(4096)  # Read in chunks
        if not chunk:
            break
        decrypted_data += decryptor.update(chunk)

    decrypted_data += decryptor.finalize()

    return decrypted_data


def decrypt(input_file_path, password, output_file_path):
    with open(input_file_path, "rb") as input_file:
        decrypted_data = get_crypto_stream(input_file, password)

    with open(output_file_path, "wb") as output_file:
        output_file.write(decrypted_data)


# Example usage:
print(computed_hash, "57f3660a880e12c178c4b2928500273a")

"""
decrypt(
    "test/OEBPS/fallback.xhtml",
    "57f3660a880e12c178c4b2928500273a",
    "fb.xhtml",
)
"""
