import os
import sys
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

AES_KEY_LENGTH = 32  # 256 bits
RSA_KEY_LENGTH = 2048  # 256 bytes


origin_file = "./README.md"
encrypted_file = "./encrypted.md"
decrypted_file = "./decrypted.md"
private_key_a = "./private_key_a.pem"
public_key_a = "./public_key_a.pem"
private_key_b = "./private_key_b.pem"
public_key_b = "./public_key_b.pem"


def generate_rsa_key_pair():
    rsa_key = RSA.generate(RSA_KEY_LENGTH)
    private_key = rsa_key.export_key()
    public_key = rsa_key.publickey().export_key()
    # RSA Key write to file
    with open('private_key.pem', 'wb') as f:
        f.write(private_key)
    with open('public_key.pem', 'wb') as f:
        f.write(public_key)
    return private_key, public_key


def generate_aes_key():
    return get_random_bytes(AES_KEY_LENGTH)


def encrypt_file(input_filename, output_filename, aes_key, rsa_public_key):
    try:
        with open(input_filename, 'rb') as file:
            plaintext = file.read()

        # Pad the plaintext to be a multiple of AES block size
        padded_plaintext = pad(plaintext, AES.block_size)

        # Generate AES cipher using the AES key
        aes_cipher = AES.new(aes_key, AES.MODE_EAX)

        # Encrypt the plaintext using AES
        ciphertext, tag = aes_cipher.encrypt_and_digest(padded_plaintext)

        # Encrypt the AES key using RSA public key
        rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)

        # Write encrypted AES key, nonce, tag, and ciphertext to the output file
        with open(output_filename, 'wb') as file_out:
            [file_out.write(x) for x in (encrypted_aes_key, aes_cipher.nonce, tag, ciphertext)]
        print(f"Encryption complete. Encrypted file saved as '{output_filename}'")

    except Exception as e:
        print(f"Error: {str(e)}")


def decrypt_file(input_filename, output_filename, rsa_private_key):
    try:
        encrypted_aes_key_size = rsa_private_key.size_in_bytes()
        # Read encrypted file contents
        with open(input_filename, 'rb') as file_in:
            # Extract AES cipher nonce, tag, and ciphertext from encrypted data
            encrypted_aes_key, nonce, tag, ciphertext = [file_in.read(x) for x in (encrypted_aes_key_size, 16, 16, -1)]

        # Decrypt the AES key with the private RSA key
        rsa_cipher = PKCS1_OAEP.new(rsa_private_key)
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)

        # Decrypt and verify the data with the AES session key
        aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        try:
            decrypted_data = aes_cipher.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            print(f"Error: Decryption failed. {e}")
            sys.exit(1)
        data = unpad(decrypted_data, AES.block_size)

        # Write the decrypted plaintext to the output file
        with open(output_filename, 'wb') as output_file:
            output_file.write(data)

        print(f"Decryption complete. Decrypted file saved as '{output_filename}'")

    except Exception as e:
        print(f"Error: {str(e)}")


def main():
    aes_key = generate_aes_key()
    rsa_public_key = RSA.import_key(open('public_key_a.pem').read())
    rsa_private_key = RSA.import_key(open('private_key_a.pem').read())
    encrypt_file(origin_file, encrypted_file, aes_key, rsa_public_key)
    decrypt_file(encrypted_file, decrypted_file, rsa_private_key)


if __name__ == "__main__":
    main()
