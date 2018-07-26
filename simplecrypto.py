from Crypto import Random
import base64
import io

import hashlib
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

BLOCK_SIZE=16
def get_digest(digest_name):
    if 'sha256' == digest_name:
        return hashlib.sha256()
    elif 'sha384' == digest_name:
        return hashlib.sha384()
    elif 'sha512' == digest_name:
        return hashlib.sha512()


def get_hash_sum(data, algorithm):
    if type(data) == str:
        data = data.encode()
    digest = get_digest(algorithm)
    digest.update(data)
    hashsum = digest.hexdigest()
    return hashsum


from itertools import cycle

def str_xor(s1, s2):
 return "".join([chr(ord(c1) ^ ord(c2)) for (c1,c2) in zip(s1,cycle(s2))])

class XOR_CRYPT:
    @staticmethod
    def encrypt(file_in, key):
        return str_xor(file_in, key)

    @staticmethod
    def decrypt(file_in, key):
        return str_xor(file_in, key)


from Crypto.Cipher import AES
from OpenSSL import crypto
class AES_EAX:
    @staticmethod
    def encrypt(public_key, message):
        if type(message) == str:
            message = message.encode('utf-8')

        file_out = io.BytesIO()
        cert = crypto.load_certificate(
            crypto.FILETYPE_PEM, open(public_key).read())

        recipient_key = RSA.importKey(crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey()))
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        file_out.write(cipher_rsa.encrypt(session_key))

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message)
        [file_out.write(x) for x in (cipher_aes.nonce, tag, ciphertext)]

        file_out.seek(0)

        return base64.b64encode(file_out.read())

    @staticmethod
    def decrypt(private_key, cipher_text):
        raw_cipher_data = base64.b64decode(cipher_text)
        file_in = io.BytesIO(raw_cipher_data)
        file_in.seek(0)
        private_key = RSA.import_key(private_key)
        enc_session_key, nonce, tag, ciphertext = \
            [file_in.read(x)
             for x in (private_key.size_in_bytes(), 16, 16, -1)]
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        decrypted = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return decrypted.decode()
    

        
