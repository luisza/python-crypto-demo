from simplecrypto import AES_EAX
from io import BytesIO
from Crypto.Random import get_random_bytes

class CryptoManager:
    def __init__(self, pub, private):
        self.crypto = AES_EAX
        self.pub = pub
        self.private = private

    def encrypt(self, message):

        dev = self.crypto.encrypt(self.pub, message)
        return dev 
         
    def decrypt(self, message):
        key = open(self.private).read()
        return self.crypto.decrypt(key, message)
