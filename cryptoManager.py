from simplecrypto import XOR_CRYPT
KEY='meetpy'

class CryptoManager:
    def __init__(self):
        self.crypto = XOR_CRYPT

    def encrypt(self, message):
        #message=
        dev = self.crypto.encrypt(message, KEY)
        return dev.encode("utf8")
         
    def decrypt(self, message):
        message = message.decode("utf8")
        return self.crypto.decrypt(message, KEY)
