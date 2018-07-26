from simplecrypto import AES_EAX
from io import BytesIO
from Crypto.Random import get_random_bytes

KEY=b'4Q,\xbaY\x99+ia\x13&N\xa1\xec:\xf9v\xc5\xcccmF\xfdr\xd8O\xf9\x12`\ng\x90'

class CryptoManager:
    def __init__(self):
        self.crypto = AES_EAX

    def encrypt(self, message):
        file_out = BytesIO()
        dev = self.crypto.encrypt(message.encode("utf8"), KEY, file_out)
        file_out.seek(0)
        return file_out.read()  
         
    def decrypt(self, message):
        file_in = BytesIO(message) 
        return self.crypto.decrypt(file_in, KEY).decode("utf8")
