from Crypto import Random
import base64
import io

import hashlib


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

