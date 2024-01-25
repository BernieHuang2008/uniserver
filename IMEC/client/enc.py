import rsa
import base64 as b64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import rsa

class EncryptionKey:
    def __init__(self, public_key, private_key=None):
        self.public_key = public_key
        self._private_key = private_key
        self.chunk_size = (self.public_key.n.bit_length() + 7) // 8 - 11
        self.enc_chunk_size = self.public_key.n.bit_length() // 8

    @classmethod
    def load_public_key(cls, public_key):
        return cls(rsa.PublicKey.load_pkcs1(public_key))

    def get_public_key(self) -> rsa.PublicKey:
        """
        Get the public key of the encryption key.
        """
        return self.public_key
    
    def encrypt(self, data) -> bytes:
        """
        Encrypt data with the public key, return the encrypted data.
        """
        if type(data) is not bytes:
            data = data.encode('utf-8')

        encrypted_data = b''

        # Split the data into chunks and encrypt each chunk
        for i in range(0, len(data), self.chunk_size):
            chunk = data[i:i+self.chunk_size]
            encrypted_chunk = rsa.encrypt(chunk, self.public_key)
            encrypted_data += encrypted_chunk

        return encrypted_data
    
    def decrypt(self, data) -> str:
        """
        Decrypt data with the private key, return the decrypted data.
        """
        if type(data) is not bytes:
            data = data.encode('utf-8')

        decrypted_data = b''

        # Split the data into chunks and decrypt each chunk
        for i in range(0, len(data), self.enc_chunk_size):
            chunk = data[i:i+self.enc_chunk_size]
            decrypted_chunk = rsa.decrypt(chunk, self._private_key)
            decrypted_data += decrypted_chunk

        return decrypted_data.decode('utf-8')

def generate_key():
    keys = rsa.newkeys(512)
    return EncryptionKey(keys[0], keys[1])


def base64(data):
    return b64.b64encode(data)


def invbase64(data):
    return b64.b64decode(data)


if __name__ == '__main__':
    key = generate_key()
    print(key.get_public_key().save_pkcs1())