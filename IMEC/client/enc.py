import rsa
import base64 as b64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class EncryptionKey:
    def __init__(self, public_key, private_key=None):
        self.public_key = public_key
        self._private_key = private_key

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

        # Generate a random AES key
        aes_key = get_random_bytes(16)
        
        # Create a new AES cipher using the key
        cipher = AES.new(aes_key, AES.MODE_EAX)
        
        # Encrypt the data using the AES cipher
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        # Encrypt the AES key using the RSA public key
        encrypted_key = rsa.encrypt(aes_key, self.public_key)
        
        # Return the encrypted AES key and the ciphertext
        return b64.b64encode(encrypted_key + cipher.nonce + tag + ciphertext)
    
    def decrypt(self, data) -> str:
        """
        Decrypt data with the private key, return the decrypted data.
        """
        # Decode the data
        decoded_data = b64.b64decode(data)
        
        # Extract the encrypted AES key, nonce, tag and ciphertext
        encrypted_key = decoded_data[:128]
        nonce = decoded_data[128:144]
        tag = decoded_data[144:160]
        ciphertext = decoded_data[160:]
        
        # Decrypt the AES key using the RSA private key
        aes_key = rsa.decrypt(encrypted_key, self._private_key)     # TODO: Decrypt failed
        
        # Create a new AES cipher using the decrypted AES key and the nonce
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        
        # Decrypt the ciphertext using the AES cipher and the tag
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext.encode('utf-8')

def generate_key():
    keys = rsa.newkeys(2048)
    return EncryptionKey(keys[0], keys[1])


def base64(data):
    return b64.b64encode(data)


def invbase64(data):
    return b64.b64decode(data)


if __name__ == '__main__':
    key = generate_key()
    print(key.get_public_key().save_pkcs1())