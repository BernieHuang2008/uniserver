import rsa

class EncryptionKey:
    def __init__(self, public_key, private_key=None):
        self.public_key = public_key
        self._private_key = private_key

    @classmethod
    def load_public_key(cls, public_key):
        return cls(rsa.PublicKey.load_pkcs1(public_key))

    def get_public_key(self):
        return self.public_key
    
    def encrypt(self, data):
        return rsa.encrypt(data, self.public_key)
    
    def decrypt(self, data):
        return rsa.decrypt(data, self._private_key)
    
    def sign(self, data):
        return rsa.sign(data, self._private_key, 'SHA-1')
    

def generate_key():
    keys = rsa.newkeys(512)
    return EncryptionKey(keys[0], keys[1])


if __name__ == '__main__':
    key = generate_key()
    print(key.get_public_key().save_pkcs1())