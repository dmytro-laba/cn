import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA


BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:
    # pycrypto helper
    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))


class UserAESCipher:
    # pycrypto helper
    def __init__(self, user_id, keys_dir):
        self.keys_dir = keys_dir
        self.user_id = user_id
        self.key_hash = self.get_key_hash()
        self.cipher = AESCipher(self.key_hash)

    def get_key_hash(self):
        f = open('%s/user_%s_key.pem' % (self.keys_dir, self.user_id), 'rb')
        key = RSA.importKey(f.read())
        key_hash = MD5.new(key.exportKey('PEM')).hexdigest()
        return key_hash

    def encrypt(self, raw):
        return self.cipher.encrypt(raw).decode()

    def decrypt(self, enc):
        bytes(enc, 'UTF-8')
        return self.cipher.decrypt(enc).decode()