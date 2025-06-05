import ecdsa
import os

if not os.path.exists('cipher/ecc/keys'):
    os.makedirs('cipher/ecc/keys')

class ECCCipher:
    def __init__(self):
        pass

    def generate_keys(self):
        """Sinh và lưu khóa riêng, khóa công khai ECC vào file."""
        sk = ecdsa.SigningKey.generate()
        vk = sk.get_verifying_key()

        with open('cipher/ecc/keys/privateKey.pem', 'wb') as p:
            p.write(sk.to_pem())

        with open('cipher/ecc/keys/publicKey.pem', 'wb') as p:
            p.write(vk.to_pem())

    def load_keys(self):
        """Tải khóa riêng và khóa công khai từ file."""
        with open('cipher/ecc/keys/privateKey.pem', 'rb') as p:
            sk = ecdsa.SigningKey.from_pem(p.read())

        with open('cipher/ecc/keys/publicKey.pem', 'rb') as p:
            vk = ecdsa.VerifyingKey.from_pem(p.read())

        return sk, vk

    def sign(self, message, key):
        """Ký thông điệp bằng khóa riêng."""
        return key.sign(message.encode('utf-8'))

    def verify(self, message, signature, key):
        """Xác thực chữ ký bằng khóa công khai."""
        try:
            return key.verify(signature, message.encode('utf-8'))
        except ecdsa.BadSignatureError:
            return False
