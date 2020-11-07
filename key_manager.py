import socketserver
import Cryptodome.Random
from Cryptodome.Cipher import AES
from known_values import K_PRIM


def get_random_key():
    return Cryptodome.Random.get_random_bytes(16)


def get_encrypted_key():
    key = get_random_key()
    cipher = AES.new(K_PRIM, AES.MODE_ECB)
    encrypted_key = cipher.encrypt(key)
    return encrypted_key


class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(get_encrypted_key())


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        server.serve_forever()
