import base64
import socketserver
import sys

from Cryptodome.Cipher import AES

from known_values import *


def read_desired_mode_of_operation(node_a_request):
    mode_of_operation = node_a_request.recv(1024).strip()
    if mode_of_operation != CODE_ECB and mode_of_operation != CODE_CFB:
        return False
    else:
        return mode_of_operation


def read_encrypted_key(node_a_request):
    key = node_a_request.recv(1024).strip()
    if len(key) != 16:
        return False
    return key


def send_data_validity_response(data, node_a_request):
    if not data:
        node_a_request.sendall(CODE_INVALID)
    else:
        node_a_request.sendall(CODE_OK)


def decrypt_key(p_encrypted_key):
    cipher = AES.new(K_PRIM, AES.MODE_ECB)
    return cipher.decrypt(p_encrypted_key)


def receive_encrypted_message(cipher, request):
    number_of_blocks = request.recv(16)
    number_of_blocks = int.from_bytes(cipher.decrypt(number_of_blocks), sys.byteorder)
    print(">>Waiting to receive " + str(number_of_blocks) + " blocks")
    blocks = []
    for i in range(number_of_blocks):
        blocks.append(request.recv(16))
    return blocks


def xor_128bits_blocks(block1, block2):
    result = []
    for byte1, byte2 in zip(block1, block2):
        result.append(byte1 ^ byte2)
    return bytes(result)


def decrypt_blocks(cipher, blocks, operation_mode):
    decrypted_blocks = []
    if operation_mode == CODE_ECB:
        for block in blocks:
            decrypted_blocks.append(cipher.decrypt(block).decode('utf-8'))
    else:
        blocks.insert(0, IV)
        for i in range(1, len(blocks)):
            mi = xor_128bits_blocks(cipher.encrypt(blocks[i - 1]), blocks[i])
            decrypted_blocks.append(mi.decode('utf-8'))
    return decrypted_blocks


class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        operation_mode = read_desired_mode_of_operation(self.request)
        print(operation_mode)
        send_data_validity_response(operation_mode, self.request)
        if not operation_mode:
            return

        encrypted_key = read_encrypted_key(self.request)
        send_data_validity_response(encrypted_key, self.request)
        if not encrypted_key:
            return
        print(">>Key received")
        key = decrypt_key(encrypted_key)
        print(">>Key decrypted")
        self.request.sendall(CODE_START_COMM)
        print(">>Start communication signal sent")
        cipher = AES.new(key, AES.MODE_ECB)
        blocks = receive_encrypted_message(cipher, self.request)
        print(">>Encrypted blocks received")
        decrypted_strings = decrypt_blocks(cipher, blocks, operation_mode)
        message = "".join(decrypted_strings)
        print(">>Decrypted message\n------------------------------\n")
        print(message)


if __name__ == "__main__":
    HOST, PORT = "localhost", 9995
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        server.serve_forever()
