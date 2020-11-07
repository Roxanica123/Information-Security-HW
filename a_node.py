import base64
import socket
import sys

from os import path
from pathlib import Path

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

from known_values import *

HOST_KM, PORT_KM = "localhost", 9999
HOST_B, PORT_B = "localhost", 9995


def check_response(response):
    if response != CODE_OK:
        print("Failed to communicate with node B")
        return False
    return True


def init_communication_sockets():
    key_manager_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    b_node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    key_manager_socket.connect((HOST_KM, PORT_KM))
    b_node_socket.connect((HOST_B, PORT_B))
    return key_manager_socket, b_node_socket


def read_desired_mode_of_operation():
    print("Hello!\nPlease specify the mode of operation you want. (ECB or CFB)")
    while True:
        mode_of_operation = bytes(input().upper(), "utf-8")
        if mode_of_operation != CODE_ECB and mode_of_operation != CODE_CFB:
            print("Invalid mode of operation! Try again :)")
        else:
            return mode_of_operation


def init_communication_with_b(mode_of_operation, node_socket):
    node_socket.sendall(mode_of_operation)
    response = node_socket.recv(1024)
    checked_response = check_response(response)
    if checked_response:
        print(">>Desired mode of operation sent to node B")
        return checked_response


def get_encrypted_key(key_manager_socket):
    print(">>Acquired encrypted key from Key Manager")
    return key_manager_socket.recv(16)


def send_encrypted_key(p_encrypted_key, node_b_socket):
    node_b_socket.sendall(p_encrypted_key)
    response = node_b_socket.recv(1024)
    checked_response = check_response(response)
    if checked_response:
        print(">>Encrypted key was successfully send to node B")
        return checked_response


def decrypt_key(p_encrypted_key):
    cipher = AES.new(K_PRIM, AES.MODE_ECB)
    print(">>Key was decrypted")
    return cipher.decrypt(p_encrypted_key)


def receive_start_signal(node_b_socket):
    response = node_b_socket.recv(1024)
    if response == CODE_START_COMM:
        print(">>Start communication signal was received from node B")
        return True
    print("Start communication signal was not received")
    return False


def read_message_to_encrypt():
    print("Insert the path to the file")
    file_path = input()
    if not path.exists(file_path):
        print("File does not exist")
        return None
    else:
        file = open(file_path, "rb")
        message_to_encrypt = file.read()
        return message_to_encrypt


def encrypt_128bits_block(cipher, block):
    return cipher.encrypt(block)


def get_blocks_array_from_message(p_message):
    number_of_blocks = len(p_message) // 16
    blocks = []
    for i in range(number_of_blocks):
        blocks.append(p_message[i * 16:i * 16 + 16])
    if len(p_message) % 16 != 0:
        blocks.append(pad(p_message[number_of_blocks * 16:], 16))
    return blocks


def xor_128bits_blocks(block1, block2):
    result = []
    for byte1, byte2 in zip(block1, block2):
        result.append(byte1 ^ byte2)
    return bytes(result)


def send_encrypted_message(p_key, p_message, node_b_socket, mode_of_operation):
    cipher = AES.new(p_key, AES.MODE_ECB)
    blocks = get_blocks_array_from_message(p_message)
    number_of_blocks = len(blocks)
    node_b_socket.sendall(encrypt_128bits_block(cipher, number_of_blocks.to_bytes(16, sys.byteorder)))
    print(">>Sent message length to node B")
    if mode_of_operation == CODE_ECB:
        for block in blocks:
            node_b_socket.sendall(encrypt_128bits_block(cipher, block))
    else:
        # mode_of_operation is CFB
        encrypted_blocks = [IV]  # C0=IV
        i = 1
        for block in blocks:
            ci = xor_128bits_blocks(encrypt_128bits_block(cipher, encrypted_blocks[i - 1]), block)
            encrypted_blocks.append(ci)
            i += 1
        for i in range(1, len(encrypted_blocks)):
            node_b_socket.sendall(encrypted_blocks[i])

    print(">>Message sent")


socket_km, socket_b = init_communication_sockets()
desired_mode_of_operation = read_desired_mode_of_operation()
init_communication_with_b(desired_mode_of_operation, socket_b)
encrypted_key = get_encrypted_key(socket_km)
send_encrypted_key(encrypted_key, socket_b)
key = decrypt_key(encrypted_key)
receive_start_signal(socket_b)

message = read_message_to_encrypt()
send_encrypted_message(key, message, socket_b, desired_mode_of_operation)
