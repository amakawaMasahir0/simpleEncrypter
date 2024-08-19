#
# copyright @wanderingxs1:https://github.com/wanderingxs1
# commercial use is strictly prohibited
#

import base64
import os

from error_handler import *

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# 设置密码盐(Salt)和AES加密参数
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100000
BLOCK_SIZE = AES.block_size
# 密码尝试次数上限
DECRYPT_CHANCE = "10"


def generate_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)


def encrypt_name(name, name_key):
    cipher_name = AES.new(name_key, AES.MODE_GCM)
    encrypt_byte = cipher_name.encrypt(name.encode())
    encrypt_byte = base64.b64encode(encrypt_byte)
    return encrypt_byte, cipher_name


def encrypt_file(file_path, password, name_key, file_num):
    # 生成随机盐
    salt = get_random_bytes(SALT_SIZE)
    key = generate_key(password, salt)

    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce

    # 读取文件数据
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # 加密文件名
    encrypted_filename, cipher_name = encrypt_name(os.path.basename(file_path), name_key)
    nonce_name = cipher_name.nonce
    # 加密文件内容
    ciphertext, tag = cipher.encrypt_and_digest(file_data)

    # 写入加密后的数据，包括盐和nonce
    file_name = os.path.basename(file_path)
    folder_path = file_path[:-len(file_name)]
    with open(folder_path + f"encryptedFile{file_num}.name", 'wb') as f:
        f.write(nonce_name)
        f.write(encrypted_filename)
    with open(r"{}".format(folder_path + f"encryptedFile{file_num}.enc"), 'wb') as f:
        [f.write(x) for x in (salt, nonce, tag, ciphertext)]

    # 删除原始文件
    os.remove(file_path)


def encrypt_folders(root_folder, name_key):
    folder_num = 1
    for root, dirs, files in os.walk(root_folder, topdown=False):
        for name in dirs:
            # 构建当前文件夹的完整路径
            current_dir = os.path.join(root, name)
            encrypted_folder_name, cipher_folder = encrypt_name(os.path.basename(current_dir), name_key)
            nonce_folder = cipher_folder.nonce
            folder_father_path = current_dir[:-len(os.path.basename(current_dir))]
            with open(current_dir + f"\\encryptedFolder{folder_num}.name", 'wb') as f:
                f.write(nonce_folder)
                f.write(encrypted_folder_name)
            print(f"{current_dir} directory encrypting...")
            try:
                os.rename(current_dir, folder_father_path + f"encryptedFolder{folder_num}")
            except PermissionError:
                print("Access Denied. Please run this program in administrator mode.")
                except_handler()
            folder_num = folder_num + 1

    print(f"{folder_num} folder(s) has been encrypted.")


def contains_directory(parent_path, directory_name):
    try:
        items = os.listdir(parent_path)
    except:
        print("Illegal path!")
        except_handler()
    for item in items:
        full_path = os.path.join(parent_path, item)
        if os.path.isdir(full_path) and item == directory_name:
            return True
    return False

