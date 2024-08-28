#
# copyright https://github.com/amakawaMasahir0/simpleEncrypter
# commercial use is strictly prohibited
#

import base64
import os

from error_handler import *
from encrypt import encrypt_name

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# 设置密码盐(Salt)和AES加密参数
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100000
BLOCK_SIZE = AES.block_size
# 密码尝试次数上限
DECRYPT_CHANCE = "10"


def generate_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)


def decrypt_name(encrypted_name, name_key, name_nonce):
    try:
        cipher_name = AES.new(name_key, AES.MODE_GCM, nonce=name_nonce)
    except:
        print("Critical File for decrypt has damaged.")
        except_handler()
    name_encrypt = base64.b64decode(encrypted_name)
    return cipher_name.decrypt(name_encrypt).decode()


def decrypt_file(file_path, password, name_key):

    with open(file_path, 'rb') as f:
        salt = f.read(SALT_SIZE)
        nonce = f.read(BLOCK_SIZE)
        tag = f.read(BLOCK_SIZE)
        ciphertext = f.read()

    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # 解密文件名
    decrypted_filename = ""
    with open(file_path[:-4] + ".name", 'rb') as f:
        name_nonce = f.read(BLOCK_SIZE)
        encrypt_filename = f.read()
    try:
        decrypted_filename = decrypt_name(encrypt_filename, name_key, name_nonce)
    except ValueError:
        print("Incorrect password or corrupted file!")
        except_handler()

    # 解密文件数据
    file_data = b''
    try:
        file_data = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        # raise ValueError("Incorrect password or corrupted file")
        print("Incorrect password or corrupted file!")
        except_handler()

    # 写入解密后的数据
    decrypted_file_path = file_path[:-len(os.path.basename(file_path))] + str(decrypted_filename)
    with open(decrypted_file_path, 'wb') as f:
        f.write(file_data)

    # 删除加密文件
    os.remove(file_path)
    os.remove(file_path[:-4] + ".name")


def decrypt_folders(root_folder, name_key):
    folder_num = 1
    for root, dirs, files in os.walk(root_folder, topdown=False):
        for name in dirs:
            # 构建当前文件夹的完整路径
            current_dir = os.path.join(root, name)
            folder_father_path = current_dir[:-len(os.path.basename(current_dir))]
            with open(current_dir + f"\\{os.path.basename(current_dir)}.name", 'rb') as f:
                folder_name_nonce = f.read(BLOCK_SIZE)
                encrypt_folder_name = f.read()
            os.remove(current_dir + f"\\{os.path.basename(current_dir)}.name")
            decrypted_folder_name = decrypt_name(encrypt_folder_name, name_key, folder_name_nonce)
            print(f"{current_dir} directory decrypting...")
            try:
                os.rename(current_dir, folder_father_path + decrypted_folder_name)
            except PermissionError:
                print("Access Denied. Please run this program in administrator mode.")
                except_handler()
            folder_num = folder_num + 1

    print(f"{folder_num} folder(s) has been decrypted.")


def decrypt_err_handler(decrypt_remain_chance, root_path, info_key):
    decrypt_remain_chance = decrypt_remain_chance - 1
    with open(root_path + f"\\{os.path.basename(root_path)}.name", 'r') as f:
        root_name_nonce = f.readline()
        encrypt_root_name = f.readline()
        for _ in range(2):
            f.readline()
        judge_en = f.readline()
        judge_nonce = f.readline()
        sec_que = f.readline()
        pwd_nonce = f.readline()
        pwd_enc = f.readline()
    os.remove(root_path + f"\\{os.path.basename(root_path)}.name")
    encrypted_remain_chance, cipher_remain = encrypt_name(str(decrypt_remain_chance), info_key)
    nonce_remain_chance = cipher_remain.nonce
    with open(root_path + f"\\{os.path.basename(root_path)}.name", 'w') as f:
        f.write(root_name_nonce)
        f.write(encrypt_root_name)
        f.write(base64.b64encode(nonce_remain_chance).decode() + "\n")
        f.write(base64.b64encode(encrypted_remain_chance).decode() + "\n")
        f.write(judge_en)
        f.write(judge_nonce)
        f.write(sec_que)
        f.write(pwd_nonce)
        f.write(pwd_enc)
    print("Incorrect password or corrupted file!")
    print(f"You still have {decrypt_remain_chance} tries.")
    except_handler()
