import base64
import os
import sys

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


def encrypt_name(name, name_key):
    cipher_name = AES.new(name_key, AES.MODE_GCM)
    encrypt_byte = cipher_name.encrypt(name.encode())
    encrypt_byte = base64.b64encode(encrypt_byte)
    return encrypt_byte, cipher_name


def decrypt_name(encrypted_name, name_key, name_nonce):
    cipher_name = AES.new(name_key, AES.MODE_GCM, nonce=name_nonce)
    name_encrypt = base64.b64decode(encrypted_name)
    return cipher_name.decrypt(name_encrypt).decode()


def generate_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)


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


def decrypt_file(file_path, password, name_key):

    with open(file_path, 'rb') as f:
        salt = f.read(SALT_SIZE)
        nonce = f.read(BLOCK_SIZE)
        tag = f.read(BLOCK_SIZE)
        ciphertext = f.read()

    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # 解密文件名
    with open(file_path[:-4] + ".name", 'rb') as f:
        name_nonce = f.read(BLOCK_SIZE)
        encrypt_filename = f.read()
    try:
        decrypted_filename = decrypt_name(encrypt_filename, name_key, name_nonce)
    except ValueError:
        print("Incorrect password or corrupted file!")
        sys.exit(1)

    # 解密文件数据
    try:
        file_data = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        # raise ValueError("Incorrect password or corrupted file")
        print("Incorrect password or corrupted file!")
        sys.exit(1)

    # 写入解密后的数据
    decrypted_file_path = file_path[:-len(os.path.basename(file_path))] + str(decrypted_filename)
    with open(decrypted_file_path, 'wb') as f:
        f.write(file_data)

    # 删除加密文件
    os.remove(file_path)
    os.remove(file_path[:-4] + ".name")


def decrypt_err_handler(decrypt_remain_chance, root_path, info_key):
    decrypt_remain_chance = decrypt_remain_chance - 1
    with open(root_path + f"\\{os.path.basename(root_path)}.name", 'r') as f:
        root_name_nonce = f.readline()
        encrypt_root_name = f.readline()
        for _ in range(2):
            f.readline()
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
        f.write(sec_que)
        f.write(pwd_nonce)
        f.write(pwd_enc)
    print("Incorrect password or corrupted file!")
    print(f"You still have {decrypt_remain_chance} tries.")
    sys.exit(1)

def process_folder(folder_path, password, encrypt=True):
    file_num = 0
    # 采用固定的password来加密剩余解密次数
    # 安全性不佳，容易逆向。如果程序联网，则可以使用来自服务器的加密短语
    info_key = generate_key("0x76b1", salt=b'tale')
    name_key = generate_key(password, salt=b'salt0x7b')

    # 解密时验证密码和剩余解密次数
    decrypt_remain_chance = 0
    if not encrypt:
        try:
            with open(folder_path + f"\\{os.path.basename(folder_path)}.name", 'r') as f:
                f.readline()
                f.readline()
                remain_chance_nonce = base64.b64decode(f.readline()[:-1].encode())
                encrypt_remain_chance = base64.b64decode(f.readline()[:-1].encode())
        except:
            print("ERROR: critical file for decrypt not found!")
            print("You can check the path.")
            sys.exit(1)
        # 如果这个文件存在，那么一定可以解密出来剩余机会
        decrypt_remain_chance = int(decrypt_name(encrypt_remain_chance, info_key, remain_chance_nonce))
        # 现如果剩余0次机会
        if not decrypt_remain_chance:
            print("You have run out of chances for decrypting!")
            sys.exit(1)

    # 首先尝试重命名父文件，出现权限问题直接退出。
    if encrypt:
        # 检查父目录是否已经存在加密了的文件夹
        if os.path.isdir(folder_path[:-len(os.path.basename(folder_path))] + "encryptedFolder0"):
            print("There already exist a encrypted folder. ")
            sys.exit(1)
        # 加密最外层文件夹名称,设定最多解密次数,和已经使用的解密次数
        encrypted_remain_chance, cipher_remain = encrypt_name(DECRYPT_CHANCE, info_key)
        nonce_remain_chance = cipher_remain.nonce
        encrypted_root_name, cipher_root = encrypt_name(os.path.basename(folder_path), name_key)
        nonce_root = cipher_root.nonce
        root_father_path = folder_path[:-len(os.path.basename(folder_path))]
        # 此处写入文本文件，将二进制数据解码。解密的时候需要将得到的文本编码
        # 额外注意，nonce还需要进行解base64编码
        try:
            with open(folder_path + "\\encryptedFolder0.name", 'w') as f:
                f.write(base64.b64encode(nonce_root).decode() + "\n")
                f.write(base64.b64encode(encrypted_root_name).decode() + "\n")
                f.write(base64.b64encode(nonce_remain_chance).decode() + "\n")
                f.write(base64.b64encode(encrypted_remain_chance).decode() + "\n")
        except:
            print("Illegal directory!")
            print("You can check the path.")
            sys.exit(1)
        print(f"\n{folder_path} root directory encrypting...\n")
        try:
            os.rename(folder_path, root_father_path + "encryptedFolder0")
        except PermissionError:
            print("Access Denied. Please run this program in administrator mode.")
            sys.exit(1)
        # 下面的参数，应该用重命名后的父文件夹名
        root_path_new = root_father_path + "encryptedFolder0"
    else:
        # 解密根文件夹名
        root_father_path = folder_path[:-len(os.path.basename(folder_path))]
        try:
            with open(folder_path + f"\\{os.path.basename(folder_path)}.name", 'r') as f:
                root_name_nonce = base64.b64decode(f.readline()[:-1].encode())
                encrypt_root_name = base64.b64decode(f.readline()[:-1].encode())
        except:
            print("Illegal directory!")
            print("You can check the path.")
            sys.exit(1)
        decrypted_root_name = "error_name"
        try:
            decrypted_root_name = decrypt_name(encrypt_root_name, name_key, root_name_nonce)
        except ValueError:
            decrypt_err_handler(decrypt_remain_chance, folder_path, info_key)
        try:
            os.rename(folder_path, root_father_path + decrypted_root_name)
        except PermissionError:
            print("Access Denied. Please run this program in administrator mode.")
            sys.exit(1)
        os.remove(root_father_path + f"{decrypted_root_name}\\{os.path.basename(folder_path)}.name")
        print(f"\n{folder_path} root directory decrypting...\n")
        # 下面的参数，应该用重命名后的父文件夹名
        root_path_new = root_father_path + decrypted_root_name

    for root, _, files in os.walk(root_path_new):
        # 加密文件内容和文件名称
        for file in files:
            file_path = os.path.join(root, file)
            if encrypt:
                # 跳过已经加密的文件
                if file_path.endswith('.enc') or file_path.endswith('.name'):
                    continue
                encrypt_file(file_path, password, name_key, file_num)
                print(f'Encrypting file: {file_path}')
                file_num = file_num + 1
            else:
                # 只处理加密过的文件
                if not file_path.endswith('.enc'):
                    continue
                decrypt_file(file_path, password, name_key)
                print(f'Decrypting file: {file_path}')
                file_num = file_num + 1

    if encrypt:
        print(f"{file_num} file(s) has been encrypted.\n")
        if not file_num:
            print("Unexpected occasion occurs.")
            print("Either there is no file, or you try to encrypt encrypted file(s).")
        # 加密子文件夹名称
        encrypt_folders(root_path_new, name_key)

    else:
        print(f"{file_num} file(s) has been decrypted.\n")
        if not file_num:
            print("Unexpected occasion occurs.")
            print("Either there is no file, or you try to decrypt unencrypted file(s).")
        # 解密子文件夹名称
        decrypt_folders(root_path_new, name_key)


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
                sys.exit(1)
            folder_num = folder_num + 1

    print(f"{folder_num} folder(s) has been decrypted.")


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
                sys.exit(1)
            folder_num = folder_num + 1

    print(f"{folder_num} folder(s) has been encrypted.")


def print_my_help_message():
    print("\nMY REMIND")
    print("BACKUP YOUR FILES BEFORE USING THIS SOFTWARE.")
    print("Encrypt: simpleEncrypter.exe path_to_folder --option encrypt --password yourpwd")
    print("Decrypt: simpleEncrypter.exe path_to_folder --option decrypt  --password yourpwd")
    print("SetSecurityQues:simpleEncrypter.exe path_to_folder --option setSecurityQues --password yourpwd, then follow instruction")
    print("reclaimPassword:simpleEncrypter.exe path_to_folder --option reclaimPassword, then follow instruction")
    print("\nNO SPACE, \\ OR /  IN PATH OR PASSWORD \n")


def store_security_info(root_path, password):
    security_ques = input("Enter security question(less than 30 character): ")
    security_answer = input("Enter answer of question(less than 30 character): ")

    pwd_key = generate_key(security_answer, salt=b'87a1')
    encrypted_pwd, cipher_pwd = encrypt_name(password, pwd_key)
    nonce_pwd = cipher_pwd.nonce

    root_father_path = root_path[:-len(os.path.basename(root_path))]
    try:
        with open(root_father_path + "encryptedFolder0\\encryptedFolder0.name", 'a') as f:
            f.write(security_ques + "\n")
            f.write(base64.b64encode(nonce_pwd).decode() + "\n")
            f.write(base64.b64encode(encrypted_pwd).decode() + "\n")
    except:
        print("Internal Error! Security question is now unavailable!")
        sys.exit(1)
    print("Security question set successfully.\n"
          f"Your question is {security_ques}\n"
          f"Your answer is {security_answer}")


def reclaim_password(root_path):
    try:
        with open(root_path + f"\\encryptedFolder0.name", 'r') as f:
            for _ in range(4):
                f.readline()
            security_ques = f.readline()[:-1]
            pwd_nonce = base64.b64decode(f.readline()[:-1].encode())
            encrypt_pwd = base64.b64decode(f.readline()[:-1].encode())
    except:
        print("Internal Error! Security question is now unavailable! Or you haven't set security question.")
        print("You can check the path.")
        sys.exit(1)

    # 应对没设密保问题，但企图找回密码
    if not security_ques:
        print("You have not set the security question!")
        sys.exit(1)

    print(f"Security question is:{security_ques}")
    sec_answer = input("Answer: ")

    pwd_key = generate_key(sec_answer, salt=b'87a1')
    try:
        decrypt_pwd = decrypt_name(encrypt_pwd, pwd_key, pwd_nonce)
    except ValueError:
        print("\nWrong answer.")
        sys.exit(1)
    print(f"Correct answer. Your password is {decrypt_pwd}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files in a folder \n")
    parser.add_argument("folder", help="Folder to process")
    parser.add_argument("--option", help="encrypt:Encrypt files and folders.\n"
                                       "decrypt: Decrypt files and folders.\n"
                                       "setSecurityQues: set a security question and answer while encrypting to reclaim your password.\n"
                                       "reclaimPassword:answer the security question to reclaim your password.")
    parser.add_argument("--password", help="Password for encryption/decryption")

    # check wrong input case
    if len(sys.argv) != 4 and len(sys.argv) != 6:
        # parser.print_help()
        print_my_help_message()
        sys.exit(1)
    args = parser.parse_args()

    # check options
    if args.option == "encrypt" or args.option == "setSecurityQues":
        if not args.password:
            print("Please enter password")
            print_my_help_message()
            sys.exit(1)
        process_folder(args.folder, args.password, encrypt=True)
        if args.option == "setSecurityQues":
            store_security_info(args.folder, args.password)
    else:
        if args.option == "decrypt":
            if not args.password:
                print("Please enter password")
                print_my_help_message()
                sys.exit(1)
            process_folder(args.folder, args.password, encrypt=False)
        else:
            if args.option == "reclaimPassword":
                reclaim_password(args.folder)
            else:
                print("Incorrect instruction format!")
                sys.exit(1)
