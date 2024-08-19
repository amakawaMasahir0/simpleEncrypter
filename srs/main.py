#
# copyright @wanderingxs1:https://github.com/wanderingxs1
# commercial use is strictly prohibited
#

import base64

from error_handler import *
from ui import *
from encrypt import generate_key
from encrypt import encrypt_name, encrypt_file, encrypt_folders, contains_directory
from decrypt import decrypt_name, decrypt_file, decrypt_folders, decrypt_err_handler
from sec_ques import store_security_info
from reclaim_pwd import reclaim_password

# decrypt try limit
DECRYPT_CHANCE = "10"
# string to judge whether pwd is valid.
# this is because AES may generate wrong result with wrong pwd, and won't raise exception
JUDGE = "valid"


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
                encrypt_judge = base64.b64decode(f.readline()[:-1].encode())
                judge_nonce = base64.b64decode(f.readline()[:-1].encode())
        except:
            print("ERROR: critical file for decrypt not found!")
            print("You can check the path.")
            except_handler()
        # 如果这个文件存在，那么一定可以解密出来剩余机会
        decrypt_remain_chance = int(decrypt_name(encrypt_remain_chance, info_key, remain_chance_nonce))
        # 现如果剩余0次机会
        if not decrypt_remain_chance:
            print("You have run out of chances for decrypting!")
            except_handler()
        # validate the password
        decrypt_judge = ""
        try:
            decrypt_judge = decrypt_name(encrypt_judge, name_key, judge_nonce)
        except ValueError:
            decrypt_err_handler(decrypt_remain_chance, folder_path, info_key)
        if not decrypt_judge == "valid":
            decrypt_err_handler(decrypt_remain_chance, folder_path, info_key)

    # 首先尝试重命名父文件，出现权限问题直接退出。
    if encrypt:
        # 检查父目录是否已经存在加密了的文件夹
        if contains_directory(folder_path, "encryptedFolder0") or ("encryptedFolder" in folder_path):
            print("There already exist a encrypted folder. ")
            except_handler()
        # 加密最外层文件夹名称,设定最多解密次数,和已经使用的解密次数
        encrypt_judge, cipher_judge = encrypt_name(JUDGE, name_key)
        nonce_judge = cipher_judge.nonce
        encrypted_remain_chance, cipher_remain = encrypt_name(DECRYPT_CHANCE, info_key)
        nonce_remain_chance = cipher_remain.nonce
        encrypted_root_name, cipher_root = encrypt_name(os.path.basename(folder_path), name_key)
        nonce_root = cipher_root.nonce
        root_father_path = folder_path[:-len(os.path.basename(folder_path))]
        # rename the encrypted father folder
        try:
            os.rename(folder_path, root_father_path + "encryptedFolder0")
        except PermissionError:
            print("Access Denied. Please run this program in administrator mode.")
            except_handler()
        except FileNotFoundError:
            print("Illegal path!")
            except_handler()
        except FileExistsError:
            print("The father path already exists encrypted folder, please select another one.")
            except_handler()
        except OSError:
            print("Unknown error, may check the path.")
            except_handler()
        # 此处写入文本文件，将二进制数据解码。解密的时候需要将得到的文本编码
        # 额外注意，nonce还需要进行解base64编码
        try:
            with open(root_father_path + "encryptedFolder0" + "\\encryptedFolder0.name", 'w') as f:
                f.write(base64.b64encode(nonce_root).decode() + "\n")
                f.write(base64.b64encode(encrypted_root_name).decode() + "\n")
                f.write(base64.b64encode(nonce_remain_chance).decode() + "\n")
                f.write(base64.b64encode(encrypted_remain_chance).decode() + "\n")
                f.write(base64.b64encode(encrypt_judge).decode() + "\n")
                f.write(base64.b64encode(nonce_judge).decode() + "\n")
        except:
            print("Illegal directory!")
            print("You can check the path.")
            except_handler()
        print(f"\n{folder_path} root directory encrypting...\n")
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
            except_handler()
        decrypted_root_name = "error_name"
        # if program run here, pwd must be correct
        decrypted_root_name = decrypt_name(encrypt_root_name, name_key, root_name_nonce)
        try:
            os.rename(folder_path, root_father_path + decrypted_root_name)
        except PermissionError:
            print("Access Denied. Please run this program in administrator mode.")
            except_handler()
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


if __name__ == "__main__":
    # renew ui interface, making it more user-friendly
    print_my_help_message()
    # get user choice
    work_type = "0"
    try:
        work_type = get_work_type()
    except ValueError as e:
        print(e)
        except_handler()
    # process work
    if work_type == "1" or work_type == "3":
        path = input("Enter full path to the folder you want to encrypt: ")
        pwd = input("Enter your password: ")
        process_folder(path, pwd, encrypt=True)
        if work_type == "3":
            store_security_info(path, pwd)
    else:
        if work_type == "2":
            path = input("Enter full path to the folder you want to decrypt: ")
            pwd = input("Enter your password: ")
            process_folder(path, pwd, encrypt=False)
        else:
            if work_type == "4":
                path = input("Enter full path to the folder you want to decrypt: ")
                reclaim_password(path)
            else:
                print("Incorrect instruction type or internal error!")
                except_handler()
    # work finished
    print("work successfully done. you can close this window.")
    input(" if you have another work to do, press Enter to process...")
    subprocess.Popen([sys.executable] + sys.argv)  # in idle this line is not working, only works in cmd

