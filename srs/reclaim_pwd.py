#
# copyright https://github.com/amakawaMasahir0/simpleEncrypter
# commercial use is strictly prohibited
#

import base64

from error_handler import *
from encrypt import generate_key
from decrypt import decrypt_name


def reclaim_password(root_path):
    try:
        with open(root_path + f"\\encryptedFolder0.name", 'r') as f:
            for _ in range(6):
                f.readline()
            security_ques = f.readline()[:-1]
            pwd_nonce = base64.b64decode(f.readline()[:-1].encode())
            encrypt_pwd = base64.b64decode(f.readline()[:-1].encode())
    except:
        print("Internal Error! Security question is now unavailable! Or you haven't set security question.")
        print("You can check the path.")
        except_handler()

    # 应对没设密保问题，但企图找回密码
    if not security_ques:
        print("You have not set the security question!")
        except_handler()
    print(f"Security question is:{security_ques}")
    sec_answer = input("Answer: ")

    pwd_key = generate_key(sec_answer, salt=b'87a1')
    decrypt_pwd = ""
    try:
        decrypt_pwd = decrypt_name(encrypt_pwd, pwd_key, pwd_nonce)
    except ValueError:
        print("\nWrong answer.")
        except_handler()
    print(f"Correct answer. Your password is {decrypt_pwd}")