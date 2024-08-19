#
# copyright @wanderingxs1:https://github.com/wanderingxs1
# commercial use is strictly prohibited
#

import base64
import os

from error_handler import *
from encrypt import generate_key
from encrypt import encrypt_name


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
        except_handler()
    print("Security question set successfully.\n"
          f"Your question is {security_ques}\n"
          f"Your answer is {security_answer}")
