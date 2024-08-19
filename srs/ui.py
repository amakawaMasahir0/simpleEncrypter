#
# copyright @wanderingxs1:https://github.com/wanderingxs1
# commercial use is strictly prohibited
#

import os


def print_centered(text):
    try:
        term_width = os.get_terminal_size().columns
    except OSError:
        # to run this program in idle
        term_width = 80
    text_length = len(text)
    left_padding = (term_width - text_length) // 2
    print(' ' * left_padding + text)


def print_my_help_message():
    print_centered("WELCOME USING SIMPLE ENCODER")
    print_centered("BACKUP YOUR FILES BEFORE USING THIS SOFTWARE")
    print("Encrypt:1\tDecrypt:2\tSetSecurityQues:3\treclaimPassword:4")


def get_work_type():
    valid_works = {'1', '2', '3', '4'}
    user_input = input("Enter your choice: ")
    if user_input not in valid_works:
        raise ValueError(f"Invalid Input: {user_input}. Please type 1, 2, 3 or 4.")
    return user_input

