#
# copyright @wanderingxs1:https://github.com/wanderingxs1
# commercial use is strictly prohibited
#


import sys
import subprocess


def except_handler():
    input("Press Enter to restart this program...")
    subprocess.Popen([sys.executable] + sys.argv)
    sys.exit()
