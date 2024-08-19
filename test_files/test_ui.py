import sys
import subprocess
import traceback
import time


def main():
    # 你的主要代码逻辑
    raise Exception("这是一个测试异常")


if __name__ == "__main__":
    while True:
        try:
            main()
        except Exception as e:
            # 打印异常信息到命令行
            print("发生异常：")
            traceback.print_exc()

            # 等待用户按键以重新启动程序
            input("按 Enter 键重新启动程序...")

            # 重新启动程序
            subprocess.Popen([sys.executable] + sys.argv)

            # 退出当前实例
            sys.exit()
