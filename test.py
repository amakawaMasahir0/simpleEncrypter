import os


def rename_folders(root_folder, old_name, new_name):
    """
    递归地重命名文件夹及其子文件夹。

    参数:
    root_folder (str): 根文件夹路径，程序将从这里开始递归重命名。
    old_name (str): 要被替换的文件夹名。
    new_name (str): 新的文件夹名。
    """
    for root, dirs, files in os.walk(root_folder, topdown=False):
        for name in dirs:
            # 构建当前文件夹的完整路径
            current_dir = os.path.join(root, name)
            # 检查文件夹名是否包含要被替换的旧名字
            if old_name in name:
                # 构建新的文件夹名
                new_dir = os.path.join(root, name.replace(old_name, new_name))
                # 重命名文件夹
                os.rename(current_dir, new_dir)
                print(f'Renamed: {current_dir} -> {new_dir}')

    print('Folder renaming completed.')


# 示例用法
if __name__ == "__main__":
    root_folder = 'D:\\test'  # 更改为你的根文件夹路径
    old_name = '111111'  # 要被替换的旧文件夹名
    new_name = 'folder'  # 新的文件夹名

    rename_folders(root_folder, old_name, new_name)
