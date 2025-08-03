#!/bin/bash

set -e

# 项目下载地址
ZIP_URL="https://github.com/imjettzhang/realm-manager/archive/refs/heads/main.zip"
ZIP_FILE="main.zip"
PROJECT_DIR="realm-manager-main"
SCRIPT_NAME="realm_manager.sh"
LINK_PATH="/usr/local/bin/rmgr"

# 清理旧文件和软链接及压缩包
cleanup_old() {
    echo "[信息] 清理旧脚本、目录、快捷命令和压缩包..."
    rm -f "$SCRIPT_NAME"
    rm -rf "$PROJECT_DIR"
    sudo rm -f "$LINK_PATH"
    rm -f "$ZIP_FILE"
}

# 下载并解压项目并安装依赖
download_and_extract() {
    echo "[信息] 下载项目脚本..."

    # 检查并安装 jq 和 unzip
    for dep in jq unzip; do
        if ! command -v $dep >/dev/null 2>&1; then
            echo "[信息] 未检测到 $dep，正在尝试安装..."
            if command -v apt >/dev/null 2>&1; then
                sudo apt update && sudo apt install -y $dep
            elif command -v yum >/dev/null 2>&1; then
                sudo yum install -y $dep
            else
                echo "[错误] 不支持的包管理器，请手动安装 $dep 后重试"
                exit 1
            fi
        fi
    done

    wget -O "$ZIP_FILE" "$ZIP_URL"
    echo "[信息] 解压项目..."
    unzip -o "$ZIP_FILE"
    rm -f "$ZIP_FILE"
}


# 创建软链接
create_symlink() {
    echo "[信息] 创建快捷命令..."
    sudo ln -sf "$(pwd)/$PROJECT_DIR/$SCRIPT_NAME" "$LINK_PATH"
    sudo chmod +x "$PROJECT_DIR/$SCRIPT_NAME"
    sudo chmod +x "$LINK_PATH"
}

# 主流程
main() {
    cleanup_old
    download_and_extract
    create_symlink

    while true; do
        read -p "[信息] 请输入 rmgr 或直接回车启动管理菜单: " user_input
        if [[ -z "$user_input" || "$user_input" == "rmgr" ]]; then
            rmgr
            break
        else
            echo "[错误] 无效输入，请输入 rmgr 或直接回车。"
        fi
    done
}

main 