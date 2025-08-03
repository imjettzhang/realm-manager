# realm-manager

一个用于管理 realm 转发的 Shell 脚本项目

## 一键安装

```bash
wget https://raw.githubusercontent.com/imjettzhang/realm-manager/main/setup.sh -O setup.sh && chmod +x setup.sh && sudo ./setup.sh

```

安装完成后，可直接使用 `gm` 命令启动 realm 管理脚本。


## 说明
- 需 root 权限运行
- 依赖 jq、curl、systemctl 等常用工具
- 配置文件路径：`/etc/realm/config.json`
- 管理脚本主程序：`realm_manager.sh`（项目目录下）
- 快捷命令软链接：`/usr/local/bin/realm`
- 项目目录（源码）：`~/realm-manager-main/`
- 安装脚本：`setup.sh`（项目目录下）