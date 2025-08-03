#!/bin/bash

# realm 节点转发脚本

# 全局配置文件路径
SERVICE_FILE="/etc/systemd/system/realm.service"
REALM_BIN="/usr/local/bin/realm"
CONFIG_FILE="/etc/realm/config.toml"



# 辅助输出函数
print_info() {
    echo -e "\033[36m[信息]\033[0m $1"
}
print_success() {
    echo -e "\033[32m[成功]\033[0m $1"
}
print_error() {
    echo -e "\033[31m[错误]\033[0m $1" >&2
}

print_warning() {
    echo -e "\033[33m[警告]\033[0m $1"
}

print_title() {
    echo -e "\033[34m=== $1 ===\033[0m"
}

# 菜单相关函数
function main_menu() {
    clear
    # 检查 realm 状态
    if command -v realm >/dev/null 2>&1; then
        if systemctl is-active --quiet realm; then
            REALM_STATUS="\033[32m运行中\033[0m"
        else
            REALM_STATUS="\033[33m已安装，未运行\033[0m"
        fi
    else
        REALM_STATUS="\033[31m未安装\033[0m"
    fi
    echo "==========================="
    echo "      REALM 转发管理        "
    echo "==========================="
    echo -e "1. 安装 realm（$REALM_STATUS）"
    echo "2. 卸载 realm"
    echo "3. 重启 realm"
    echo "4. 新增规则"
    echo "5. 删除规则"
    echo "6. 查看状态"
    echo "0. 退出"
    read -p "请选择操作: " choice
    case $choice in
        1) install_realm ;;
        2) uninstall_realm ;;
        3) restart_realm ;;
        4) add_realm_rules ;;
        5) delete_realm_rules ;;
        6) view_realm_status ;;
        0) exit 0 ;;
        *) echo "无效选择"; read -p "按回车继续..."; main_menu ;;
    esac
}


# 检查系统类型和架构
function check_sys() {
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif grep -qi "debian" /etc/issue; then
        release="debian"
    elif grep -qi "ubuntu" /etc/issue; then
        release="ubuntu"
    elif grep -qi "centos" /etc/issue; then
        release="centos"
    elif grep -qi "debian" /proc/version; then
        release="debian"
    elif grep -qi "ubuntu" /proc/version; then
        release="ubuntu"
    elif grep -qi "centos" /proc/version; then
        release="centos"
    else
        release="unknown"
    fi

    arch=$(uname -m)
    if [[ "$arch" == "x86_64" || "$arch" == "amd64" ]]; then
        bit="amd64"
    elif [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
        bit="arm64"
    else
        bit="amd64"
    fi
}

# 安装realm（自动适配架构）
install_realm() {
    # 自动识别架构
    local arch
    case "$(uname -m)" in
        x86_64) arch="x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) arch="aarch64-unknown-linux-gnu" ;;
        armv7l) arch="armv7-unknown-linux-gnueabihf" ;;
        *) echo "不支持的架构: $(uname -m)" ; return 1 ;;
    esac

    # 获取最新版版本号
    local version
    version=$(curl -fsSL "https://api.github.com/repos/zhboner/realm/releases/latest" | grep '"tag_name"' | head -n1 | cut -d '"' -f4)
    if [[ -z "$version" ]]; then
        echo "获取 Realm 最新版本失败"
        return 1
    fi

    # 拼接下载链接
    local url="https://github.com/zhboner/realm/releases/download/${version}/realm-${arch}.tar.gz"

    echo "开始下载安装 realm ${version} (${arch})"
    cd /tmp || return 1

    # 下载并解压
    curl -fsSL "$url" -o realm.tar.gz || { echo "下载失败"; return 1; }
    tar xzf realm.tar.gz || { echo "解压失败"; return 1; }

    # 查找解压出来的 realm 可执行文件（包内可能为 realm 或 realm.exe）
    if [[ -f realm ]]; then
        sudo mv realm /usr/local/bin/realm
        sudo chmod +x /usr/local/bin/realm
    elif [[ -f realm.exe ]]; then
        sudo mv realm.exe /usr/local/bin/realm
        sudo chmod +x /usr/local/bin/realm
    else
        echo "找不到 realm 可执行文件"
        return 1
    fi

    rm -f realm.tar.gz

    # 检查安装结果
    if command -v realm &>/dev/null; then
        echo "✅ realm 安装成功，版本：$(realm -v)"
    else
        echo "❌ realm 安装失败"
        return 1
    fi

    # 创建 realm 服务
    create_realm_service
    # 重启 realm 服务
    restart_realm
    read -p "按回车返回主菜单..."
    main_menu
}



# 卸载 realm
function uninstall_realm() {
    read -p "确定要卸载 realm 以及相关配置吗？(y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "已取消卸载。"
        read -p "按回车返回主菜单..."
        main_menu
        return 0
    fi
    print_info "正在卸载 realm..."

    # 停止并禁用 systemd 服务（如果存在）
    if systemctl list-unit-files | grep -q '^realm.service'; then
        systemctl stop realm.service
        systemctl disable realm.service
        rm -f /etc/systemd/system/realm.service
        systemctl daemon-reload
        print_success "已移除 systemd 服务"
    fi

    # 删除主程序
    if [ -f /usr/local/bin/realm ]; then
        rm -f /usr/local/bin/realm
        print_success "已删除 /usr/local/bin/realm"
    fi

    # 删除配置文件和目录
    if [ -d /etc/realm ]; then
        rm -rf /etc/realm
        print_success "已删除 /etc/realm 配置目录"
    fi

    # 删除日志文件（如果存在）
    if [ -f /var/log/realm.log ]; then
        rm -f /var/log/realm.log
        print_success "已删除 /var/log/realm.log 日志文件"
    fi

    # 验证卸载结果
    if ! command -v realm >/dev/null 2>&1 && [ ! -f /usr/local/bin/realm ]; then
        print_success "realm 及相关配置已全部卸载完成"
    else
        print_error "部分文件未能成功删除，请手动检查"
    fi
}


# 启动 realm
function start_realm() {
    print_info "正在启动 realm 服务..."
    sudo systemctl start realm
    if [ $? -eq 0 ]; then
        print_success "realm 服务已启动"
    else
        print_error "realm 服务启动失败，请检查服务状态"
    fi
}


# 停止 realm
function stop_realm() {
    print_info "正在停止 realm 服务..."
    sudo systemctl stop realm
    if [ $? -eq 0 ]; then
        print_success "realm 服务已停止"
    else
        print_error "realm 服务停止失败，请检查服务状态"
    fi
}

# 重启 realm
function restart_realm() {
    print_info "正在重启 realm 服务..."
    sudo systemctl restart realm
    if [ $? -eq 0 ]; then
        print_success "realm 服务已成功重启"
    else
        print_error "realm 服务重启失败，请检查服务状态"
    fi
    print_info "realm 服务状态："
    systemctl status realm --no-pager
    read -p "按回车返回主菜单..."
    main_menu
}

# 查看 realm 状态
function view_realm_status() {
    print_info "正在显示 realm 状态..."
    systemctl status realm --no-pager
    read -p "按回车返回主菜单..."
    main_menu
}


# 新增realm转发配置
function add_realm_rules() {
    # 新增一条 realm 转发配置
    select_port
    select_realm_protocol
    input_realm_target
    add_realm_rule_and_restart
    read -p "按回车返回主菜单..."
    main_menu
}

# 查看现有转发规则
function view_realm_rules() {
    CONFIG_FILE="/etc/realm/config.toml"
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "未找到 realm 配置文件"
        return 1
    fi

    local idx=0
    local listen="" remote="" protocol=""
    print_info "现有 realm 转发规则："

    awk '
    BEGIN { idx=0 }
    /^\[\[endpoints\]\]/ { if (listen && remote) {
        idx++; printf "%d: 监听: %s, 协议: %s, 目标: %s\n", idx, listen, (protocol?protocol:"TCP"), remote
    }
    listen=""; remote=""; protocol=""
    next }
    /^listen[ \t]*=/ { gsub(/"/,"",$3); listen=$3 }
    /^remote[ \t]*=/ { gsub(/"/,"",$3); remote=$3 }
    /^protocol[ \t]*=/ { gsub(/"/,"",$3); protocol=toupper($3) }
    END { if (listen && remote) {
        idx++; printf "%d: 监听: %s, 协议: %s, 目标: %s\n", idx, listen, (protocol?protocol:"TCP"), remote
    } }
    ' "$CONFIG_FILE"
}


# 删除realm转发规则
function delete_realm_rules() {
    CONFIG_FILE="/etc/realm/config.toml"
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "未找到 realm 配置文件"
        return 1
    fi

    # 展示现有规则
    view_realm_rules

    # 让用户输入要删除的监听端口
    read -p "请输入要删除的监听端口: " del_port
    if [[ ! "$del_port" =~ ^[0-9]+$ ]] || [ "$del_port" -lt 1 ] || [ "$del_port" -gt 65535 ]; then
        print_error "无效端口号"
        read -p "按回车返回主菜单..."
        main_menu
        return 1
    fi

    # 检查该端口是否存在
    if ! grep -Eq "listen\s*=\s*\".*:${del_port}\"" "$CONFIG_FILE"; then
        print_error "端口 $del_port 不存在于任何规则中"
        read -p "按回车返回主菜单..."
        main_menu
        return 1
    fi

    # 备份
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"

    # 用 awk 删除对应端口的 [[endpoints]] 块
    awk -v port="$del_port" '
    BEGIN {del=0}
    /^\[\[endpoints\]\]/ { if(del==1){del=0} block=1; block_lines=""; next_block=0; }
    block==1 {
        block_lines = block_lines $0 "\n"
        if($0 ~ /^listen[ \t]*=/ && $0 ~ ":" port "\"") { next_block=1 }
        if($0 ~ /^$/) { block=0; if(next_block!=1) printf "%s", block_lines; block_lines=""; next_block=0 }
        next
    }
    { print }
    ' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"

    print_success "已删除监听端口为 $del_port 的所有规则（原文件已备份为 ${CONFIG_FILE}.bak）"

    # 重启 realm 服务
    restart_realm
    read -p "按回车返回主菜单..."
    main_menu
}





# 检查是否为 root 用户
function check_root() {
    # 如果不是 root 用户，则提示并退出
    if [ "$(id -u)" != "0" ]; then
        print_error "请以 root 用户身份运行此脚本！"
        exit 1
    fi
}


# 选择端口
function select_port() {
    CONFIG_FILE="/etc/realm/config.toml"
    echo "==========================="
    echo "    选择 realm 监听端口"
    echo "==========================="
    echo "1) 随机端口（默认）"
    echo "2) 自定义端口"
    while true; do
        read -p "请选择端口设置方式 [1/2]: " mode
        if [[ -z "$mode" ]]; then
            mode="1"
        fi
        case $mode in
            1)
                # 随机分配端口
                local max_attempts=10
                local attempt=0
                while [ $attempt -lt $max_attempts ]; do
                    port=$((2000 + RANDOM % 58001))
                    # 检查 realm 配置文件是否已包含该端口
                    if [ -f "$CONFIG_FILE" ] && grep -Eq "listen\s*=\s*\".*:${port}\"" "$CONFIG_FILE"; then
                        ((attempt++))
                        continue
                    fi
                    # 检查系统端口占用
                    if ss -tuln | grep -q ":$port "; then
                        ((attempt++))
                        continue
                    fi
                    REALM_PORT=$port
                    echo "随机选择端口: $REALM_PORT"
                    break
                done
                if [ -z "$REALM_PORT" ]; then
                    print_error "无法找到可用的随机端口，请选择自定义端口"
                    continue
                fi
                ;;
            2)
                while true; do
                    read -p "请输入端口号 (1-65535): " port
                    if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
                        echo "无效端口号，请输入1-65535之间的数字"
                        continue
                    fi
                    # 检查 realm 配置文件是否已包含该端口
                    if [ -f "$CONFIG_FILE" ] && grep -Eq "listen\s*=\s*\".*:${port}\"" "$CONFIG_FILE"; then
                        echo "端口 $port 已被 realm 配置使用，请选择其他端口"
                        continue
                    fi
                    if ss -tuln | grep -q ":$port "; then
                        read -p "端口 $port 可能已被系统其他服务占用，是否继续? (y/n): " confirm
                        if [[ $confirm =~ ^[Yy]$ ]]; then
                            REALM_PORT=$port
                            break
                        else
                            continue
                        fi
                    else
                        REALM_PORT=$port
                        break
                    fi
                done
                ;;
            *)
                echo "无效选择，请输入 1 或 2"
                continue
                ;;
        esac
        break
    done
    echo "设置端口: $REALM_PORT"
}

# 创建realm systemd 服务文件
function create_realm_service() {
    print_info "正在创建 realm systemd 服务文件..."

    # 配置变量
    REALM_BIN="/usr/local/bin/realm"
    CONFIG_FILE="/etc/realm/config.toml"
    SERVICE_FILE="/etc/systemd/system/realm.service"

    # 创建默认配置文件（如不存在）
    if [ ! -f "$CONFIG_FILE" ]; then
        mkdir -p /etc/realm
        cat <<EOF > "$CONFIG_FILE"
[log]
level = "info"
output = "/var/log/realm.log"

[[endpoints]]
listen = "0.0.0.0:65532"
remote = "127.0.0.1:65532"
protocol = "tcp"
EOF
        print_success "已生成默认配置文件：$CONFIG_FILE"
    fi

    # 创建 systemd 服务文件
    cat <<EOF | sudo tee "$SERVICE_FILE" > /dev/null
[Unit]
Description=Realm Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=$REALM_BIN -c $CONFIG_FILE
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    print_success "realm 服务已创建"
    # 设置开机自启动
    enable_realm_autostart
    # 重启 realm 服务
    restart_realm
    read -p "按回车返回主菜单..."
    main_menu
}


# 选择协议
function select_realm_protocol() {
    echo "==========================="
    echo "      选择 realm 协议"
    echo "==========================="
    echo "1) tcp（默认）"
    echo "2) udp"
    while true; do
        read -p "请选择协议 [1/2]: " proto
        if [[ -z "$proto" ]]; then
            proto="1"
        fi
        case $proto in
            1)
                REALM_PROTOCOL="tcp"
                ;;
            2)
                REALM_PROTOCOL="udp"
                ;;
            *)
                echo "无效选择，请输入 1 或 2"
                continue
                ;;
        esac
        break
    done
    echo "已选择协议: $REALM_PROTOCOL"
}



function input_realm_target() {
    # 检查IPv4地址是否合法
    is_valid_ipv4() {
        local ip=$1
        if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            local IFS='.'
            local -a ip_parts=($ip)
            for part in "${ip_parts[@]}"; do
                if ((part < 0 || part > 255)); then
                    return 1
                fi
            done
            return 0
        fi
        return 1
    }

    # 检查IPv6地址是否合法
    is_valid_ipv6() {
        local ip=$1
        if [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]] || \
           [[ $ip =~ ^::([0-9a-fA-F]{0,4}:){0,6}[0-9a-fA-F]{0,4}$ ]] || \
           [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,6}:([0-9a-fA-F]{0,4}:){0,5}[0-9a-fA-F]{0,4}$ ]] || \
           [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,7}:$ ]] || \
           [[ $ip == "::" ]]; then
            return 0
        fi
        return 1
    }

    # 更严格的域名校验
    is_valid_domain() {
        local domain=$1
        [[ $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$ ]] && \
        [[ ! $domain =~ ^[0-9]+$ ]]
    }

    while true; do
        echo "请选择目标输入方式："
        echo "1) 目标IP或域名（默认）"
        echo "2) 节点URL（自动提取目标地址和端口）"
        read -p "请选择 [1/2]: " mode
        if [[ -z "$mode" ]]; then
            mode="1"
        fi

        case $mode in
            1)  node_url=""
                # 目标IP或域名
                while true; do
                    read -p "请输入目标IP或域名: " target
                    if [[ -z "$target" ]]; then
                        print_error "目标不能为空，请重新输入"
                        continue
                    fi

                    if is_valid_ipv4 "$target"; then
                        REALM_TARGET="$target"
                        break
                    elif is_valid_ipv6 "$target"; then
                        REALM_TARGET="[$target]"
                        break
                    elif is_valid_domain "$target"; then
                        REALM_TARGET="$target"
                        break
                    else
                        print_error "输入格式不正确，请输入合法的IPv4、IPv6或域名"
                    fi
                done
                # 端口输入
                while true; do
                    read -p "请输入目标端口 (1-65535): " port
                    if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
                        print_error "无效端口号，请输入1-65535之间的数字"
                        continue
                    fi
                    REALM_TARGET_PORT="$port"
                    break
                done
                break
                ;;
            2)
                # 输入节点URL
                read -p "请输入节点URL: " node_url
                # 提取 @ 后面的域名和端口
                if [[ "$node_url" =~ @([^:/\?]+):([0-9]+) ]]; then
                    REALM_TARGET="${BASH_REMATCH[1]}"
                    REALM_TARGET_PORT="${BASH_REMATCH[2]}"
                    echo "已自动提取目标地址: $REALM_TARGET, 目标端口: $REALM_TARGET_PORT"
                    break
                else
                    print_error "未能从URL中提取到目标地址和端口，请检查格式"
                fi
                ;;
            *)
                print_error "无效选择，请输入 1 或 2"
                ;;
        esac
    done
    print_success "已设置目标: $REALM_TARGET"
    print_success "已设置目标端口: $REALM_TARGET_PORT"
}



function add_realm_rule_and_restart() {
    CONFIG_FILE="/etc/realm/config.toml"

    # 构造 [[endpoints]] 配置片段
    local rule_tcp=""
    local rule_udp=""
    case "$REALM_PROTOCOL" in
        tcp)
            rule_tcp="\n[[endpoints]]\nlisten = \"0.0.0.0:$REALM_PORT\"\nremote = \"$REALM_TARGET:$REALM_TARGET_PORT\"\nprotocol = \"tcp\""
            ;;
        udp)
            rule_udp="\n[[endpoints]]\nlisten = \"0.0.0.0:$REALM_PORT\"\nremote = \"$REALM_TARGET:$REALM_TARGET_PORT\"\nprotocol = \"udp\""
            ;;
        ws)
            rule_tcp="\n[[endpoints]]\nlisten = \"0.0.0.0:$REALM_PORT\"\nremote = \"$REALM_TARGET:$REALM_TARGET_PORT\"\nprotocol = \"ws\""
            ;;
        wss)
            rule_tcp="\n[[endpoints]]\nlisten = \"0.0.0.0:$REALM_PORT\"\nremote = \"$REALM_TARGET:$REALM_TARGET_PORT\"\nprotocol = \"wss\""
            # 如有证书参数可进一步扩展
            ;;
        tcp+udp)
            rule_tcp="\n[[endpoints]]\nlisten = \"0.0.0.0:$REALM_PORT\"\nremote = \"$REALM_TARGET:$REALM_TARGET_PORT\"\nprotocol = \"tcp\""
            rule_udp="\n[[endpoints]]\nlisten = \"0.0.0.0:$REALM_PORT\"\nremote = \"$REALM_TARGET:$REALM_TARGET_PORT\"\nprotocol = \"udp\""
            ;;
        *)
            print_error "未知协议类型: $REALM_PROTOCOL"
            return 1
            ;;
    esac

    # 创建 realm 配置文件（如不存在）
    if [ ! -f "$CONFIG_FILE" ]; then
        mkdir -p /etc/realm
        cat <<EOF > "$CONFIG_FILE"
[log]
level = "info"
output = "/var/log/realm.log"
EOF
    fi

    # 追加规则到 config.toml
    if [[ "$REALM_PROTOCOL" == "tcp+udp" ]]; then
        printf "%b" "$rule_tcp" >> "$CONFIG_FILE"
        printf "%b" "$rule_udp" >> "$CONFIG_FILE"
        print_success "已添加 TCP 规则: $REALM_PORT -> $REALM_TARGET:$REALM_TARGET_PORT"
        print_success "已添加 UDP 规则: $REALM_PORT -> $REALM_TARGET:$REALM_TARGET_PORT"
    else
        printf "%b" "${rule_tcp:-$rule_udp}" >> "$CONFIG_FILE"
        print_success "已添加规则: $REALM_PORT -> $REALM_TARGET:$REALM_TARGET_PORT 协议: $REALM_PROTOCOL"
    fi

    # 获取本地公网IP
    LOCAL_IP=$(curl -4 -s ifconfig.me)
    if [[ -z "$LOCAL_IP" ]]; then
        LOCAL_IP=$(curl -4 -s api.ipify.org)
    fi
    if [[ -z "$LOCAL_IP" ]]; then
        LOCAL_IP=$(curl -6 -s ifconfig.me)
        if [[ -z "$LOCAL_IP" ]]; then
            LOCAL_IP=$(curl -6 -s api64.ipify.org)
        fi
    fi
    # IPv6 显示方括号
    if [[ "$LOCAL_IP" =~ : ]]; then
        LOCAL_IP="[$LOCAL_IP]"
    fi

    # 如果是节点URL模式，输出 realm 监听节点url
    if [[ "$node_url" =~ @([^:/\?]+):([0-9]+) ]]; then
        relay_url="${node_url/@${BASH_REMATCH[1]}:${BASH_REMATCH[2]}/@$LOCAL_IP:$REALM_PORT}"
        print_success "中转节点URL: $relay_url"
    fi

    # 重启 realm 服务
    restart_realm
}


# 设置 realm 开机自启动
function enable_realm_autostart() {
    # 检查 systemd 服务文件是否存在
    if [ ! -f /etc/systemd/system/realm.service ]; then
        print_error "未找到 /etc/systemd/system/realm.service，请先创建服务文件"
        return 1
    fi

    sudo systemctl enable realm
    if [ $? -eq 0 ]; then
        print_success "realm 服务已设置为开机自启动"
    else
        print_error "realm 服务开机自启动设置失败，请检查 systemd 状态"
    fi
}


# 启用 BBR
function enable_bbr() {
    print_info "正在检查是否已开启 BBR..."
    if lsmod | grep -q bbr && sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        print_success "BBR 已启用！"
        return 0
    else
        print_warning "未检测到 BBR，开始配置..."
    fi

    sudo tee -a /etc/sysctl.conf > /dev/null <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

    sudo sysctl -p

    if lsmod | grep -q bbr && sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        print_success "BBR 已成功启用！"
    else
        print_error "BBR 启用失败，请检查内核版本是否 >= 4.9"
    fi
}



# 启动主菜单

main_menu 