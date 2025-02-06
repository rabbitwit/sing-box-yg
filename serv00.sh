#!/bin/bash

# 定义颜色常量
re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"

# 定义颜色输出函数
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }

# 定义读取输入函数
reading() { read -p "$(red "$1")" "$2"; }

# 获取当前用户名并转换为小写
USERNAME=$(whoami | tr '[:upper:]' '[:lower:]')

# 获取主机名
HOSTNAME=$(hostname)

# 获取主机名的第一个部分
snb=$(hostname | awk -F '.' '{print $1}')

# 添加虚拟主机
devil www add ${USERNAME}.serv00.net php > /dev/null 2>&1

# 设置文件路径
FILE_PATH="${HOME}/domains/${USERNAME}.serv00.net/public_html"
WORKDIR="${HOME}/domains/${USERNAME}.serv00.net/logs"

# 确保工作目录存在并设置权限
[ -d "$WORKDIR" ] || (mkdir -p "$WORKDIR" && chmod 777 "$WORKDIR")

# 读取或选择IP地址
read_ip() {
    local ip_file="ip.txt"

    # 检查文件是否存在
    if [[ ! -f "$ip_file" ]]; then
        red "错误: 文件 $ip_file 不存在"
        return 1
    fi

    # 显示可用IP地址列表
    cat "$ip_file"

    # 提示用户输入IP地址，建议回车默认自动选择可用IP
    reading "请输入上面三个IP中的任意一个 (建议默认回车自动选择可用IP): " IP

    # 如果用户输入为空，则自动选择可用IP
    if [[ -z "$IP" ]]; then
        # 尝试从ip.txt中选择第一个标记为“可用”的IP
        IP=$(grep -m 1 "可用" "$ip_file" | awk -F ':' '{print $1}')

        # 如果没有找到可用的IP，则调用okip函数获取IP
        if [[ -z "$IP" ]]; then
            IP=$(okip)
        fi

        # 验证okip函数返回的IP是否有效
        if [[ -z "$IP" ]]; then
            # 如果okip函数也没有获取到IP，则选择ip.txt中的第一个IP
            IP=$(head -n 1 "$ip_file" | awk -F ':' '{print $1}')

            # 再次验证IP是否有效
            if [[ -z "$IP" ]]; then
                red "错误: 文件 $ip_file 中没有有效的IP地址"
                return 1
            fi
        fi
    fi

    # 输出选定的IP地址
    green "你选择的IP为: $IP"
}


# 读取或生成UUID
read_uuid() {
    # 提示用户输入UUID密码，建议回车默认随机生成
    reading "请输入统一的uuid密码 (建议回车默认随机): " UUID

    # 如果用户输入为空，则生成随机UUID
    if [[ -z "$UUID" ]]; then
        UUID=$(uuidgen -r)
    fi

    # 输出选定的UUID
    green "你的uuid为: $UUID"
}

# 读取reality域名
read_reym() {
    # 提示用户选择reality域名的方式
    yellow "方式一：回车使用CF域名，支持proxyip+非标端口反代ip功能 (推荐)"
    yellow "方式二：输入 s 表示使用Serv00自带域名，不支持proxyip功能 (推荐)"
    yellow "方式三：支持其他域名，注意要符合reality域名规则"

    # 获取用户输入
    reading "请输入reality域名 【请选择 回车 或者 s 或者 输入域名】: " reym

    # 处理用户输入
    if [[ -z "$reym" ]]; then
        # 如果用户输入为空，使用默认CF域名
        reym=www.speedtest.net
    elif [[ "$reym" == "s" || "$reym" == "S" ]]; then
        # 如果用户输入s，使用Serv00自带域名
        reym=$USERNAME.serv00.net
    fi

    # 输出选定的reality域名
    green "你的reality域名为: $reym"
}

# 检查和调整端口配置
check_port() {
    # 获取当前端口列表
    port_list=$(devil port list)
    tcp_ports=$(echo "$port_list" | grep -c "tcp")
    udp_ports=$(echo "$port_list" | grep -c "udp")

    # 检查端口数量是否符合要求
    if [[ $tcp_ports -ne 2 || $udp_ports -ne 1 ]]; then
        red "端口数量不符合要求，正在调整..."

        # 删除多余的TCP端口
        if [[ $tcp_ports -gt 2 ]]; then
            tcp_to_delete=$((tcp_ports - 2))
            echo "$port_list" | awk '/tcp/ {print $1, $2}' | head -n $tcp_to_delete | while read port type; do
                devil port del $type $port
                green "已删除TCP端口: $port"
            done
        fi

        # 删除多余的UDP端口
        if [[ $udp_ports -gt 1 ]]; then
            udp_to_delete=$((udp_ports - 1))
            echo "$port_list" | awk '/udp/ {print $1, $2}' | head -n $udp_to_delete | while read port type; do
                devil port del $type $port
                green "已删除UDP端口: $port"
            done
        fi

        # 添加缺少的TCP端口
        if [[ $tcp_ports -lt 2 ]]; then
            tcp_ports_to_add=$((2 - tcp_ports))
            tcp_ports_added=0
            while [[ $tcp_ports_added -lt $tcp_ports_to_add ]]; do
                tcp_port=$(shuf -i 10000-65535 -n 1)
                result=$(devil port add tcp $tcp_port 2>&1)
                if [[ $result == *"succesfully"* ]]; then
                    green "已添加TCP端口: $tcp_port"
                    if [[ $tcp_ports_added -eq 0 ]]; then
                        tcp_port1=$tcp_port
                    else
                        tcp_port2=$tcp_port
                    fi
                    tcp_ports_added=$((tcp_ports_added + 1))
                else
                    yellow "端口 $tcp_port 不可用，尝试其他端口..."
                fi
            done
        fi

        # 添加缺少的UDP端口
        if [[ $udp_ports -lt 1 ]]; then
            while true; do
                udp_port=$(shuf -i 10000-65535 -n 1)
                result=$(devil port add udp $udp_port 2>&1)
                if [[ $result == *"succesfully"* ]]; then
                    green "已添加UDP端口: $udp_port"
                    break
                else
                    yellow "端口 $udp_port 不可用，尝试其他端口..."
                fi
            done
        fi

        # 提示端口已调整完成并断开SSH连接
        green "端口已调整完成,将断开ssh连接,请重新连接ssh重新执行脚本"
        devil binexec on >/dev/null 2>&1
        kill -9 $(ps -o ppid= -p $$) >/dev/null 2>&1
    else
        # 获取当前的TCP和UDP端口
        tcp_ports=$(echo "$port_list" | awk '/tcp/ {print $1}')
        tcp_port1=$(echo "$tcp_ports" | sed -n '1p')
        tcp_port2=$(echo "$tcp_ports" | sed -n '2p')
        udp_port=$(echo "$port_list" | awk '/udp/ {print $1}')

        # 输出当前端口信息
        purple "当前TCP端口: $tcp_port1 和 $tcp_port2"
        purple "当前UDP端口: $udp_port"
    fi

    # 导出端口变量
    export vless_port=$tcp_port1
    export vmess_port=$tcp_port2
    export hy2_port=$udp_port

    # 输出端口信息
    green "你的vless-reality端口: $vless_port"
    green "你的vmess-ws端口(设置Argo固定域名端口): $vmess_port"
    green "你的hysteria2端口: $hy2_port"
    sleep 2
}

# 安装sing-box
install_singbox() {
    # 检查是否已安装sing-box
    if [[ -e $WORKDIR/list.txt ]]; then
        yellow "已安装sing-box，请先选择2卸载，再执行安装" && exit
    fi

    # 提示用户为确保节点可用性，建议在Serv00网页不设置端口
    yellow "为确保节点可用性，建议在Serv00网页不设置端口，脚本会随机生成有效端口"
    sleep 2

    # 切换到工作目录
    cd $WORKDIR

    # 读取IP地址
    echo
    read_ip
    echo

    # 读取reym域名
    read_reym
    echo

    # 生成UUID
    read_uuid
    echo

    # 检查端口
    check_port
    echo

    # 等待2秒
    sleep 2

    # 配置Argo隧道
    argo_configure
    echo

    # 下载并运行sing-box
    download_and_run_singbox
    cd

    # 安装网页进程保活
    servkeep
    cd $WORKDIR

    # 获取节点链接
    echo
    get_links
    cd
}

# 卸载sing-box及相关内容
uninstall_singbox() {
    # 提示用户确认是否继续卸载
    reading "\n确定要卸载吗？【y/n】: " choice

    case "$choice" in
        [Yy])
            # 终止当前用户的所有进程（排除sshd、bash和grep）
            bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1

            # 删除相关文件和目录
            rm -rf domains serv00.sh serv00keep.sh

            # 清屏
            clear

            # 输出卸载完成信息
            green "已完全卸载"
            ;;
        [Nn])
            # 如果用户选择不卸载，退出脚本
            exit 0
            ;;
        *)
            # 如果用户输入无效，提示错误并返回主菜单
            red "无效的选择，请输入y或n" && menu
            ;;
    esac
}

# 清理所有进程并清空所有安装内容
kill_all_tasks() {
    # 提示用户确认是否继续清理
    reading "\n清理所有进程并清空所有安装内容，将退出ssh连接，确定继续清理吗？【y/n】: " choice

    case "$choice" in
        [Yy])
            # 终止当前用户的所有进程（排除sshd、bash和grep）
            bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1

            # 删除相关文件和目录
            rm -rf domains serv00.sh serv00keep.sh

            # 重置文件权限
            find ~ -type f -exec chmod 644 {} \; 2>/dev/null
            find ~ -type d -exec chmod 755 {} \; 2>/dev/null

            # 删除所有文件和空目录
            find ~ -type f -exec rm -f {} \; 2>/dev/null
            find ~ -type d -empty -exec rmdir {} \; 2>/dev/null

            # 强制终止当前用户的全部进程
            killall -9 -u $(whoami)
            ;;
        *)
            # 如果用户选择不清理，返回主菜单
            menu
            ;;
    esac
}

# 生成Argo配置
argo_configure() {
    while true; do
        # 提示用户选择Argo隧道方式
        yellow "方式一：Argo临时隧道 (无需域名，推荐)"
        yellow "方式二：Argo固定隧道 (需要域名，需要CF设置提取Token)"
        echo -e "${red}注意：${purple}Argo固定隧道使用Token时，需要在cloudflare后台设置隧道端口，该端口必须与vmess-ws的tcp端口 $vmess_port 一致)${re}"

        # 获取用户选择
        reading "输入 g 表示使用Argo固定隧道，回车跳过表示使用Argo临时隧道 【请选择 g 或者 回车】: " argo_choice

        # 检查用户输入的有效性
        if [[ "$argo_choice" != "g" && "$argo_choice" != "G" && -n "$argo_choice" ]]; then
            red "无效的选择，请输入 g 或回车"
            continue
        fi

        # 处理用户选择
        if [[ "$argo_choice" == "g" || "$argo_choice" == "G" ]]; then
            # 获取Argo固定隧道域名
            reading "请输入argo固定隧道域名: " ARGO_DOMAIN
            green "你的argo固定隧道域名为: $ARGO_DOMAIN"

            # 获取Argo固定隧道密钥
            reading "请输入argo固定隧道密钥（当你粘贴Token时，必须以ey开头）: " ARGO_AUTH
            green "你的argo固定隧道密钥为: $ARGO_AUTH"
        else
            green "使用Argo临时隧道"
        fi

        # 退出循环
        break
    done

    # 如果ARGO_AUTH包含TunnelSecret，则生成tunnel.json和tunnel.yml文件
    if [[ $ARGO_AUTH =~ TunnelSecret ]]; then
        echo "$ARGO_AUTH" > tunnel.json
        cat > tunnel.yml << EOF
tunnel: $(cut -d\" -f12 <<< "$ARGO_AUTH")
credentials-file: tunnel.json
protocol: http2

ingress:
  - hostname: $ARGO_DOMAIN
    service: http://localhost:$vmess_port
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
    fi
}

# 下载并运行sing-box及相关工具
download_and_run_singbox() {
     script
    # 获取系统架构并设置下载目录和文件信息数组
    ARCH=$(uname -m)
    DOWNLOAD_DIR="."
    mkdir -p "$DOWNLOAD_DIR"
    FILE_INFO=()

    # 根据系统架构设置文件信息数组
    if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
        FILE_INFO=("https://github.com/eooce/test/releases/download/arm64/sb web" "https://github.com/eooce/test/releases/download/arm64/bot13 bot")
    elif [ "$ARCH" == "amd64" ] || [ "$ARCH" == "x86_64" ] || [ "$ARCH" == "x86" ]; then
        FILE_INFO=("https://github.com/yonggekkk/Cloudflare_vless_trojan/releases/download/serv00/sb web" "https://github.com/yonggekkk/Cloudflare_vless_trojan/releases/download/serv00/server bot")
    else
        echo "Unsupported architecture: $ARCH"
        exit 1
    fi

    # 声明文件映射关联数组
    declare -A FILE_MAP

    # 生成随机文件名的函数
    generate_random_name() {
        local chars=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
        local name=""
        for i in {1..6}; do
            name="$name${chars:RANDOM%${#chars}:1}"
        done
        echo "$name"
    }

    # 下载文件并提供备用下载方案（curl失败时使用wget）
    download_with_fallback() {
        local URL=$1
        local NEW_FILENAME=$2

        # 使用curl开始下载文件，并在后台运行
        curl -L -sS --max-time 2 -o "$NEW_FILENAME" "$URL" &
        CURL_PID=$!  # 获取curl进程ID
        CURL_START_SIZE=$(stat -c%s "$NEW_FILENAME" 2>/dev/null || echo 0)  # 获取下载开始时的文件大小

        sleep 1  # 等待1秒以检查下载进度
        CURL_CURRENT_SIZE=$(stat -c%s "$NEW_FILENAME" 2>/dev/null || echo 0)  # 获取当前文件大小

        # 如果文件大小没有增加，说明下载可能失败，终止curl并使用wget重新下载
        if [ "$CURL_CURRENT_SIZE" -le "$CURL_START_SIZE" ]; then
            kill $CURL_PID 2>/dev/null  # 终止curl进程
            wait $CURL_PID 2>/dev/null  # 等待curl进程结束
            wget -q -O "$NEW_FILENAME" "$URL"  # 使用wget下载文件
            echo -e "\e[1;32mDownloading $NEW_FILENAME by wget\e[0m"  # 输出使用wget下载的信息
        else
            wait $CURL_PID  # 等待curl进程完成
            echo -e "\e[1;32mDownloading $NEW_FILENAME by curl\e[0m"  # 输出使用curl下载的信息
        fi
    }

    # 遍历文件信息数组，下载并处理每个文件
    for entry in "${FILE_INFO[@]}"; do
        # 解析URL和文件标识符
        URL=$(echo "$entry" | cut -d ' ' -f 1)
        RANDOM_NAME=$(generate_random_name)  # 生成随机文件名
        NEW_FILENAME="$DOWNLOAD_DIR/$RANDOM_NAME"

        # 检查文件是否已存在
        if [ -e "$NEW_FILENAME" ]; then
            echo -e "\e[1;32m$NEW_FILENAME already exists, Skipping download\e[0m"
        else
            # 使用download_with_fallback函数下载文件，并提供备用方案
            download_with_fallback "$URL" "$NEW_FILENAME"
        fi

        # 设置文件为可执行
        chmod +x "$NEW_FILENAME"

        # 将文件标识符映射到新文件名
        FILE_MAP[$(echo "$entry" | cut -d ' ' -f 2)]="$NEW_FILENAME"
    done

    # 等待所有后台任务完成
    wait

    # 生成reality密钥对并提取私钥和公钥
    output=$("./$(basename ${FILE_MAP[web]})" generate reality-keypair)
    private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
    public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')

    # 将私钥和公钥保存到文件
    echo "${private_key}" > private_key.txt
    echo "${public_key}" > public_key.txt

    # 生成EC参数和自签名证书
    openssl ecparam -genkey -name prime256v1 -out "private.key"
    openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=$USERNAME.serv00.net"

    # 获取主机名缩写
    nb=$(hostname | cut -d '.' -f 1 | tr -d 's')

    # 根据主机名设置特定变量
    if [ "$nb" == "14" ] || [ "$nb" == "15" ]; then
        ytb='"jnn-pa.googleapis.com",'
    fi

    # 从hy2ip.txt文件中提取前三个IP地址
    hy1p=$(sed -n '1p' hy2ip.txt)
    hy2p=$(sed -n '2p' hy2ip.txt)
    hy3p=$(sed -n '3p' hy2ip.txt)

    # 生成配置文件config.json
    cat > config.json << EOF
    {
      "log": {
        "disabled": true,
        "level": "info",
        "timestamp": true
      },
      "inbounds": [
        {
          "tag": "hysteria-in",
          "type": "hysteria2",
          "listen": "$hy1p",
          "listen_port": $hy2_port,
          "users": [
            {
              "password": "$UUID"
            }
          ],
          "masquerade": "https://www.bing.com",
          "ignore_client_bandwidth": false,
          "tls": {
            "enabled": true,
            "alpn": [
              "h3"
            ],
            "certificate_path": "cert.pem",
            "key_path": "private.key"
          }
        },
        {
          "tag": "hysteria-in",
          "type": "hysteria2",
          "listen": "$hy2p",
          "listen_port": $hy2_port,
          "users": [
            {
              "password": "$UUID"
            }
          ],
          "masquerade": "https://www.bing.com",
          "ignore_client_bandwidth": false,
          "tls": {
            "enabled": true,
            "alpn": [
              "h3"
            ],
            "certificate_path": "cert.pem",
            "key_path": "private.key"
          }
        },
        {
          "tag": "hysteria-in",
          "type": "hysteria2",
          "listen": "$hy3p",
          "listen_port": $hy2_port,
          "users": [
            {
              "password": "$UUID"
            }
          ],
          "masquerade": "https://www.bing.com",
          "ignore_client_bandwidth": false,
          "tls": {
            "enabled": true,
            "alpn": [
              "h3"
            ],
            "certificate_path": "cert.pem",
            "key_path": "private.key"
          }
        },
        {
          "tag": "vless-reality-vesion",
          "type": "vless",
          "listen": "::",
          "listen_port": $vless_port,
          "users": [
            {
              "uuid": "$UUID",
              "flow": "xtls-rprx-vision"
            }
          ],
          "tls": {
            "enabled": true,
            "server_name": "$reym",
            "reality": {
              "enabled": true,
              "handshake": {
                "server": "$reym",
                "server_port": 443
              },
              "private_key": "$private_key",
              "short_id": [
                ""
              ]
            }
          }
        },
        {
          "tag": "vmess-ws-in",
          "type": "vmess",
          "listen": "::",
          "listen_port": $vmess_port,
          "users": [
            {
              "uuid": "$UUID"
            }
          ],
          "transport": {
            "type": "ws",
            "path": "$UUID-vm",
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        }
      ],
      "outbounds": [
        {
          "type": "wireguard",
          "tag": "wg",
          "server": "162.159.192.200",
          "server_port": 4500,
          "local_address": [
            "172.16.0.2/32",
            "2606:4700:110:8f77:1ca9:f086:846c:5f9e/128"
          ],
          "private_key": "wIxszdR2nMdA7a2Ul3XQcniSfSZqdqjPb6w6opvf5AU=",
          "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
          "reserved": [
            126,
            246,
            173
          ]
        },
        {
          "type": "direct",
          "tag": "direct"
        },
        {
          "type": "block",
          "tag": "block"
        }
      ],
      "route": {
        "rules": [
          {
            "domain": [
              $ytb
              "oh.my.god"
            ],
            "outbound": "wg"
          }
        ],
        "final": "direct"
      }
    }
EOF

    # 启动sing-box主进程
    if [ -e "$(basename "${FILE_MAP[web]}")" ]; then
        echo "$(basename "${FILE_MAP[web]}")" > sb.txt
        sbb=$(cat sb.txt)
        nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
        sleep 5

        if pgrep -x "$sbb" > /dev/null; then
            green "$sbb 主进程已启动"
        else
            for ((i=1; i<=5; i++)); do
                red "$sbb 主进程未启动, 重启中... (尝试次数: $i)"
                pkill -x "$sbb"
                nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
                sleep 5
                if pgrep -x "$sbb" > /dev/null; then
                    purple "$sbb 主进程已成功重启"
                    break
                fi
                if [[ $i -eq 5 ]]; then
                    red "$sbb 主进程重启失败"
                fi
            done
        fi
    fi

    # 启动Argo进程
    if [ -e "$(basename "${FILE_MAP[bot]}")" ]; then
        echo "$(basename "${FILE_MAP[bot]}")" > ag.txt
        agg=$(cat ag.txt)
        rm -rf boot.log

        if [[ $ARGO_AUTH =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
            args="tunnel --no-autoupdate run --token ${ARGO_AUTH}"
        elif [[ $ARGO_AUTH =~ TunnelSecret ]]; then
            args="tunnel --config tunnel.yml run"
        else
            args="tunnel --url http://localhost:$vmess_port --no-autoupdate --logfile boot.log --loglevel info"
        fi

        nohup ./"$agg" $args >/dev/null 2>&1 &
        sleep 10

        if pgrep -x "$agg" > /dev/null; then
            green "$agg Argo进程已启动"
        else
            red "$agg Argo进程未启动, 重启中..."
            pkill -x "$agg"
            nohup ./"$agg" "${args}" >/dev/null 2>&1 &
            sleep 5
            purple "$agg Argo进程已重启"
        fi
    fi

    sleep 2
    if ! pgrep -x "$(cat sb.txt)" > /dev/null; then
        red "主进程未启动，根据以下情况一一排查"
        yellow "1、网页端权限是否开启"
        yellow "2、网页后台删除所有端口，让脚本自动生成随机可用端口"
        yellow "3、选择5重置"
        yellow "4、当前Serv00服务器炸了？等会再试"
        red "5、以上都试了，哥直接躺平，交给进程保活，过会再来看"
        sleep 6
    fi
}

# 获取Argo域名
get_argodomain() {
    # 如果ARGO_AUTH变量不为空，直接使用预设的ARGO_DOMAIN
    if [[ -n $ARGO_AUTH ]]; then
        echo "$ARGO_DOMAIN" > gdym.log
        echo "$ARGO_DOMAIN"
    else
        # 初始化重试次数和最大重试次数
        local retry=0
        local max_retries=6
        local argodomain=""

        # 循环尝试获取Argo临时域名，最多重试6次
        while [[ $retry -lt $max_retries ]]; do
            ((retry++))

            # 从boot.log文件中提取Argo临时域名
            argodomain=$(cat boot.log 2>/dev/null | grep -a trycloudflare.com | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}')

            # 如果成功获取到域名，则退出循环
            if [[ -n $argodomain ]]; then
                break
            fi

            # 等待2秒后重试
            sleep 2
        done

        # 如果最终未能获取到域名，设置默认提示信息
        if [ -z "${argodomain}" ]; then
            argodomain="Argo临时域名暂时获取失败，Argo节点暂不可用"
        fi

        # 输出获取到的Argo域名或提示信息
        echo "$argodomain"
    fi
}

# 获取并生成节点分享链接和配置文件
get_links() {
    # 获取Argo域名并显示
    argodomain=$(get_argodomain)
    echo -e "\e[1;32mArgo域名：\e[1;35m${argodomain}\e[0m\n"

    # 获取ISP信息
    ISP=$(curl -sL --max-time 5 https://speed.cloudflare.com/meta | awk -F\" '{print $26}' | sed -e 's/ /_/g' || echo "0")

    # 获取服务器名称
    get_name() {
        if [ "$HOSTNAME" = "s1.ct8.pl" ]; then
            SERVER="CT8"
        else
            SERVER=$(echo "$HOSTNAME" | cut -d '.' -f 1)
        fi
        echo "$SERVER"
    }
    NAME="$ISP-$(get_name)"

    # 清理旧的链接文件
    rm -rf jh.txt

    # 生成Vless Reality链接
    vl_link="vless://$UUID@$IP:$vless_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$reym&fp=chrome&pbk=$public_key&type=tcp&headerType=none#$NAME-reality"
    echo "$vl_link" >> jh.txt

    # 生成Vmess WS链接
    vmws_link="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-ws\", \"add\": \"$IP\", \"port\": \"$vmess_port\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\", \"sni\": \"\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)"
    echo "$vmws_link" >> jh.txt

    # 生成Vmess WS TLS Argo链接
    vmatls_link="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-ws-tls-argo\", \"add\": \"icook.hk\", \"port\": \"8443\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$argodomain\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)"
    echo "$vmatls_link" >> jh.txt

    # 生成Vmess WS Argo链接
    vma_link="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-ws-argo\", \"add\": \"icook.hk\", \"port\": \"8880\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)"
    echo "$vma_link" >> jh.txt

    # 生成Hysteria2链接
    hy2_link="hysteria2://$UUID@$IP:$hy2_port?sni=www.bing.com&alpn=h3&insecure=1#$NAME-hy2"
    echo "$hy2_link" >> jh.txt

    # 将所有链接读取到变量中，并进行Base64编码
    url=$(cat jh.txt 2>/dev/null)
    baseurl=$(echo -e "$url" | base64 -w 0)

    # 生成sing-box配置文件
    cat > sing_box.json <<EOF
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "ui",
      "default_mode": "Rule"
    },
    "cache_file": {
      "enabled": true,
      "path": "cache.db",
      "store_fakeip": true
    }
  },
  "dns": {
    "servers": [
      {
        "tag": "proxydns",
        "address": "tls://8.8.8.8/dns-query",
        "detour": "select"
      },
      {
        "tag": "localdns",
        "address": "h3://223.5.5.5/dns-query",
        "detour": "direct"
      },
      {
        "tag": "dns_fakeip",
        "address": "fakeip"
      }
    ],
    "rules": [
      {
        "outbound": "any",
        "server": "localdns",
        "disable_cache": true
      },
      {
        "clash_mode": "Global",
        "server": "proxydns"
      },
      {
        "clash_mode": "Direct",
        "server": "localdns"
      },
      {
        "rule_set": "geosite-cn",
        "server": "localdns"
      },
      {
        "rule_set": "geosite-geolocation-!cn",
        "server": "proxydns"
      },
      {
        "rule_set": "geosite-geolocation-!cn",
        "query_type": ["A", "AAAA"],
        "server": "dns_fakeip"
      }
    ],
    "fakeip": {
      "enabled": true,
      "inet4_range": "198.18.0.0/15",
      "inet6_range": "fc00::/18"
    },
    "independent_cache": true,
    "final": "proxydns"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "address": ["172.19.0.1/30", "fd00::1/126"],
      "auto_route": true,
      "strict_route": true,
      "sniff": true,
      "sniff_override_destination": true,
      "domain_strategy": "prefer_ipv4"
    }
  ],
  "outbounds": [
    {
      "tag": "select",
      "type": "selector",
      "default": "auto",
      "outbounds": [
        "auto",
        "vless-$NAME",
        "vmess-$NAME",
        "hy2-$NAME",
        "vmess-tls-argo-$NAME",
        "vmess-argo-$NAME"
      ]
    },
    {
      "type": "vless",
      "tag": "vless-$NAME",
      "server": "$IP",
      "server_port": $vless_port,
      "uuid": "$UUID",
      "packet_encoding": "xudp",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "$reym",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
        "reality": {
          "enabled": true,
          "public_key": "$public_key",
          "short_id": ""
        }
      }
    },
    {
      "server": "$IP",
      "server_port": $vmess_port,
      "tag": "vmess-$NAME",
      "tls": {
        "enabled": false,
        "server_name": "www.bing.com",
        "insecure": false,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      },
      "packet_encoding": "packetaddr",
      "transport": {
        "headers": {
          "Host": ["www.bing.com"]
        },
        "path": "/$UUID-vm",
        "type": "ws"
      },
      "type": "vmess",
      "security": "auto",
      "uuid": "$UUID"
    },
    {
      "type": "hysteria2",
      "tag": "hy2-$NAME",
      "server": "$IP",
      "server_port": $hy2_port,
      "password": "$UUID",
      "tls": {
        "enabled": true,
        "server_name": "www.bing.com",
        "insecure": true,
        "alpn": ["h3"]
      }
    },
    {
      "server": "icook.hk",
      "server_port": 8443,
      "tag": "vmess-tls-argo-$NAME",
      "tls": {
        "enabled": true,
        "server_name": "$argodomain",
        "insecure": false,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      },
      "packet_encoding": "packetaddr",
      "transport": {
        "headers": {
          "Host": ["$argodomain"]
        },
        "path": "/$UUID-vm",
        "type": "ws"
      },
      "type": "vmess",
      "security": "auto",
      "uuid": "$UUID"
    },
    {
      "server": "icook.hk",
      "server_port": 8880,
      "tag": "vmess-argo-$NAME",
      "tls": {
        "enabled": false,
        "server_name": "$argodomain",
        "insecure": false,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      },
      "packet_encoding": "packetaddr",
      "transport": {
        "headers": {
          "Host": ["$argodomain"]
        },
        "path": "/$UUID-vm",
        "type": "ws"
      },
      "type": "vmess",
      "security": "auto",
      "uuid": "$UUID"
    },
    {
      "tag": "direct",
      "type": "direct"
    },
    {
      "tag": "auto",
      "type": "urltest",
      "outbounds": [
        "vless-$NAME",
        "vmess-$NAME",
        "hy2-$NAME",
        "vmess-tls-argo-$NAME",
        "vmess-argo-$NAME"
      ],
      "url": "https://www.gstatic.com/generate_204",
      "interval": "1m",
      "tolerance": 50,
      "interrupt_exist_connections": false
    }
  ],
  "route": {
    "rule_set": [
      {
        "tag": "geosite-geolocation-!cn",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
        "download_detour": "select",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
        "download_detour": "select",
        "update_interval": "1d"
      },
      {
        "tag": "geoip-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
        "download_detour": "select",
        "update_interval": "1d"
      }
    ],
    "auto_detect_interface": true,
    "final": "select",
    "rules": [
      {
        "inbound": "tun-in",
        "action": "sniff"
      },
      {
        "protocol": "dns",
        "action": "hijack-dns"
      },
      {
        "port": 443,
        "network": "udp",
        "action": "reject"
      },
      {
        "clash_mode": "Direct",
        "outbound": "direct"
      },
      {
        "clash_mode": "Global",
        "outbound": "select"
      },
      {
        "rule_set": "geoip-cn",
        "outbound": "direct"
      },
      {
        "rule_set": "geosite-cn",
        "outbound": "direct"
      },
      {
        "ip_is_private": true,
        "outbound": "direct"
      },
      {
        "rule_set": "geosite-geolocation-!cn",
        "outbound": "select"
      }
    ]
  },
  "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123,
    "interval": "30m",
    "detour": "direct"
  }
}
EOF

    # 生成Clash Meta配置文件
    cat > clash_meta.yaml <<EOF
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: true
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 223.5.5.5
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: vless-reality-vision-$NAME
  type: vless
  server: $IP
  port: $vless_port
  uuid: $UUID
  network: tcp
  udp: true
  tls: true
  flow: xtls-rprx-vision
  servername: $reym
  reality-opts:
    public-key: $public_key
  client-fingerprint: chrome

- name: vmess-ws-$NAME
  type: vmess
  server: $IP
  port: $vmess_port
  uuid: $UUID
  alterId: 0
  cipher: auto
  udp: true
  tls: false
  network: ws
  servername: www.bing.com
  ws-opts:
    path: "/$UUID-vm"
    headers:
      Host: www.bing.com

- name: hysteria2-$NAME
  type: hysteria2
  server: $IP
  port: $hy2_port
  password: $UUID
  alpn:
    - h3
  sni: www.bing.com
  skip-cert-verify: true
  fast-open: true

- name: vmess-tls-argo-$NAME
  type: vmess
  server: icook.hk
  port: 8443
  uuid: $UUID
  alterId: 0
  cipher: auto
  udp: true
  tls: true
  network: ws
  servername: $argodomain
  ws-opts:
    path: "/$UUID-vm"
    headers:
      Host: $argodomain

- name: vmess-argo-$NAME
  type: vmess
  server: icook.hk
  port: 8880
  uuid: $UUID
  alterId: 0
  cipher: auto
  udp: true
  tls: false
  network: ws
  servername: $argodomain
  ws-opts:
    path: "/$UUID-vm"
    headers:
      Host: $argodomain

proxy-groups:
- name: Balance
  type: load-balance
  url: https://www.gstatic.com/generate_204
  interval: 300
  strategy: round-robin
  proxies:
    - vless-reality-vision-$NAME
    - vmess-ws-$NAME
    - hysteria2-$NAME
    - vmess-tls-argo-$NAME
    - vmess-argo-$NAME

- name: Auto
  type: url-test
  url: https://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - vless-reality-vision-$NAME
    - vmess-ws-$NAME
    - hysteria2-$NAME
    - vmess-tls-argo-$NAME
    - vmess-argo-$NAME
    
- name: Select
  type: select
  proxies:
    - Balance                                         
    - Auto
    - DIRECT
    - vless-reality-vision-$NAME                              
    - vmess-ws-$NAME
    - hysteria2-$NAME
    - vmess-tls-argo-$NAME
    - vmess-argo-$NAME
rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,Select
EOF

# 生成并显示节点及订阅链接信息
sleep 2

# 确保文件路径存在，如果不存在则创建
[ -d "$FILE_PATH" ] || mkdir -p "$FILE_PATH"

# 将基础URL写入v2sub.txt文件
echo "$baseurl" > ${FILE_PATH}/${USERNAME}_v2sub.txt

# 将Clash-meta和Sing-box配置文件内容分别写入对应的文本文件
cat clash_meta.yaml > ${FILE_PATH}/${USERNAME}_clashmeta.txt
cat sing_box.json > ${FILE_PATH}/${USERNAME}_singbox.txt

# 构建分享链接
V2rayN_LINK="https://${USERNAME}.serv00.net/${USERNAME}_v2sub.txt"
Clashmeta_LINK="https://${USERNAME}.serv00.net/${USERNAME}_clashmeta.txt"
Singbox_LINK="https://${USERNAME}.serv00.net/${USERNAME}_singbox.txt"

# 生成并写入list.txt文件，包含详细的节点及订阅链接信息
cat > list.txt <<EOF
=================================================================================================

一、Vless-reality分享链接如下：
$vl_link

注意：如果之前输入的reality域名为CF域名，将激活以下功能：
可应用在 https://github.com/yonggekkk/Cloudflare_vless_trojan 项目中创建CF vless/trojan 节点

1. Proxyip(带端口)信息如下：
   方式一全局应用：设置变量名：proxyip    设置变量值：$IP:$vless_port
   方式二单节点应用：path路径改为：/pyip=$IP:$vless_port
   CF节点的TLS可开可关
   CF节点落地到CF网站的地区为：$IP所在地区

2. 非标端口反代IP信息如下：
   客户端优选IP地址为：$IP，端口：$vless_port
   CF节点的TLS必须开启
   CF节点落地到非CF网站的地区为：$IP所在地区

注：如果serv00的IP被墙，proxyip依旧有效，但用于客户端地址与端口的非标端口反代IP将不可用
注：可能有大佬会扫Serv00的反代IP作为其共享IP库或者出售，请慎重将reality域名设置为CF域名
-------------------------------------------------------------------------------------------------


二、Vmess-ws分享链接三形态如下：

1. Vmess-ws主节点分享链接如下：
   (该节点默认不支持CDN，如果设置为CDN回源(需域名)：客户端地址可自行修改优选IP/域名，7个80系端口随便换，被墙依旧能用！)
   $vmws_link

   Argo域名：${argodomain}
   如果上面Argo临时域名未生成，以下 2 与 3 的Argo节点将不可用 (打开Argo固定/临时域名网页，显示HTTP ERROR 404说明正常可用)

2. Vmess-ws-tls_Argo分享链接如下：
   (该节点为CDN优选IP节点，客户端地址可自行修改优选IP/域名，6个443系端口随便换，被墙依旧能用！)
   $vmatls_link

3. Vmess-ws_Argo分享链接如下：
   (该节点为CDN优选IP节点，客户端地址可自行修改优选IP/域名，7个80系端口随便换，被墙依旧能用！)
   $vma_link
-------------------------------------------------------------------------------------------------


三、HY2分享链接如下：
$hy2_link
-------------------------------------------------------------------------------------------------


四、以上五个节点的聚合通用订阅分享链接如下：
$V2rayN_LINK

以上五个节点聚合通用分享码：
$baseurl
-------------------------------------------------------------------------------------------------


五、查看Sing-box与Clash-meta的订阅配置文件，请进入主菜单选择4

Clash-meta订阅分享链接：
$Clashmeta_LINK

Sing-box订阅分享链接：
$Singbox_LINK
-------------------------------------------------------------------------------------------------

=================================================================================================
EOF

    # 显示生成的list.txt内容
    cat list.txt
    sleep 2

    # 清理临时日志文件
    rm -rf sb.log core tunnel.yml tunnel.json fake_useragent_0.2.0.json
}

# 显示节点及proxyip/非标端口反代ip信息
showlist() {
    # 检查list.txt文件是否存在
    if [[ -e $WORKDIR/list.txt ]]; then
        # 输出提示信息
        green "查看节点及proxyip/非标端口反代ip信息"

        # 显示list.txt文件内容
        cat $WORKDIR/list.txt
    else
        # 如果未安装sing-box，输出错误信息并退出
        red "未安装sing-box" && exit
    fi
}

# 显示sing-box和clash-meta配置文件内容
showsbclash() {
    # 检查sing-box配置文件是否存在
    if [[ -e $WORKDIR/sing_box.json ]]; then
        # 输出sing-box配置文件提示信息
        green "Sing_box配置文件如下，可上传到订阅类客户端上使用："
        yellow "其中Argo节点为CDN优选IP节点，server地址可自行修改优选IP/域名，被墙依旧能用！"
        sleep 2

        # 显示sing-box配置文件内容
        cat $WORKDIR/sing_box.json
        echo
        echo

        # 输出clash-meta配置文件提示信息
        green "Clash_meta配置文件如下，可上传到订阅类客户端上使用："
        yellow "其中Argo节点为CDN优选IP节点，server地址可自行修改优选IP/域名，被墙依旧能用！"
        sleep 2

        # 显示clash-meta配置文件内容
        cat $WORKDIR/clash_meta.yaml
        echo
    else
        # 如果未安装sing-box，输出错误信息并退出
        red "未安装sing-box" && exit
    fi
}

# 安装和配置网页进程保活脚本
servkeep() {
    # 下载并设置可执行权限给保活脚本
    curl -sSL https://raw.githubusercontent.com/rabbitwit/sing-box-yg/master/serv00keep.sh -o serv00keep.sh && chmod +x serv00keep.sh

    # 替换保活脚本中的占位符为实际值
    sed -i '' -e "14s|''|'$UUID'|" serv00keep.sh
    sed -i '' -e "17s|''|'$vless_port'|" serv00keep.sh
    sed -i '' -e "18s|''|'$vmess_port'|" serv00keep.sh
    sed -i '' -e "19s|''|'$hy2_port'|" serv00keep.sh
    sed -i '' -e "20s|''|'$IP'|" serv00keep.sh
    sed -i '' -e "21s|''|'$reym'|" serv00keep.sh

    # 如果boot.log文件不存在，则替换Arigo域名和认证信息
    if [ ! -f "$WORKDIR/boot.log" ]; then
        sed -i '' -e "15s|''|'${ARGO_DOMAIN}'|" serv00keep.sh
        sed -i '' -e "16s|''|'${ARGO_AUTH}'|" serv00keep.sh
    fi

    green "开始安装网页进程保活"

    # 设置保活网页路径，并创建目录（如果不存在）
    keep_path="$HOME/domains/${USERNAME}.${USERNAME}.serv00.net/public_nodejs"
    [ -d "$keep_path" ] || mkdir -p "$keep_path"

    # 下载并配置Node.js应用文件
    curl -sL https://raw.githubusercontent.com/rabbitwit/sing-box-yg/master/app.js -o "$keep_path"/app.js
    sed -i '' "28s/name/$USERNAME/g" "$keep_path"/app.js
    sed -i '' "22s/name/$snb/g" "$keep_path"/app.js

    # 删除旧的虚拟主机配置并添加新的配置
    devil www del ${USERNAME}.${USERNAME}.serv00.net > /dev/null 2>&1
    devil www add ${USERNAME}.serv00.net php > /dev/null 2>&1
    devil www add ${USERNAME}.${USERNAME}.serv00.net nodejs /usr/local/bin/node18 > /dev/null 2>&1

    # 配置Node.js环境
    ln -fs /usr/local/bin/node18 ~/bin/node > /dev/null 2>&1
    ln -fs /usr/local/bin/npm18 ~/bin/npm > /dev/null 2>&1
    mkdir -p ~/.npm-global
    npm config set prefix '~/.npm-global'
    echo 'export PATH=~/.npm-global/bin:~/bin:$PATH' >> $HOME/.bash_profile && source $HOME/.bash_profile
    rm -rf $HOME/.npmrc > /dev/null 2>&1

    # 进入保活网页目录并安装依赖
    cd "$keep_path"
    npm install basic-auth express dotenv axios --silent > /dev/null 2>&1

    # 清理默认页面并重启虚拟主机
    rm $HOME/domains/${USERNAME}.${USERNAME}.serv00.net/public_nodejs/public/index.html > /dev/null 2>&1
    devil www restart ${USERNAME}.${USERNAME}.serv00.net

    # 清理日志文件
    rm -rf $HOME/domains/${USERNAME}.${USERNAME}.serv00.net/logs/*

    # 输出安装完成信息
    green "安装完毕，保活网页：http://${USERNAME}.${USERNAME}.serv00.net/up" && sleep 2
}

# 检查可用IP并返回最佳选择
okip() {
    # 获取所有虚拟主机的IP地址列表
    IP_LIST=($(devil vhost list | awk '/^[0-9]+/ {print $1}'))

    # 定义API URL用于检查IP状态
    API_URL="https://status.eooce.com/api"
    IP=""

    # 获取第三个IP地址（如果有）
    THIRD_IP=${IP_LIST[2]}

    # 检查第三个IP是否可用
    RESPONSE=$(curl -s --max-time 2 "${API_URL}/${THIRD_IP}")
    if [[ $(echo "$RESPONSE" | jq -r '.status') == "Available" ]]; then
        IP=$THIRD_IP
    else
        # 如果第三个IP不可用，检查第一个IP
        FIRST_IP=${IP_LIST[0]}
        RESPONSE=$(curl -s --max-time 2 "${API_URL}/${FIRST_IP}")

        if [[ $(echo "$RESPONSE" | jq -r '.status') == "Available" ]]; then
            IP=$FIRST_IP
        else
            # 如果前两个IP都不可用，选择第二个IP
            IP=${IP_LIST[1]}
        fi
    fi

    # 输出最终选择的IP地址
    echo "$IP"
}

# 显示菜单界面
menu() {
    clear
    echo "============================================================"
    purple "修改自Serv00|ct8老王sing-box安装脚本"
    purple "不得转载"
    green "甬哥Github项目  ：github.com/yonggekkk"
    green "甬哥Blogger博客 ：ygkkk.blogspot.com"
    green "甬哥YouTube频道 ：www.youtube.com/@ygkkk"
    green "一键三协议共存：vless-reality、Vmess-ws(Argo)、hysteria2"
    green "当前脚本版本：V25.1.27  快捷方式：bash serv00.sh"
    echo "============================================================"
    green "1. 安装sing-box"
    echo "------------------------------------------------------------"
    red "2. 卸载sing-box"
    echo "------------------------------------------------------------"
    green "3. 查看：各节点分享/sing-box与clash-meta订阅链接/CF节点proxyip"
    echo "------------------------------------------------------------"
    green "4. 查看：sing-box与clash-meta配置文件"
    echo "------------------------------------------------------------"
    yellow "5. 重置并清理所有服务进程(系统初始化)"
    echo "------------------------------------------------------------"
    red "0. 退出脚本"
    echo "============================================================"

    # 获取主机名缩写，并初始化域名数组
    nb=$(echo "$HOSTNAME" | cut -d '.' -f 1 | tr -d 's')
    ym=("$HOSTNAME" "cache$nb.serv00.com" "web$nb.serv00.com")

    # 清理先前的IP记录文件
    rm -rf $WORKDIR/ip.txt $WORKDIR/hy2ip.txt

    # 查询并记录hysteria2的IP信息
    for ip in "${ym[@]}"; do
        dig @8.8.8.8 +time=2 +short $ip >> $WORKDIR/hy2ip.txt
        sleep 1
    done

    # 查询并记录所有域名的IP信息，并检测其可用性
    for ym in "${ym[@]}"; do
        response=$(curl -sL --connect-timeout 5 --max-time 7 "https://ss.botai.us.kg/api/getip?host=$ym")
        if [[ -z "$response" || "$response" == *unknown* ]]; then
            for ip in "${ym[@]}"; do
                dig @8.8.8.8 +time=2 +short $ip >> $WORKDIR/ip.txt
                sleep 1
            done
        else
            echo "$response" | while IFS='|' read -r ip status; do
                if [[ $status == "Accessible" ]]; then
                    echo "$ip: 可用" >> $WORKDIR/ip.txt
                else
                    echo "$ip: 被墙 (Argo与CDN回源节点、proxyip依旧有效)" >> $WORKDIR/ip.txt
                fi
            done
        fi
    done

    # 显示服务器名称和可用IP列表
    green "Serv00服务器名称：$snb"
    green "当前可选择的IP如下："
    cat $WORKDIR/ip.txt
    echo

    # 检查并显示sing-box的安装和运行状态
    if [[ -e $WORKDIR/list.txt ]]; then
        green "已安装sing-box"
        ps aux | grep '[r]un -c con' > /dev/null && green "主进程运行正常" || yellow "主进程未启动…………请刷新一下保活网页"

        if [ -f "$WORKDIR/boot.log" ] && grep -q "trycloudflare.com" "$WORKDIR/boot.log" 2>/dev/null && ps aux | grep '[t]unnel --u' > /dev/null; then
            argosl=$(cat "$WORKDIR/boot.log" 2>/dev/null | grep -a trycloudflare.com | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}')
            checkhttp=$(curl -o /dev/null -s -w "%{http_code}\n" "https://$argosl")
            [ "$checkhttp" -eq 404 ] && check="域名有效" || check="域名可能无效"
            green "当前Argo临时域名：$argosl  $check"
        fi

        if [ -f "$WORKDIR/boot.log" ] && ! ps aux | grep '[t]unnel --u' > /dev/null; then
            yellow "当前Argo临时域名暂时不存在，请刷新一下保活网页，稍后可再次进入脚本查看"
        fi

        if ps aux | grep '[t]unnel --n' > /dev/null; then
            argogd=$(cat $WORKDIR/gdym.log 2>/dev/null)
            checkhttp=$(curl --max-time 2 -o /dev/null -s -w "%{http_code}\n" "https://$argogd")
            [ "$checkhttp" -eq 404 ] && check="域名有效" || check="域名可能失效"
            green "当前Argo固定域名：$argogd $check"
        fi

        if [ ! -f "$WORKDIR/boot.log" ] && ! ps aux | grep '[t]unnel --n' > /dev/null; then
            yellow "当前Argo固定域名：$(cat $WORKDIR/gdym.log 2>/dev/null)，启用失败，请检查相关参数是否输入有误"
        fi

        green "保活网页：http://${USERNAME}.${USERNAME}.serv00.net/up"
    else
        red "未安装sing-box，请选择 1 进行安装"
    fi

    # 更新脚本文件并获取用户选择
    curl -sSL https://raw.githubusercontent.com/rabbitwit/sing-box-yg/master/serv00.sh -o serv00.sh && chmod +x serv00.sh
    echo "========================================================="
    reading "请输入选择【0-5】: " choice
    echo ""

    case "${choice}" in
        1) install_singbox ;;
        2) uninstall_singbox ;;
        3) showlist ;;
        4) showsbclash ;;
        5) kill_all_tasks ;;
        0) exit 0 ;;
        *) red "无效的选项，请输入 0 到 5" ;;
    esac
}

menu
