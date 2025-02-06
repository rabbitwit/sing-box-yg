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

# 定义系统变量
export LC_ALL=C
export UUID=${UUID:-''}  
export ARGO_DOMAIN=${ARGO_DOMAIN:-''}   
export ARGO_AUTH=${ARGO_AUTH:-''}     
export vless_port=${vless_port:-''}    
export vmess_port=${vmess_port:-''}  
export hy2_port=${hy2_port:-''}       
export IP=${IP:-''}                  
export reym=${reym:-''}
export reset=${reset:-''}

USERNAME=$(whoami | tr '[:upper:]' '[:lower:]')
HOSTNAME=$(hostname)

# 检查是否需要重置系统
if [[ "$reset" =~ ^[Yy]$ ]]; then
    # 杀死当前用户（除sshd、bash、grep外）的所有进程
    bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1

    # 将当前用户主目录下的所有文件权限设置为644
    find ~ -type f -exec chmod 644 {} \; 2>/dev/null

    # 将当前用户主目录下的所有目录权限设置为755
    find ~ -type d -exec chmod 755 {} \; 2>/dev/null

    # 删除当前用户主目录下的所有文件
    find ~ -type f -exec rm -f {} \; 2>/dev/null

    # 删除当前用户主目录下所有空目录
    find ~ -type d -empty -exec rmdir {} \; 2>/dev/null

    # 强制删除当前用户主目录下的所有内容（包括非空目录）
    find ~ -exec rm -rf {} \; 2>/dev/null

    # 输出重置完成提示信息
    echo "重置系统完成"
fi

# 等待2秒钟，确保前面的操作已经完成
sleep 2

# 使用devil命令为指定用户添加一个PHP服务，并将输出重定向到/dev/null以避免显示
devil www add ${USERNAME}.serv00.net php > /dev/null 2>&1

# 定义文件路径为用户的public_html目录
FILE_PATH="${HOME}/domains/${USERNAME}.serv00.net/public_html"

# 定义工作日志目录路径
WORKDIR="${HOME}/domains/${USERNAME}.serv00.net/logs"

# 检查工作日志目录是否存在，如果不存在则创建并设置权限为777
if [ ! -d "$WORKDIR" ]; then
    mkdir -p "$WORKDIR"
    chmod 777 "$WORKDIR"
fi

# 定义函数 read_ip 用于获取并处理 IP 地址
read_ip() {
    # 提取主机名中的数字部分，并去掉前缀 's'
    nb=$(echo "$HOSTNAME" | cut -d '.' -f 1 | tr -d 's')

    # 定义需要查询的域名列表
    ym=("$HOSTNAME" "cache$nb.serv00.com" "web$nb.serv00.com")

    # 删除旧的 IP 文件
    rm -rf ip.txt hy2ip.txt

    # 使用 dig 命令查询每个域名的 IP 地址，并将结果写入 hy2ip.txt
    for ip in "${ym[@]}"; do
        dig @8.8.8.8 +time=2 +short $ip >> hy2ip.txt
        sleep 1  # 每次查询后暂停1秒，避免频繁请求
    done

    # 遍历域名列表，尝试从 API 获取 IP 地址信息
    for ym_item in "${ym[@]}"; do
        # 引用 frankiejun API 获取 IP 地址及其状态
        response=$(curl -s "https://ss.botai.us.kg/api/getip?host=$ym_item")

        if [[ -z "$response" ]]; then
            # 如果 API 返回为空，则使用 dig 命令再次查询 IP 地址
            for ip in "${ym[@]}"; do
                dig @8.8.8.8 +time=2 +short $ip >> ip.txt
                sleep 1  # 每次查询后暂停1秒，避免频繁请求
            done
            break  # 如果 API 失败，跳出循环
        else
            # 解析 API 返回的结果
            echo "$response" | while IFS='|' read -r ip status; do
                if [[ $status == "Accessible" ]]; then
                    echo "$ip: 可用" >> ip.txt
                else
                    echo "$ip: 被墙 (Argo与CDN回源节点、proxyip依旧有效)" >> ip.txt
                fi
            done
        fi
    done

    # 如果环境变量 IP 为空，则尝试从 ip.txt 中获取可用的 IP 地址
    if [[ -z "$IP" ]]; then
        IP=$(grep -m 1 "可用" ip.txt | awk -F ':' '{print $1}')

        if [ -z "$IP" ]; then
            # 如果没有找到可用的 IP 地址，则调用 okip 函数获取 IP 地址
            IP=$(okip)

            if [ -z "$IP" ]; then
                # 如果 okip 函数也失败，则使用 ip.txt 中的第一个 IP 地址
                IP=$(head -n 1 ip.txt | awk -F ':' '{print $1}')
            fi
        fi
    fi
}

# 定义函数 okip 用于获取可用的 IP 地址
okip() {
    # 获取所有虚拟主机的 IP 地址列表，并存储在数组 IP_LIST 中
    IP_LIST=($(devil vhost list | awk '/^[0-9]+/ {print $1}'))

    # 定义 API 的 URL
    API_URL="https://status.eooce.com/api"

    # 初始化 IP 变量为空
    IP=""

    # 获取第三个 IP 地址（如果存在）
    THIRD_IP=${IP_LIST[2]}

    # 调用 API 检查第三个 IP 地址是否可用
    RESPONSE=$(curl -s --max-time 2 "${API_URL}/${THIRD_IP}")

    # 检查 API 返回的状态
    if [[ $(echo "$RESPONSE" | jq -r '.status') == "Available" ]]; then
        # 如果第三个 IP 地址可用，则设置 IP 为第三个 IP 地址
        IP=$THIRD_IP
    else
        # 如果第三个 IP 地址不可用，则检查第一个 IP 地址
        FIRST_IP=${IP_LIST[0]}
        RESPONSE=$(curl -s --max-time 2 "${API_URL}/${FIRST_IP}")

        # 再次检查 API 返回的状态
        if [[ $(echo "$RESPONSE" | jq -r '.status') == "Available" ]]; then
            # 如果第一个 IP 地址可用，则设置 IP 为第一个 IP 地址
            IP=$FIRST_IP
        else
            # 如果前两个 IP 地址都不可用，则选择第二个 IP 地址
            IP=${IP_LIST[1]}
        fi
    fi

    # 输出最终选择的 IP 地址
    echo "$IP"
}

# 定义函数 argo_configure 用于生成 Argo 配置文件
argo_configure() {
    # 检查 ARGO_AUTH 是否包含 "TunnelSecret" 字符串
    if [[ $ARGO_AUTH =~ TunnelSecret ]]; then
        # 如果包含，则将 ARGO_AUTH 内容写入 tunnel.json 文件
        echo "$ARGO_AUTH" > tunnel.json

        # 使用 here document 创建 tunnel.yml 文件并写入配置内容
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

# 定义函数 uuidport 用于生成 UUID 并管理端口配置
uuidport() {
    # 检查并生成 UUID
    if [[ -z "$UUID" ]]; then
        if [ ! -e UUID.txt ]; then
            # 如果 UUID.txt 文件不存在，则生成新的 UUID 并写入文件
            UUID=$(uuidgen -r)
            echo "$UUID" > UUID.txt
        else
            # 如果 UUID.txt 文件存在，则读取已有的 UUID
            UUID=$(<UUID.txt)
        fi
    fi

    # 设置 reym 变量（如果未设置）
    if [[ -z "$reym" ]]; then
        reym=$USERNAME.serv00.net
    fi

    # 检查并设置 vless_port, vmess_port, hy2_port
    if [[ -z "$vless_port" ]] || [[ -z "$vmess_port" ]] || [[ -z "$hy2_port" ]]; then
        # 获取当前端口列表
        port_list=$(devil port list)
        tcp_ports=$(echo "$port_list" | grep -c "tcp")
        udp_ports=$(echo "$port_list" | grep -c "udp")

        # 检查端口数量是否符合要求
        if [[ $tcp_ports -ne 2 || $udp_ports -ne 1 ]]; then
            echo "端口数量不符合要求，正在调整..."

            # 处理多余的 TCP 端口
            if [[ $tcp_ports -gt 2 ]]; then
                tcp_to_delete=$((tcp_ports - 2))
                echo "$port_list" | awk '/tcp/ {print $1, $2}' | head -n $tcp_to_delete | while read port type; do
                    devil port del $type $port
                    echo "已删除TCP端口: $port"
                done
            fi

            # 处理多余的 UDP 端口
            if [[ $udp_ports -gt 1 ]]; then
                udp_to_delete=$((udp_ports - 1))
                echo "$port_list" | awk '/udp/ {print $1, $2}' | head -n $udp_to_delete | while read port type; do
                    devil port del $type $port
                    echo "已删除UDP端口: $port"
                done
            fi

            # 添加缺少的 TCP 端口
            if [[ $tcp_ports -lt 2 ]]; then
                tcp_ports_to_add=$((2 - tcp_ports))
                tcp_ports_added=0
                while [[ $tcp_ports_added -lt $tcp_ports_to_add ]]; do
                    tcp_port=$(shuf -i 10000-65535 -n 1)
                    result=$(devil port add tcp $tcp_port 2>&1)
                    if [[ $result == *"succesfully"* ]]; then
                        echo "已添加TCP端口: $tcp_port"
                        if [[ $tcp_ports_added -eq 0 ]]; then
                            tcp_port1=$tcp_port
                        else
                            tcp_port2=$tcp_port
                        fi
                        tcp_ports_added=$((tcp_ports_added + 1))
                    else
                        echo "端口 $tcp_port 不可用，尝试其他端口..."
                    fi
                done
            fi

            # 添加缺少的 UDP 端口
            if [[ $udp_ports -lt 1 ]]; then
                while true; do
                    udp_port=$(shuf -i 10000-65535 -n 1)
                    result=$(devil port add udp $udp_port 2>&1)
                    if [[ $result == *"succesfully"* ]]; then
                        echo "已添加UDP端口: $udp_port"
                        break
                    else
                        echo "端口 $udp_port 不可用，尝试其他端口..."
                    fi
                done
            fi

            echo "端口已调整完成, 将断开SSH连接"
            sleep 3
            devil binexec on >/dev/null 2>&1
            kill -9 $(ps -o ppid= -p $$) >/dev/null 2>&1
        else
            # 如果端口数量符合要求，直接获取端口号
            tcp_ports=$(echo "$port_list" | awk '/tcp/ {print $1}')
            tcp_port1=$(echo "$tcp_ports" | sed -n '1p')
            tcp_port2=$(echo "$tcp_ports" | sed -n '2p')
            udp_port=$(echo "$port_list" | awk '/udp/ {print $1}')

            echo "你的vless-reality的TCP端口: $tcp_port1"
            echo "你的vmess的TCP端口(设置Argo固定域名端口)：$tcp_port2"
            echo "你的hysteria2的UDP端口: $udp_port"
        fi
    fi

    # 导出端口号到环境变量
    export vless_port=$tcp_port1
    export vmess_port=$tcp_port2
    export hy2_port=$udp_port
}

# 定义函数 download_and_run_singbox 用于下载并运行 SingBox 和 Argo 配置
download_and_run_singbox() {
    # 检查 sb.txt 和 ag.txt 是否存在，如果不存在则执行下载和配置逻辑
    if [ ! -s sb.txt ] && [ ! -s ag.txt ]; then
        ARCH=$(uname -m) && DOWNLOAD_DIR="." && mkdir -p "$DOWNLOAD_DIR" && FILE_INFO=()

        # 根据架构选择合适的文件下载链接
        if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
            FILE_INFO=("https://github.com/eooce/test/releases/download/arm64/sb web" "https://github.com/eooce/test/releases/download/arm64/bot13 bot")
        elif [ "$ARCH" == "amd64" ] || [ "$ARCH" == "x86_64" ] || [ "$ARCH" == "x86" ]; then
            FILE_INFO=("https://github.com/yonggekkk/Cloudflare_vless_trojan/releases/download/serv00/sb web" "https://github.com/yonggekkk/Cloudflare_vless_trojan/releases/download/serv00/server bot")
        else
            echo "Unsupported architecture: $ARCH"
            exit 1
        fi

        # 声明关联数组 FILE_MAP 用于存储文件名映射
        declare -A FILE_MAP

        # 生成随机文件名的辅助函数
        generate_random_name() {
            local chars=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
            local name=""
            for i in {1..6}; do
                name="$name${chars:RANDOM%${#chars}:1}"
            done
            echo "$name"
        }

        # 下载文件并处理下载失败的辅助函数
        download_with_fallback() {
            local URL=$1
            local NEW_FILENAME=$2

            curl -L -sS --max-time 2 -o "$NEW_FILENAME" "$URL" &
            CURL_PID=$!
            CURL_START_SIZE=$(stat -c%s "$NEW_FILENAME" 2>/dev/null || echo 0)

            sleep 1
            CURL_CURRENT_SIZE=$(stat -c%s "$NEW_FILENAME" 2>/dev/null || echo 0)

            if [ "$CURL_CURRENT_SIZE" -le "$CURL_START_SIZE" ]; then
                kill $CURL_PID 2>/dev/null
                wait $CURL_PID 2>/dev/null
                wget -q -O "$NEW_FILENAME" "$URL"
                echo -e "\e[1;32mDownloading $NEW_FILENAME by wget\e[0m"
            else
                wait $CURL_PID
                echo -e "\e[1;32mDownloading $NEW_FILENAME by curl\e[0m"
            fi
        }

        # 下载并处理每个文件
        for entry in "${FILE_INFO[@]}"; do
            URL=$(echo "$entry" | cut -d ' ' -f 1)
            RANDOM_NAME=$(generate_random_name)
            NEW_FILENAME="$DOWNLOAD_DIR/$RANDOM_NAME"

            if [ -e "$NEW_FILENAME" ]; then
                echo -e "\e[1;32m$NEW_FILENAME already exists, Skipping download\e[0m"
            else
                download_with_fallback "$URL" "$NEW_FILENAME"
            fi

            chmod +x "$NEW_FILENAME"
            FILE_MAP[$(echo "$entry" | cut -d ' ' -f 2)]="$NEW_FILENAME"
        done
        wait
    fi

    # 如果 private_key.txt 文件不存在，则生成密钥对
    if [ ! -e private_key.txt ]; then
        output=$("./$(basename ${FILE_MAP[web]})" generate reality-keypair)
        private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
        public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')
        echo "${private_key}" > private_key.txt
        echo "${public_key}" > public_key.txt
    fi

    # 读取私钥和公钥
    private_key=$(<private_key.txt)
    public_key=$(<public_key.txt)

    # 生成 SSL 证书
    openssl ecparam -genkey -name prime256v1 -out "private.key"
    openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=$USERNAME.serv00.net"

    # 提取主机名中的数字部分，并去掉前缀 's'
    nb=$(hostname | cut -d '.' -f 1 | tr -d 's')

    # 根据条件设置 ytb 变量
    if [ "$nb" == "14" ] || [ "$nb" == "15" ]; then
        ytb='"jnn-pa.googleapis.com",'
    fi

    # 读取 hy2ip.txt 文件中的 IP 地址
    hy1p=$(sed -n '1p' hy2ip.txt)
    hy2p=$(sed -n '2p' hy2ip.txt)
    hy3p=$(sed -n '3p' hy2ip.txt)

    # 创建 config.json 文件并写入配置内容
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
        "alpn": ["h3"],
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
        "alpn": ["h3"],
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
        "alpn": ["h3"],
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
          "short_id": [""]
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
      "reserved": [126, 246, 173]
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

    # 检查并启动 SingBox 主进程
    if ! ps aux | grep '[r]un -c con' > /dev/null; then
        ps aux | grep '[r]un -c con' | awk '{print $2}' | xargs -r kill -9 > /dev/null 2>&1
        if [ -e "$(basename "${FILE_MAP[web]}")" ]; then
            echo "$(basename "${FILE_MAP[web]}")" > sb.txt
            sbb=$(cat sb.txt)
            nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
            sleep 5
            if pgrep -x "$sbb" > /dev/null; then
                green "$sbb 主进程已启动"
            else
                red "$sbb 主进程未启动, 重启中..."
                pkill -x "$sbb"
                nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
                sleep 2
                purple "$sbb 主进程已重启"
            fi
        else
            sbb=$(cat sb.txt)
            nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
            sleep 5
            if pgrep -x "$sbb" > /dev/null; then
                green "$sbb 主进程已启动"
            else
                red "$sbb 主进程未启动, 重启中..."
                pkill -x "$sbb"
                nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
                sleep 2
                purple "$sbb 主进程已重启"
            fi
        fi
    else
        green "主进程已启动"
    fi

    # 启动 Argo 进程
    cfgo() {
        rm -rf boot.log
        if [ -e "$(basename "${FILE_MAP[bot]}")" ]; then
            echo "$(basename "${FILE_MAP[bot]}")" > ag.txt
            agg=$(cat ag.txt)
            if [[ $ARGO_AUTH =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
                args="tunnel --no-autoupdate run --token ${ARGO_AUTH}"
            elif [[ $ARGO_AUTH =~ TunnelSecret ]]; then
                args="tunnel --edge-ip-version auto --config tunnel.yml run"
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
        else
            agg=$(cat ag.txt)
            if [[ $ARGO_AUTH =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
                args="tunnel --no-autoupdate run --token ${ARGO_AUTH}"
            elif [[ $ARGO_AUTH =~ TunnelSecret ]]; then
                args="tunnel --edge-ip-version auto --config tunnel.yml run"
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
    }

    # 检查并启动 Argo 进程
    if [ -z "$ARGO_DOMAIN" ] && ! ps aux | grep '[t]unnel --u' > /dev/null; then
        ps aux | grep '[t]unnel --u' | awk '{print $2}' | xargs -r kill -9 > /dev/null 2>&1
        cfgo
    elif [ -n "$ARGO_DOMAIN" ] && ! ps aux | grep '[t]unnel --n' > /dev/null; then
        ps aux | grep '[t]unnel --n' | awk '{print $2}' | xargs -r kill -9 > /dev/null 2>&1
        cfgo
    else
        green "Argo进程已启动"
    fi

    sleep 2

    # 检查 SingBox 主进程是否启动成功
    if ! pgrep -x "$(cat sb.txt)" > /dev/null; then
        red "主进程未启动，根据以下情况一一排查"
        yellow "1、网页端权限是否开启"
        yellow "2、网页后台删除所有端口，让脚本自动生成随机可用端口"
        yellow "3、选择y运行一次重置"
        yellow "4、当前Serv00服务器炸了？等会再试"
        red "5、以上都试了，哥直接躺平，交给进程保活，过会再来看"
    fi
}

# 定义函数 get_argodomain 用于获取 Argo 域名
get_argodomain() {
    # 如果 ARGO_AUTH 不为空，则直接使用 ARGO_DOMAIN 并记录到 gdym.log 文件
    if [[ -n $ARGO_AUTH ]]; then
        echo "$ARGO_DOMAIN" > gdym.log
        echo "$ARGO_DOMAIN"
    else
        # 初始化重试次数和最大重试次数
        local retry=0
        local max_retries=6
        local argodomain=""

        # 循环尝试获取 Argo 域名，最多重试 max_retries 次
        while [[ $retry -lt $max_retries ]]; do
            ((retry++))

            # 从 boot.log 文件中提取 Argo 域名
            argodomain=$(cat boot.log 2>/dev/null | grep -a trycloudflare.com | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}')

            # 如果成功获取到域名，则退出循环
            if [[ -n $argodomain ]]; then
                break
            fi

            # 每次重试之间暂停2秒
            sleep 2
        done

        # 如果最终未能获取到域名，则设置默认提示信息
        if [ -z "${argodomain}" ]; then
            argodomain="Argo临时域名暂时获取失败，Argo节点暂不可用"
        fi

        # 输出最终获取到的 Argo 域名
        echo "$argodomain"
    fi
}

get_links(){
argodomain=$(get_argodomain)
echo -e "\e[1;32mArgo域名：\e[1;35m${argodomain}\e[0m\n"
ISP=$(curl -sL --max-time 5 https://speed.cloudflare.com/meta | awk -F\" '{print $26}' | sed -e 's/ /_/g' || echo "0")
get_name() { if [ "$HOSTNAME" = "s1.ct8.pl" ]; then SERVER="CT8"; else SERVER=$(echo "$HOSTNAME" | cut -d '.' -f 1); fi; echo "$SERVER"; }
NAME="$ISP-$(get_name)"
rm -rf jh.txt
vl_link="vless://$UUID@$IP:$vless_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$reym&fp=chrome&pbk=$public_key&type=tcp&headerType=none#$NAME-reality"
echo "$vl_link" >> jh.txt
vmws_link="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-ws\", \"add\": \"$IP\", \"port\": \"$vmess_port\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\", \"sni\": \"\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)"
echo "$vmws_link" >> jh.txt
vmatls_link="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-ws-tls-argo\", \"add\": \"icook.hk\", \"port\": \"8443\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$argodomain\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)"
echo "$vmatls_link" >> jh.txt
vma_link="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-ws-argo\", \"add\": \"icook.hk\", \"port\": \"8880\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)"
echo "$vma_link" >> jh.txt
hy2_link="hysteria2://$UUID@$IP:$hy2_port?sni=www.bing.com&alpn=h3&insecure=1#$NAME-hy2"
echo "$hy2_link" >> jh.txt
url=$(cat jh.txt 2>/dev/null)
baseurl=$(echo -e "$url" | base64 -w 0)

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
      "external_ui_download_url": "",
      "external_ui_download_detour": "",
      "secret": "",
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
                "query_type": [
                    "A",
                    "AAAA"
                ],
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
	  "address": [
      "172.19.0.1/30",
	  "fd00::1/126"
      ],
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
                    "Host": [
                        "www.bing.com"
                    ]
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
            "alpn": [
                "h3"
            ]
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
                    "Host": [
                        "$argodomain"
                    ]
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
                    "Host": [
                        "$argodomain"
                    ]
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

sleep 2
[ -d "$FILE_PATH" ] || mkdir -p "$FILE_PATH"
echo "$baseurl" > ${FILE_PATH}/${USERNAME}_v2sub.txt
cat clash_meta.yaml > ${FILE_PATH}/${USERNAME}_clashmeta.txt
cat sing_box.json > ${FILE_PATH}/${USERNAME}_singbox.txt
V2rayN_LINK="https://${USERNAME}.serv00.net/${USERNAME}_v2sub.txt"
Clashmeta_LINK="https://${USERNAME}.serv00.net/${USERNAME}_clashmeta.txt"
Singbox_LINK="https://${USERNAME}.serv00.net/${USERNAME}_singbox.txt"
cat > list.txt <<EOF
=================================================================================================

一、Vless-reality分享链接如下：
$vl_link

注意：如果之前输入的reality域名为CF域名，将激活以下功能：
可应用在 https://github.com/yonggekkk/Cloudflare_vless_trojan 项目中创建CF vless/trojan 节点
1、Proxyip(带端口)信息如下：
方式一全局应用：设置变量名：proxyip    设置变量值：$IP:$vless_port  
方式二单节点应用：path路径改为：/pyip=$IP:$vless_port
CF节点的TLS可开可关
CF节点落地到CF网站的地区为：$IP所在地区

2、非标端口反代IP信息如下：
客户端优选IP地址为：$IP，端口：$vless_port
CF节点的TLS必须开启
CF节点落地到非CF网站的地区为：$IP所在地区

注：如果serv00的IP被墙，proxyip依旧有效，但用于客户端地址与端口的非标端口反代IP将不可用
注：可能有大佬会扫Serv00的反代IP作为其共享IP库或者出售，请慎重将reality域名设置为CF域名
-------------------------------------------------------------------------------------------------


二、Vmess-ws分享链接三形态如下：

1、Vmess-ws主节点分享链接如下：
(该节点默认不支持CDN，如果设置为CDN回源(需域名)：客户端地址可自行修改优选IP/域名，7个80系端口随便换，被墙依旧能用！)
$vmws_link

Argo域名：${argodomain}
如果上面Argo临时域名未生成，以下 2 与 3 的Argo节点将不可用 (打开Argo固定/临时域名网页，显示HTTP ERROR 404说明正常可用)

2、Vmess-ws-tls_Argo分享链接如下： 
(该节点为CDN优选IP节点，客户端地址可自行修改优选IP/域名，6个443系端口随便换，被墙依旧能用！)
$vmatls_link

3、Vmess-ws_Argo分享链接如下：
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
cat list.txt
sleep 2
rm -rf sb.log core tunnel.yml tunnel.json fake_useragent_0.2.0.json
}

# 定义函数 install_singbox 用于安装 SingBox
install_singbox() {
    cd "$WORKDIR" || { echo "无法切换到工作目录 $WORKDIR"; exit 1; }

    # 调用 read_ip 函数获取 IP 地址
    read_ip

    # 调用 argo_configure 函数生成 Argo 配置
    argo_configure

    # 调用 uuidport 函数生成 UUID 并管理端口配置
    uuidport

    # 下载并运行 SingBox
    download_and_run_singbox

    # 获取链接信息
    get_links

    # 返回主目录
    cd || { echo "无法返回主目录"; exit 1; }
}

install_singbox
