#!/bin/bash

re="\033[0m"
red="\033[1;91m"
# shellcheck disable=SC2034
green="\e[1;32m"
# shellcheck disable=SC2034
yellow="\e[1;33m"
purple="\e[1;35m"

red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }

reading() { read -p "$(red "$1")" "$2"; }

# 获取用户名并转换为小写
USERNAME=$(whoami | tr '[:upper:]' '[:lower:]')
HOSTNAME=$(hostname)
snb=$(hostname | awk -F '.' '{print $1}')

# 验证 USERNAME 是否包含非法字符
if ! [[ "$USERNAME" =~ ^[a-z0-9_-]+$ ]]; then
    echo "Invalid username: $USERNAME"
    exit 1
fi

# 定义路径
BASE_DIR="${HOME}/domains/${USERNAME}.serv00.net"
FILE_PATH="${BASE_DIR}/public_html"
WORKDIR="${BASE_DIR}/logs"

# 创建工作目录并设置权限
if [ ! -d "$WORKDIR" ]; then
    if ! mkdir -p "$WORKDIR"; then
        echo "Failed to create directory: $WORKDIR"
        exit 1
    fi
    chmod 755 "$WORKDIR"  # 更严格的权限设置
fi


read_ip() {
    # 检查 ip.txt 文件是否存在
    if [ ! -f "ip.txt" ]; then
        red "文件 ip.txt 不存在"
        exit 1
    fi

    # 显示 ip.txt 内容
    cat ip.txt

    # 提示用户输入 IP
    reading "请输入上面三个IP中的任意一个 (建议默认回车自动选择可用IP): " IP

    # 如果用户没有输入 IP，则尝试自动选择
    if [[ -z "$IP" ]]; then
        # 尝试选择标记为可用的 IP
        IP=$(grep -m 1 "可用" ip.txt | awk -F ':' '{print $1}')
        if [ -z "$IP" ]; then
            # 如果没有可用的 IP，调用 okip 函数
            IP=$(okip)
            if [ -z "$IP" ]; then
                # 如果 okip 函数返回空，选择第一个 IP
                IP=$(head -n 1 ip.txt | awk -F ':' '{print $1}')
            fi
        fi
    fi

    # 输出选择的 IP
    green "你选择的IP为: $IP"
}

read_uuid() {
    reading "请输入统一的uuid密码 (建议回车默认随机): " UUID
    if [[ -z "$UUID" ]]; then
        # 尝试使用 uuidgen 生成 UUID
        UUID=$(uuidgen 2>/dev/null)
        if [[ -z "$UUID" ]]; then
            # 如果 uuidgen 失败，使用其他方法生成 UUID
            UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null)
            if [[ -z "$UUID" ]]; then
                # 如果所有方法都失败，手动生成一个简单的 UUID
                UUID=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
            fi
        fi
    fi
    green "你的uuid为: $UUID"
}

read_reym() {
    yellow "方式一：回车使用CF域名，支持proxyip+非标端口反代ip功能 (推荐)"
    yellow "方式二：输入 s 表示使用Serv00自带域名，不支持proxyip功能 (推荐)"
    yellow "方式三：支持其他域名，注意要符合reality域名规则"
    reading "请输入reality域名 【请选择 回车 或者 s 或者 输入域名】: " reym

    if [[ -z "$reym" ]]; then
        reym="www.speedtest.net"
    elif [[ "$reym" == "s" || "$reym" == "S" ]]; then
        reym="${USERNAME}.serv00.net"
    else
        # 验证输入的域名是否符合域名规则
        if ! [[ "$reym" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            red "输入的域名格式不正确，请重新输入"
            read_reym  # 重新调用函数以获取正确的输入
            return
        fi
    fi

    green "你的reality域名为: $reym"
}

check_port() {
    # 获取端口列表
    port_list=$(devil port list)

    # 统计 TCP 和 UDP 端口数量
    tcp_ports=$(echo "$port_list" | grep -c "tcp")
    udp_ports=$(echo "$port_list" | grep -c "udp")

    # 检查端口数量是否符合要求
    if [[ $tcp_ports -ne 2 || $udp_ports -ne 1 ]]; then
        red "端口数量不符合要求，正在调整..."

        # 删除多余的 TCP 端口
        if [[ $tcp_ports -gt 2 ]]; then
            tcp_to_delete=$((tcp_ports - 2))
            echo "$port_list" | awk '/tcp/ {print $1, $2}' | head -n $tcp_to_delete | while read port type; do
                devil port del $type $port
                green "已删除TCP端口: $port"
            done
        fi

        # 删除多余的 UDP 端口
        if [[ $udp_ports -gt 1 ]]; then
            udp_to_delete=$((udp_ports - 1))
            echo "$port_list" | awk '/udp/ {print $1, $2}' | head -n $udp_to_delete | while read port type; do
                devil port del $type $port
                green "已删除UDP端口: $port"
            done
        fi

        # 添加缺少的 TCP 端口
        if [[ $tcp_ports -lt 2 ]]; then
            tcp_ports_to_add=$((2 - tcp_ports))
            tcp_ports_added=0
            while [[ $tcp_ports_added -lt $tcp_ports_to_add ]]; do
                tcp_port=$(shuf -i 10000-65535 -n 1)
                if ! netstat -tuln | grep -q ":$tcp_port "; then
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
                else
                    yellow "端口 $tcp_port 已被占用，尝试其他端口..."
                fi
            done
        fi

        # 添加缺少的 UDP 端口
        if [[ $udp_ports -lt 1 ]]; then
            while true; do
                udp_port=$(shuf -i 10000-65535 -n 1)
                if ! netstat -uln | grep -q ":$udp_port "; then
                    result=$(devil port add udp $udp_port 2>&1)
                    if [[ $result == *"succesfully"* ]]; then
                        green "已添加UDP端口: $udp_port"
                        break
                    else
                        yellow "端口 $udp_port 不可用，尝试其他端口..."
                    fi
                else
                    yellow "端口 $udp_port 已被占用，尝试其他端口..."
                fi
            done
        fi

        green "端口已调整完成,将断开ssh连接,请重新连接ssh重新执行脚本"
        devil binexec on >/dev/null 2>&1
        kill -9 $(ps -o ppid= -p $$) >/dev/null 2>&1
    else
        # 提取现有的 TCP 和 UDP 端口
        tcp_ports=$(echo "$port_list" | awk '/tcp/ {print $1}')
        tcp_port1=$(echo "$tcp_ports" | sed -n '1p')
        tcp_port2=$(echo "$tcp_ports" | sed -n '2p')
        udp_port=$(echo "$port_list" | awk '/udp/ {print $1}')

        purple "当前TCP端口: $tcp_port1 和 $tcp_port2"
        purple "当前UDP端口: $udp_port"
    fi

    # 导出端口变量
    export vless_port=$tcp_port1
    export vmess_port=$tcp_port2
    export hy2_port=$udp_port

    green "你的vless-reality端口: $vless_port"
    green "你的vmess-ws端口(设置Argo固定域名端口): $vmess_port"
    green "你的hysteria2端口: $hy2_port"
    sleep 2
}


install_singbox() {
    # 检查是否已安装 sing-box
    if [[ -e "$WORKDIR/list.txt" ]]; then
        yellow "已安装sing-box，请先选择2卸载，再执行安装" && exit 1
    fi

    yellow "为确保节点可用性，建议在Serv00网页不设置端口，脚本会随机生成有效端口"
    sleep 2

    # 切换到工作目录
    cd "$WORKDIR" || { red "无法切换到工作目录 $WORKDIR"; exit 1; }

    echo
    read_ip
    echo
    read_reym
    echo
    read_uuid
    echo
    check_port
    echo
    sleep 2
    argo_configure
    echo
    download_and_run_singbox
    echo
    servkeep
    echo
    get_links
    echo

    # 返回原目录
    cd || { red "无法返回原目录"; exit 1; }
}

uninstall_singbox() {
    reading "\n确定要卸载吗？【y/n】: " choice
    case "$choice" in
        [Yy])
            # 终止用户相关的进程
            bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill >/dev/null 2>&1'
            sleep 5  # 等待5秒，确保进程终止

            # 确认删除文件
            reading "确定要删除文件 domains, serv00.sh, serv00keep.sh 吗？【y/n】: " confirm_delete
            case "$confirm_delete" in
                [Yy])
                    rm -rf domains serv00.sh serv00keep.sh
                    green "文件已删除"
                    ;;
                [Nn])
                    yellow "文件未删除"
                    ;;
                *)
                    red "无效的选择，请输入y或n"
                    uninstall_singbox
                    return
                    ;;
            esac

            # 清除 crontab 中的 serv00keep 条目
            crontab -l | grep -v "serv00keep" | crontab -
            green "crontab 条目已清除"

            clear
            green "已完全卸载"
            ;;
        [Nn])
            exit 0
            ;;
        *)
            red "无效的选择，请输入y或n"
            uninstall_singbox
            ;;
    esac
}

kill_all_tasks() {
  read -p "\n清理所有进程并清空所有安装内容，将退出ssh连接，确定继续清理吗？【y/n】: " choice
  case "$choice" in
    [Yy])
      set -e  # 确保命令失败时立即退出
      pkill -u "$(whoami)" -o || true  # 安全地终止用户进程
      rm -rf domains serv00.sh serv00keep.sh  # 删除指定文件
      find ~ -type f \( -name "domains" -o -name "serv00.sh" -o -name "serv00keep.sh" \) -exec rm -f {} + 2>/dev/null
      find ~ -type d -empty -delete 2>/dev/null  # 删除空目录
      ;;
    *)
      menu
      ;;
  esac
}

# Generating argo Config
argo_configure() {
  while true; do
    yellow "方式一：Argo临时隧道 (无需域名，推荐)"
    yellow "方式二：Argo固定隧道 (需要域名，需要CF设置提取Token)"
    echo -e "${red}注意：${purple}Argo固定隧道使用Token时，需要在cloudflare后台设置隧道端口，该端口必须与vmess-ws的tcp端口 $vmess_port 一致)${re}"
    reading "输入 g 表示使用Argo固定隧道，回车跳过表示使用Argo临时隧道 【请选择 g 或者 回车】: " argo_choice
    if [[ "$argo_choice" != "g" && "$argo_choice" != "G" && -n "$argo_choice" ]]; then
        red "无效的选择，请输入 g 或回车"
        continue
    fi
    if [[ "$argo_choice" == "g" || "$argo_choice" == "G" ]]; then
        while true; do
            reading "请输入argo固定隧道域名: " ARGO_DOMAIN
            if [[ $ARGO_DOMAIN =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                break
            else
                red "无效的域名格式，请重新输入"
            fi
        done
        green "你的argo固定隧道域名为: $ARGO_DOMAIN"
        while true; do
            reading "请输入argo固定隧道密钥（当你粘贴Token时，必须以ey开头）: " ARGO_AUTH
            if [[ $ARGO_AUTH =~ ^ey[a-zA-Z0-9_-]+$ ]]; then
                break
            else
                red "无效的Token格式，请重新输入"
            fi
        done
        green "你的argo固定隧道密钥为: $ARGO_AUTH"
    else
        green "使用Argo临时隧道"
    fi
    break
  done

  if [[ $ARGO_AUTH =~ TunnelSecret ]]; then
    # 使用mktemp创建临时文件，并进行原子写入
    local tmp_json=$(mktemp)
    local tmp_yml=$(mktemp)
    echo "$ARGO_AUTH" > "$tmp_json"
    cat > "$tmp_yml" << EOF
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
    mv "$tmp_json" tunnel.json
    mv "$tmp_yml" tunnel.yml
    if [[ $? -ne 0 ]]; then
        red "文件写入失败，请检查权限或磁盘空间"
        return 1
    fi
  fi
}


# Download Dependency Files
download_and_run_singbox() {
  ARCH=$(uname -m) && DOWNLOAD_DIR="." && mkdir -p "$DOWNLOAD_DIR" && FILE_INFO=()

  # 支持更多架构
  case "$ARCH" in
    arm|arm64|aarch64)
      FILE_INFO=("https://github.com/eooce/test/releases/download/arm64/sb web" "https://github.com/eooce/test/releases/download/arm64/bot13 bot")
      ;;
    amd64|x86_64|x86)
      FILE_INFO=("https://github.com/yonggekkk/Cloudflare_vless_trojan/releases/download/serv00/sb web" "https://github.com/yonggekkk/Cloudflare_vless_trojan/releases/download/serv00/server bot")
      ;;
    *)
      echo "Unsupported architecture: $ARCH"
      exit 1
      ;;
  esac

  declare -A FILE_MAP

  generate_random_name() {
    local chars=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
    local name=""
    for i in {1..6}; do
      name="$name${chars:RANDOM%${#chars}:1}"
    done
    echo "$name"
  }

  download_with_fallback() {
    local URL=$1
    local NEW_FILENAME=$2
    local MAX_RETRIES=3
    local RETRY_DELAY=2

    for ((i=1; i<=MAX_RETRIES; i++)); do
      if curl -L -sS --max-time 2 -o "$NEW_FILENAME" "$URL"; then
        echo -e "\e[1;32mDownloading $NEW_FILENAME by curl\e[0m"
        return 0
      elif wget -q -O "$NEW_FILENAME" "$URL"; then
        echo -e "\e[1;32mDownloading $NEW_FILENAME by wget\e[0m"
        return 0
      else
        echo "Download attempt $i failed, retrying in $RETRY_DELAY seconds..."
        sleep $RETRY_DELAY
      fi
    done
    echo "Failed to download $URL after $MAX_RETRIES attempts."
    return 1
  }

  for entry in "${FILE_INFO[@]}"; do
    URL=$(echo "$entry" | cut -d ' ' -f 1)
    RANDOM_NAME=$(generate_random_name)
    NEW_FILENAME="$DOWNLOAD_DIR/$RANDOM_NAME"

    if [ -e "$NEW_FILENAME" ]; then
      echo -e "\e[1;32m$NEW_FILENAME already exists, Skipping download\e[0m"
    else
      if ! download_with_fallback "$URL" "$NEW_FILENAME"; then
        echo "Failed to download $URL"
        exit 1
      fi
    fi

    chmod +x "$NEW_FILENAME"
    FILE_MAP[$(echo "$entry" | cut -d ' ' -f 2)]="$NEW_FILENAME"
  done

  output=$("${FILE_MAP[web]}" generate reality-keypair)
  private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
  public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')
  echo "${private_key}" > private_key.txt
  echo "${public_key}" > public_key.txt

  openssl ecparam -genkey -name prime256v1 -out "private.key"
  openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=${USERNAME:-serv00}.serv00.net"

  nb=$(hostname | cut -d '.' -f 1 | tr -d 's')
  ytb=$(if [ "$nb" == "14" ] || [ "$nb" == "15" ]; then echo '"jnn-pa.googleapis.com",'; fi)

  hy_ips=($(sed -n '1,3p' hy2ip.txt))
  hy_ports=($hy2_port $hy2_port $hy2_port)

  cat > config.json << EOF
{
  "log": {
    "disabled": true,
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    $(for i in {0..2}; do
      cat << INBOUNDS
    {
       "tag": "hysteria-in",
       "type": "hysteria2",
       "listen": "${hy_ips[i]}",
       "listen_port": ${hy_ports[i]},
       "users": [
         {
             "password": "$UUID"
         }
     ],
     "masquerade": "https://www.bing.com",
     "ignore_client_bandwidth":false,
     "tls": {
         "enabled": true,
         "alpn": [
             "h3"
         ],
         "certificate_path": "cert.pem",
         "key_path": "private.key"
        }
    }$(if [ $i -lt 2 ]; then echo ","; fi)
INBOUNDS
    done),
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

  sbb=$(basename "${FILE_MAP[web]}")
  nohup "./$sbb" run -c config.json >/dev/null 2>&1 &
  sleep 5

  if pgrep -x "$sbb" > /dev/null; then
    green "$sbb 主进程已启动"
  else
    for ((i=1; i<=5; i++)); do
      red "$sbb 主进程未启动, 重启中... (尝试次数: $i)"
      pkill -x "$sbb"
      nohup "./$sbb" run -c config.json >/dev/null 2>&1 &
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

  agg=$(basename "${FILE_MAP[bot]}")
  rm -rf boot.log

  if [[ $ARGO_AUTH =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
    args="tunnel --no-autoupdate run --token ${ARGO_AUTH}"
  elif [[ $ARGO_AUTH =~ TunnelSecret ]]; then
    args="tunnel --edge-ip-version auto --config tunnel.yml run"
  else
    args="tunnel --url http://localhost:$vmess_port --no-autoupdate --logfile boot.log --loglevel info"
  fi

  nohup "./$agg" $args >/dev/null 2>&1 &
  sleep 10

  if pgrep -x "$agg" > /dev/null; then
    green "$agg Argo进程已启动"
  else
    red "$agg Argo进程未启动, 重启中..."
    pkill -x "$agg"
    nohup "./$agg" "${args}" >/dev/null 2>&1 &
    sleep 5
    purple "$agg Argo进程已重启"
  fi

  sleep 2
  if ! pgrep -x "$sbb" > /dev/null; then
    red "主进程未启动，根据以下情况一一排查"
    yellow "1、网页端权限是否开启"
    yellow "2、网页后台删除所有端口，让脚本自动生成随机可用端口"
    yellow "3、选择5重置"
    yellow "4、当前Serv00服务器炸了？等会再试"
    red "5、以上都试了，哥直接躺平，交给进程保活，过会再来看"
    sleep 6
  fi
}

get_argodomain() {
  if [[ -n $ARGO_AUTH ]]; then
    echo "$ARGO_DOMAIN" > gdym.log
    echo "$ARGO_DOMAIN"
  else
    local retry=0
    local max_retries=6
    local argodomain=""

    # 检查 boot.log 文件是否存在
    if [[ ! -f boot.log ]]; then
      echo "boot.log 文件不存在或无法读取"
      argodomain="Argo临时域名暂时获取失败，Argo节点暂不可用"
      echo "$argodomain"
      return
    fi

    # 缓存 boot.log 文件内容
    local log_content=$(cat boot.log 2>/dev/null)

    while [[ $retry -lt $max_retries ]]; do
      ((retry++))

      # 提取 argodomain
      argodomain=$(echo "$log_content" | grep -a trycloudflare.com | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}')

      # 检查 argodomain 是否为空或无效
      if [[ -n $argodomain && $argodomain =~ ^[a-zA-Z0-9.-]+$ ]]; then
        break
      fi

      sleep 2
    done

    if [[ -z ${argodomain} ]]; then
      argodomain="Argo临时域名暂时获取失败，Argo节点暂不可用"
    fi

    echo "$argodomain"
  fi
}

get_links() {
    # 获取 Argo 域名并输出
    argodomain=$(get_argodomain)
    echo -e "\e[1;32mArgo域名：\e[1;35m${argodomain}\e[0m\n"

    # 获取 ISP 并处理异常
    ISP=$(curl -sL --max-time 5 https://speed.cloudflare.com/meta | awk -F\" '{print $26}' | sed -e 's/ /_/g' || echo "unknown")

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

    # 创建临时文件用于存储链接
    temp_file=$(mktemp)

    # 定义生成链接的函数
    generate_link() {
        local protocol=$1
        local server=$2
        local port=$3
        local path=$4
        local tls=$5
        local sni=$6
        local fp=$7
        local ps=$8

        local link="${protocol}://${UUID}@${server}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${reym}&fp=chrome&pbk=${public_key}&type=tcp&headerType=none#${ps}-reality"
        echo "$link" >> "$temp_file"
    }

    # 生成 Vless 链接
    generate_link "vless" "$IP" "$vless_port" "/$UUID-vm?ed=2048" "tls" "$reym" "chrome" "$NAME"

    # 生成 Vmess-ws 链接
    vmws_link="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-ws\", \"add\": \"$IP\", \"port\": \"$vmess_port\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\", \"sni\": \"\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)"
    echo "$vmws_link" >> "$temp_file"

    # 生成 Vmess-ws-tls-argo 链接
    vmatls_link="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-ws-tls-argo\", \"add\": \"icook.hk\", \"port\": \"8443\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$argodomain\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)"
    echo "$vmatls_link" >> "$temp_file"

    # 生成 Vmess-ws-argo 链接
    vma_link="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-ws-argo\", \"add\": \"icook.hk\", \"port\": \"8880\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)"
    echo "$vma_link" >> "$temp_file"

    # 生成 Hysteria2 链接
    hy2_link="hysteria2://$UUID@$IP:$hy2_port?sni=www.bing.com&alpn=h3&insecure=1#$NAME-hy2"
    echo "$hy2_link" >> "$temp_file"

    # 读取临时文件内容并进行 Base64 编码
    url=$(cat "$temp_file" 2>/dev/null)
    baseurl=$(echo -e "$url" | base64 -w 0)

    # 生成 sing_box.json 和 clash_meta.yaml 文件
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

showlist() {
    if [[ -f "$WORKDIR/list.txt" ]]; then
        green "查看节点及proxyip/非标端口反代ip信息"
        if ! cat "$WORKDIR/list.txt"; then
            red "无法读取文件 $WORKDIR/list.txt" && exit 1
        fi
    else
        red "未安装sing-box 或 文件不存在" && exit 1
    fi
}

showsbclash() {
    # 检查 WORKDIR 是否为空或包含非法字符
    if [[ -z "$WORKDIR" || "$WORKDIR" =~ [^a-zA-Z0-9_\-/.] ]]; then
        red "WORKDIR 路径不合法" && exit 1
    fi

    # 定义一个函数来处理文件显示逻辑
    show_config_file() {
        local file_path="$1"
        local file_name="$2"

        if [[ -e "$file_path" ]]; then
            green "${file_name}配置文件如下，可上传到订阅类客户端上使用："
            yellow "其中Argo节点为CDN优选IP节点，server地址可自行修改优选IP/域名，被墙依旧能用！"
            sleep 2
            cat "$file_path"
            echo
        else
            red "未找到${file_name}配置文件" && exit 1
        fi
    }

    if [[ -e "$WORKDIR/sing_box.json" ]]; then
        show_config_file "$WORKDIR/sing_box.json" "Sing_box"
        show_config_file "$WORKDIR/clash_meta.yaml" "Clash_meta"
    else
        red "未安装sing-box" && exit 1
    fi
}

servkeep() {
    # 定义常量和变量
    local SCRIPT_URL="https://raw.githubusercontent.com/yonggekkk/sing-box-yg/master/serv00keep.sh"
    local APP_JS_URL="https://raw.githubusercontent.com/yonggekkk/sing-box-yg/master/app.js"
    local KEEP_PATH="$HOME/domains/${USERNAME}.${USERNAME}.serv00.net/public_nodejs"
    local LOG_FILE="$WORKDIR/boot.log"

    # 下载并设置权限
    curl -sSL "$SCRIPT_URL" -o serv00keep.sh && chmod +x serv00keep.sh

    # 替换变量值
    sed -i '' -e "14s|''|'$(printf %q "$UUID")'|" serv00keep.sh
    sed -i '' -e "17s|''|'$(printf %q "$vless_port")'|" serv00keep.sh
    sed -i '' -e "18s|''|'$(printf %q "$vmess_port")'|" serv00keep.sh
    sed -i '' -e "19s|''|'$(printf %q "$hy2_port")'|" serv00keep.sh
    sed -i '' -e "20s|''|'$(printf %q "$IP")'|" serv00keep.sh
    sed -i '' -e "21s|''|'$(printf %q "$reym")'|" serv00keep.sh

    if [ ! -f "$LOG_FILE" ]; then
        sed -i '' -e "15s|''|'$(printf %q "${ARGO_DOMAIN}")'|" serv00keep.sh
        sed -i '' -e "16s|''|'$(printf %q "${ARGO_AUTH}")'|" serv00keep.sh
    fi

    # 安装网页进程保活
    green "开始安装网页进程保活"
    mkdir -p "$KEEP_PATH"
    curl -sL "$APP_JS_URL" -o "$KEEP_PATH"/app.js

    # 替换 app.js 中的变量值
    sed -i '' "28s/name/$(printf %q "$USERNAME")/g" "$KEEP_PATH"/app.js
    sed -i '' "22s/name/$(printf %q "$snb")/g" "$KEEP_PATH"/app.js

    # 配置 web 服务
    devil www del ${USERNAME}.${USERNAME}.serv00.net > /dev/null 2>&1
    devil www add ${USERNAME}.serv00.net php > /dev/null 2>&1
    devil www add ${USERNAME}.${USERNAME}.serv00.net nodejs /usr/local/bin/node18 > /dev/null 2>&1

    # 设置 Node.js 环境
    ln -fs /usr/local/bin/node18 ~/bin/node > /dev/null 2>&1
    ln -fs /usr/local/bin/npm18 ~/bin/npm > /dev/null 2>&1
    mkdir -p ~/.npm-global
    npm config set prefix '~/.npm-global'
    echo 'export PATH=~/.npm-global/bin:~/bin:$PATH' >> $HOME/.bash_profile && source $HOME/.bash_profile
    rm -rf $HOME/.npmrc > /dev/null 2>&1

    # 安装依赖并清理
    cd "$KEEP_PATH"
    npm install basic-auth express dotenv axios --silent > /dev/null 2>&1
    rm -f $HOME/domains/${USERNAME}.${USERNAME}.serv00.net/public_nodejs/public/index.html > /dev/null 2>&1
    devil www restart ${USERNAME}.${USERNAME}.serv00.net
    rm -rf $HOME/domains/${USERNAME}.${USERNAME}.serv00.net/logs/*

    green "安装完毕，保活网页：http://${USERNAME}.${USERNAME}.serv00.net/up" && sleep 2
}

okip() {
    # 检查依赖工具是否存在
    if ! command -v jq &> /dev/null || ! command -v curl &> /dev/null; then
        echo "Error: jq or curl is not installed" >&2
        return 1
    fi

    # 获取 IP 列表并验证
    IP_LIST=($(devil vhost list | awk '/^[0-9]+/ {print $1}'))
    if [ ${#IP_LIST[@]} -lt 3 ]; then
        echo "Error: IP list contains fewer than 3 elements" >&2
        return 1
    fi

    API_URL="https://status.eooce.com/api"
    check_ip_status() {
        local ip=$1
        RESPONSE=$(curl -s --max-time 2 "${API_URL}/${ip}")
        if [[ $(echo "$RESPONSE" | jq -r '.status') == "Available" ]]; then
            echo "$ip"
            return 0
        else
            return 1
        fi
    }

    # 尝试获取第三个 IP
    THIRD_IP=${IP_LIST[2]}
    if IP=$(check_ip_status "$THIRD_IP"); then
        echo "$IP"
        return 0
    fi

    # 尝试获取第一个 IP
    FIRST_IP=${IP_LIST[0]}
    if IP=$(check_ip_status "$FIRST_IP"); then
        echo "$IP"
        return 0
    fi

    # 使用第二个 IP
    IP=${IP_LIST[1]}
    echo "$IP"
}

#主菜单
menu() {
   clear
   echo "============================================================"
   purple "修改自Serv00|ct8老王sing-box安装脚本"
   purple "转载请著名出自老王，请勿滥用"
   green "甬哥Github项目  ：github.com/yonggekkk"
   green "甬哥Blogger博客 ：ygkkk.blogspot.com"
   green "甬哥YouTube频道 ：www.youtube.com/@ygkkk"
   green "一键三协议共存：vless-reality、Vmess-ws(Argo)、hysteria2"
   green "当前脚本版本：V25.1.27  快捷方式：bash serv00.sh"
   echo   "============================================================"
   green  "1. 安装sing-box"
   echo   "------------------------------------------------------------"
   red    "2. 卸载sing-box"
   echo   "------------------------------------------------------------"
   green  "3. 查看：各节点分享/sing-box与clash-meta订阅链接/CF节点proxyip"
   echo   "------------------------------------------------------------"
   green  "4. 查看：sing-box与clash-meta配置文件"
   echo   "------------------------------------------------------------"
   yellow "5. 重置并清理所有服务进程(系统初始化)"
   echo   "------------------------------------------------------------"
   red    "0. 退出脚本"
   echo   "============================================================"

   local nb=$(echo "$HOSTNAME" | cut -d '.' -f 1 | tr -d 's')
   local ym=("$HOSTNAME" "cache$nb.serv00.com" "web$nb.serv00.com")

   # 清理旧文件
   rm -rf $WORKDIR/ip.txt $WORKDIR/hy2ip.txt

   # 获取IP地址
   for ip in "${ym[@]}"; do
       dig @8.8.8.8 +time=2 +short $ip >> $WORKDIR/hy2ip.txt || true
       sleep 1
   done

   # 获取响应并处理
   for domain in "${ym[@]}"; do
       local response=$(curl -sL --connect-timeout 5 --max-time 7 "https://ss.botai.us.kg/api/getip?host=$domain")
       if [[ -z "$response" || "$response" == *unknown* ]]; then
           dig @8.8.8.8 +time=2 +short $domain >> $WORKDIR/ip.txt || true
       else
           echo "$response" | while IFS='|' read -r ip status; do
               if [[ $status == "Accessible" ]]; then
                   echo "$ip: 可用" >> $WORKDIR/ip.txt
               else
                   echo "$ip: 被墙 (Argo与CDN回源节点、proxyip依旧有效)" >> $WORKDIR/ip.txt
               fi
           done
       fi
       sleep 1
   done

   # 输出信息
   green "Serv00服务器名称：$snb"
   green "当前可选择的IP如下："
   cat $WORKDIR/ip.txt
   echo

   if [[ -e $WORKDIR/list.txt ]]; then
       green "已安装sing-box"

       local is_running=$(ps aux | grep '[r]un -c con' > /dev/null && echo "true" || echo "false")
       if [[ $is_running == "true" ]]; then
           green "主进程运行正常"
       else
           yellow "主进程未启动…………请刷新一下保活网页"
       fi

       if [ -f "$WORKDIR/boot.log" ] && grep -q "trycloudflare.com" "$WORKDIR/boot.log" 2>/dev/null && ps aux | grep '[t]unnel --u' > /dev/null; then
           local argosl=$(grep -a trycloudflare.com "$WORKDIR/boot.log" | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}')
           local checkhttp=$(curl -o /dev/null -s -w "%{http_code}\n" "https://$argosl")
           local check="域名有效"
           [[ "$checkhttp" -ne 404 ]] && check="域名可能无效"
           green "当前Argo临时域名：$argosl  $check"
       elif [ -f "$WORKDIR/boot.log" ] && ! ps aux | grep '[t]unnel --u' > /dev/null; then
           yellow "当前Argo临时域名暂时不存在，请刷新一下保活网页，稍后可再次进入脚本查看"
       fi

       if ps aux | grep '[t]unnel --n' > /dev/null; then
           local argogd=$(cat $WORKDIR/gdym.log 2>/dev/null)
           local checkhttp=$(curl --max-time 2 -o /dev/null -s -w "%{http_code}\n" "https://$argogd")
           local check="域名有效"
           [[ "$checkhttp" -ne 404 ]] && check="域名可能失效"
           green "当前Argo固定域名：$argogd $check"
       elif [ ! -f "$WORKDIR/boot.log" ] && ! ps aux | grep '[t]unnel --n' > /dev/null; then
           yellow "当前Argo固定域名：$(cat $WORKDIR/gdym.log 2>/dev/null)，启用失败，请检查相关参数是否输入有误"
       fi

       green "保活网页：http://${USERNAME}.${USERNAME}.serv00.net/up"
   else
       red "未安装sing-box，请选择 1 进行安装"
   fi

   curl -sSL https://raw.githubusercontent.com/yonggekkk/sing-box-yg/master/serv00.sh -o serv00.sh && chmod +x serv00.sh

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
