#!/bin/bash

dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
=============================================

clear

function import_data() {
    export RED="\033[0;31m"
    export GREEN="\033[0;32m"
    export YELLOW="\033[0;33m"
    export BLUE="\033[0;34m"
    export PURPLE="\033[0;35m"
    export CYAN="\033[0;36m"
    export LIGHT="\033[0;37m"
    export NC="\033[0m"
    export ERROR="[${RED} ERROR ${NC}]"
    export INFO="[${YELLOW} INFO ${NC}]"
    export FAIL="[${RED} FAIL ${NC}]"
    export OKEY="[${GREEN} OKEY ${NC}]"
    export PENDING="[${YELLOW} PENDING ${NC}]"
    export SEND="[${YELLOW} SEND ${NC}]"
    export RECEIVE="[${YELLOW} RECEIVE ${NC}]"
    export RED_BG="\e[41m"
    export BOLD="\e[1m"
    export WARNING="${RED}\e[5m"
    export UNDERLINE="\e[4m"
}

import_data

BURIQ () {
    curl -sS https://raw.githubusercontent.com/iyalucu51/getxserv/main/ip.txt > /root/tmp
    data=( `cat /root/tmp | grep -E "^### " | awk '{print $2}'` )
    for user in "${data[@]}"
    do
    exp=( `grep -E "^### $user" "/root/tmp" | awk '{print $3}'` )
    d1=(`date -d "$exp" +%s`)
    d2=(`date -d "$biji" +%s`)
    exp2=$(( (d1 - d2) / 86400 ))
    if [[ "$exp2" -le "0" ]]; then
    echo $user > /etc/.$user.ini
    else
    rm -f /etc/.$user.ini > /dev/null 2>&1
    fi
    done
    rm -f /root/tmp
}

MYIP=$(curl -sS ipv4.icanhazip.com)
Name=$(curl -sS https://raw.githubusercontent.com/iyalucu51/getxserv/main/ip.txt | grep $MYIP | awk '{print $2}')
Isadmin=$(curl -sS https://raw.githubusercontent.com/iyalucu51/getxserv/main/ip.txt | grep $MYIP | awk '{print $5}')
echo $Name > /usr/local/etc/.$Name.ini
CekOne=$(cat /usr/local/etc/.$Name.ini)

Bloman () {
if [ -f "/etc/.$Name.ini" ]; then
CekTwo=$(cat /etc/.$Name.ini)
    if [ "$CekOne" = "$CekTwo" ]; then
        res="Expired"
    fi
else
res="Permission Accepted..."
fi
}

PERMISSION () {
    MYIP=$(curl -sS ipv4.icanhazip.com)
    IZIN=$(curl -sS https://raw.githubusercontent.com/iyalucu51/getxserv/main/ip.txt | awk '{print $4}' | grep $MYIP)
    if [ "$MYIP" = "$IZIN" ]; then
    Bloman
    else
    res="Permission Denied!"
    fi
    BURIQ
}

x="ok"


PERMISSION

if [ "$res" = "Expired" ]; then
Exp="\e[36mExpired\033[0m"
rm -f /home/needupdate > /dev/null 2>&1
else
Exp=$(curl -sS https://raw.githubusercontent.com/iyalucu51/getxserv/main/ip.txt | grep $MYIP | awk '{print $3}')
fi
export RED='\033[0;31m'
export GREEN='\033[0;32m'

crod=$( systemctl status cron | grep Active | awk '{print $3}' | sed 's/(//g' | sed 's/)//g' )
if [[ $crod == "running" ]]; then
BCD1="${GREEN}ON${NC}"
else
BCD1="${RED}OFF${NC}"
fi

ngtd=$( systemctl status nginx | grep Active | awk '{print $3}' | sed 's/(//g' | sed 's/)//g' )
if [[ $ngtd == "running" ]]; then
BCD2="${GREEN}ON${NC}"
else
BCD2="${RED}OFF${NC}"
fi

xr=$( systemctl status xray@tls | grep Active | awk '{print $3}' | sed 's/(//g' | sed 's/)//g' )
if [[ $xr == "running" ]]; then
BCD3="${GREEN}ON${NC}"
else
BCD3="${RED}OFF${NC}"
fi

if [ "$Isadmin" = "ON" ]; then
cit="${GREEN}PREMIUM${NC}"
else
cit="${RED}FREE{$NC}"
fi

echo -e ""
echo -e "  ${YELLOW}---------==[${NC} ${RED}PREMIUM PANEL MENU${NC} ${YELLOW}]==--------- ${NC}"
echo -e ""
DOMAIN=$(cat /etc/xray/domain.conf)
ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10 )
CITY=$(curl -s ipinfo.io/city )
WKT=$(curl -s ipinfo.io/timezone )
IP=$(curl -s ipinfo.io/ip )
JAM=$(date +"%T")
HARI=$(date +"%A")
TGL=$(date +"%d-%B-%Y")
echo -e "        ${GREEN} ISP NAME${NC}${LIGHT}  : ${ISP} ${NC}"
echo -e "        ${GREEN} DOMAIN${NC}${LIGHT}    : ${DOMAIN} ${NC}"
echo -e "        ${GREEN} IP SERVER${NC}${LIGHT} : ${IP} ${NC}"
echo -e "        ${GREEN} DAY${NC}${LIGHT}       : ${HARI} ${NC}"
echo -e "        ${GREEN} DATE${NC}${LIGHT}      : ${TGL} ${NC}"
echo -e "        ${GREEN} TIME${NC}${LIGHT}      : ${JAM} ${NC}"
echo -e "        ${GREEN} CITY${NC}${LIGHT}      : ${CITY} ${NC}"
echo -e "        ${GREEN} TIMEZONE${NC}${LIGHT}  : ${WKT} ${NC}"
echo -e ""
echo -e "  ${YELLOW}-------------------------------------------- ${NC}"
echo -e "  ${LIGHT}  CRON :${NC} $BCD1      ${LIGHT}NGINX :${NC} $BCD2      ${LIGHT}XRAY :${NC} $BCD3"
echo -e "  ${YELLOW}-------------------------------------------- ${NC}"
echo -e ""
echo -e "  ${YELLOW}------------==[${NC} ${RED}XRAY SERVICE${NC} ${YELLOW}]==------------ ${NC}"
echo -e ""
echo -e "    ${GREEN} 1${NC}${LIGHT}). PANEL XRAY${NC}"
echo -e "    ${GREEN} 2${NC}${LIGHT}). PANEL SHADOWSOCKS${NC}"
echo -e "    ${GREEN} 3${NC}${LIGHT}). PANEL TROJAN${NC}"
echo -e "    ${GREEN} 4${NC}${LIGHT}). PANEL VLESS${NC}"
echo -e "    ${GREEN} 5${NC}${LIGHT}). PANEL VMESS${NC}"
echo -e ""
echo -e "  ${YELLOW}------------==[${NC} ${RED}OPTIONS MENU${NC} ${YELLOW}]==------------ ${NC}"
echo -e ""
echo -e "    ${GREEN} 6${NC}${LIGHT}). ADD NEW SUBDOMAIN${NC}"
echo -e "    ${GREEN} 7${NC}${LIGHT}). RENEW CERT XRAY${NC}"
echo -e "    ${GREEN} 8${NC}${LIGHT}). SPEEDTEST SERVER${NC}"
echo -e "    ${GREEN} 9${NC}${LIGHT}). CHECK BANDWIDTH VPS${NC}"
echo -e "    ${GREEN}10${NC}${LIGHT}). CHECK RUNNING SERVICE${NC}"
echo -e "   ${GREEN} 11${NC}${LIGHT}). INFORMATION SCRIPT${NC}"
echo -e "   ${GREEN} 12${NC}${LIGHT}). REBOOT VPS${NC}"
echo -e ""
echo -e "  ${YELLOW}-------------------------------------------- ${NC}"
echo -e "    ${LIGHT}  ROLE : $cit    ${NC}${LIGHT}CLIENT NAME :${GREEN} $Name ${NC}"
echo -e "  ${YELLOW}-------------------------------------------- ${NC}"
echo -e ""
echo -e "    ${LIGHT} Select From Options ${NC}"
read -p "     [1-12 or type x to exit the menu] : " menuu
echo -e ""
case $menuu in
1)
function alm(){
#!/bin/sh

dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
=============================================

clear

function import_data() {
    export RED="\033[0;31m"
    export GREEN="\033[0;32m"
    export YELLOW="\033[0;33m"
    export BLUE="\033[0;34m"
    export PURPLE="\033[0;35m"
    export CYAN="\033[0;36m"
    export LIGHT="\033[0;37m"
    export NC="\033[0m"
    export ERROR="[${RED} ERROR ${NC}]"
    export INFO="[${YELLOW} INFO ${NC}]"
    export FAIL="[${RED} FAIL ${NC}]"
    export OKEY="[${GREEN} OKEY ${NC}]"
    export PENDING="[${YELLOW} PENDING ${NC}]"
    export SEND="[${YELLOW} SEND ${NC}]"
    export RECEIVE="[${YELLOW} RECEIVE ${NC}]"
    export RED_BG="\e[41m"
    export BOLD="\e[1m"
    export WARNING="${RED}\e[5m"
    export UNDERLINE="\e[4m"
}

import_data

function adal(){
#!/bin/sh

clear
IPNYA=$(wget --inet4-only -qO- https://ipinfo.io/ip)
ISPNYA=$(wget --inet4-only -qO- https://ipinfo.io/org | cut -d " " -f 2-100)

read -p "Username : " username
username="$(echo ${username} | sed 's/ //g' | tr -d '\r' | tr -d '\r\n')"

# // Validate Input
if [[ $username == "" ]]; then
    clear
    echo -e "${FAIL} Silakan Masukan Username terlebih dahulu !"
    exit 1
fi

# // Checking User already on vps or no
if [[ "$(cat /etc/xray/ss-client.conf | grep -w ${username})" != "" ]]; then
    clear
    echo -e "${FAIL} User [ ${Username} ] sudah ada !"
    exit 1
fi

# // Expired Date
read -p "Expired  : " Jumlah_Hari
exp=$(date -d "$Jumlah_Hari days" +"%Y-%m-%d")
hariini=$(date -d "0 days" +"%Y-%m-%d")

# // Get UUID
uuid=$(uuidgen)

# // Generate New UUID & Domain
domain=$(cat /etc/xray/domain.conf)


# // Getting Vmess port using grep from config
tls_port=$(cat /etc/xray/config/xray/tls.json | grep -w port | awk '{print $2}' | head -n1 | sed 's/,//g' | tr '\n' ' ' | tr -d '\r' | tr -d '\r\n' | sed 's/ //g')
nontls_port=$(cat /etc/xray/config/xray/nontls.json | grep -w port | awk '{print $2}' | head -n1 | sed 's/,//g' | tr '\n' ' ' | tr -d '\r' | tr -d '\r\n' | sed 's/ //g')

# // Input Your Data to server
cat /etc/xray/config/xray/tls.json | jq '.inbounds[7].settings.clients += [{"method": "'"aes-256-gcm"'","password": "'${uuid}'","email":"'${username}'" }]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq '.inbounds[8].settings.clients += [{"method": "'"aes-256-gcm"'","password": "'${uuid}'","email":"'${username}'" }]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
echo -e "Shadowsocks $username $exp $uuid" >>/etc/xray/ss-client.conf

# // Make Configruation Link
cipher="aes-256-gcm"
code=`echo -n $cipher:$uuid | base64`;
shadowsockslink="ss://${code}@$domain:$tls?plugin=xray-plugin;mux=0;path=/ss-ws;host=$domain;tls#${username}"
shadowsockslink1="ss://${code}@$domain:$tls?plugin=xray-plugin;mux=0;serviceName=ss-grpc;host=$domain;tls#${username}"

# // Restarting XRay Service
cat > /home/vps/public_html/ss-ws-$username.txt <<-END
{ 
 "dns": {
    "servers": [
      "8.8.8.8",
      "8.8.4.4"
    ]
  },
 "inbounds": [
   {
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true,
        "userLevel": 8
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls"
        ],
        "enabled": true
      },
      "tag": "socks"
    },
    {
      "port": 10809,
      "protocol": "http",
      "settings": {
        "userLevel": 8
      },
      "tag": "http"
    }
  ],
  "log": {
    "loglevel": "none"
  },
  "outbounds": [
    {
      "mux": {
        "enabled": true
      },
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          {
            "address": "$domain",
            "level": 8,
            "method": "$cipher",
            "password": "$uuid",
            "port": 443
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "allowInsecure": true,
          "serverName": "isi_bug_disini"
        },
        "wsSettings": {
          "headers": {
            "Host": "$domain"
          },
          "path": "/ss-ws"
        }
      },
      "tag": "proxy"
    },
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      },
      "tag": "block"
    }
  ],
  "policy": {
    "levels": {
      "8": {
        "connIdle": 300,
        "downlinkOnly": 1,
        "handshake": 4,
        "uplinkOnly": 1
      }
    },
    "system": {
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "routing": {
    "domainStrategy": "Asls",
"rules": []
  },
  "stats": {}
}
END
cat > /home/vps/public_html/ss-grpc-$username.txt <<-END
{
    "dns": {
    "servers": [
      "8.8.8.8",
      "8.8.4.4"
    ]
  },
 "inbounds": [
   {
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true,
        "userLevel": 8
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls"
        ],
        "enabled": true
      },
      "tag": "socks"
    },
    {
      "port": 10809,
      "protocol": "http",
      "settings": {
        "userLevel": 8
      },
      "tag": "http"
    }
  ],
  "log": {
    "loglevel": "none"
  },
  "outbounds": [
    {
      "mux": {
        "enabled": true
      },
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          {
            "address": "$domain",
            "level": 8,
            "method": "$cipher",
            "password": "$uuid",
            "port": 443
          }
        ]
      },
      "streamSettings": {
        "grpcSettings": {
          "multiMode": true,
          "serviceName": "ss-grpc"
        },
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "allowInsecure": true,
          "serverName": "isi_bug_disini"
        }
      },
      "tag": "proxy"
    },
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      },
      "tag": "block"
    }
  ],
  "policy": {
    "levels": {
      "8": {
        "connIdle": 300,
        "downlinkOnly": 1,
        "handshake": 4,
        "uplinkOnly": 1
      }
    },
    "system": {
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "routing": {
    "domainStrategy": "Asls",
"rules": []
  },
  "stats": {}
}
END

# // Input Your Data to server
cat /etc/xray/config/xray/tls.json | jq '.inbounds[0].settings.clients += [{"password": "'${uuid}'","flow": "xtls-rprx-direct","email":"'${username}'","level": 0 }]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq '.inbounds[1].settings.clients += [{"password": "'${uuid}'","email":"'${username}'" }]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq '.inbounds[4].settings.clients += [{"password": "'${uuid}'","email":"'${username}'" }]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
echo -e "Trojan $username $exp $uuid" >>/etc/xray/trojan-client.conf

# // Make Configruation Link
tgrpc_link="trojan://${uuid}@${domain}:${tls_port}?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc#${username}"
ttcp_tls_link="trojan://${uuid}@${domain}:${tls_port}?security=tls&headerType=none&type=tcp#${username}"
tws_tls_link="trojan://${uuid}@${domain}:${tls_port}?path=%2Ftrojan&security=tls&type=ws#${username}"

# // Input Your Data to server
cat /etc/xray/config/xray/tls.json | jq '.inbounds[3].settings.clients += [{"id": "'${uuid}'","email": "'${username}'"}]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq '.inbounds[6].settings.clients += [{"id": "'${uuid}'","email": "'${username}'"}]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/nontls.json | jq '.inbounds[1].settings.clients += [{"id": "'${uuid}'","email": "'${username}'"}]' >/etc/config/config/xray/nontls.json.tmp && mv /etc/xray/config/xray/nontls.json.tmp /etc/xray/config/xray/nontls.json
echo -e "Vless $username $exp $uuid" >>/etc/xray/vless-client.conf

# // Vless Link
vless_nontls="vless://${uuid}@${domain}:${nontls_port}?path=%2Fvless&security=none&encryption=none&type=ws#${username}"
vless_tls="vless://${uuid}@${domain}:${tls_port}?path=%2Fvless&security=tls&encryption=none&type=ws#${username}"
vless_grpc="vless://${uuid}@${domain}:${tls_port}?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc#${username}"

# // Input Your Data to server
cat /etc/xray/config/xray/tls.json | jq '.inbounds[2].settings.clients += [{"id": "'${uuid}'","email": "'${username}'","alterid": '"0"'}]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq '.inbounds[5].settings.clients += [{"id": "'${uuid}'","email": "'${username}'","alterid": '"0"'}]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/nontls.json | jq '.inbounds[0].settings.clients += [{"id": "'${uuid}'","email": "'${username}'","alterid": '"0"'}]' >/etc/xray/config/xray/nontls.json.tmp && mv /etc/xray/config/xray/nontls.json.tmp /etc/xray/config/xray/nontls.json
echo -e "Vmess $username $exp $uuid" >>/etc/xray/vmess-client.conf

cat >/etc/xray/xray-cache/vmess-tls-gun-$username.json <<END
{"add":"${domain}","aid":"0","host":"","id":"${uuid}","net":"grpc","path":"vmess-grpc","port":"${tls_port}","ps":"${username}","scy":"none","sni":"","tls":"tls","type":"gun","v":"2"}
END

cat >/etc/xray/xray-cache/vmess-tls-ws-$username.json <<END
{"add":"${domain}","aid":"0","host":"","id":"${uuid}","net":"ws","path":"/vmess","port":"${tls_port}","ps":"${username}","scy":"none","sni":"${domain}","tls":"tls","type":"","v":"2"}
END

cat >/etc/xray/xray-cache/vmess-nontls-$username.json <<END
{"add":"${domain}","aid":"0","host":"","id":"${uuid}","net":"ws","path":"/vmess","port":"${nontls_port}","ps":"${username}","scy":"none","sni":"","tls":"","type":"","v":"2"}
END

# // Vmess Link
grpc_link="vmess://$(base64 -w 0 /etc/xray/xray-cache/vmess-tls-gun-$username.json)"
ws_tls_link="vmess://$(base64 -w 0 /etc/xray/xray-cache/vmess-tls-ws-$username.json)"
ws_nontls_link="vmess://$(base64 -w 0 /etc/xray/xray-cache/vmess-nontls-$username.json)"

# // Restarting XRay Service
systemctl restart xray@tls
systemctl restart xray@nontls

# // Successfully
clear
echo -e "====================================="
echo -e "       XRAY ACCOUNT DETAILS"
echo -e "====================================="
echo -e " ISP              : ${ISPNYA}"
echo -e " Remarks          : ${username}"
echo -e " IP               : ${IPNYA}"
echo -e " Address          : ${domain}"
echo -e " Port TLS         : ${tls_port}"
echo -e " Port Non TLS     : ${nontls_port}"
echo -e " Password / UUID  : ${uuid}"
echo -e " Service          : TCP/WS/GRPC"
echo -e " Path SS WS       : /ss-ws"
echo -e " ServiceName GRPC : ss-grpc"
echo -e " Path Trojan WS   : /trojan"
echo -e " ServiceName GRPC : trojan-grpc"
echo -e " Path Vless WS    : /vless"
echo -e " ServiceName GRPC : vless-grpc"
echo -e " Path Vmess WS    : /vmess"
echo -e " ServiceName GRPC : vmess-grpc"
echo -e " Expired On       : ${exp}"
echo -e "====================================="
echo -e " SHADOWSOCKS WS LINK :"
echo -e " ${shadowsockslink}"
echo -e "-------------------------------------"
echo -e " SHADOWSOCKS GRPC TLS LINK :"
echo -e " ${shadowsockslink1}"
echo -e "-------------------------------------"
echo -e " CONFIG JSON SS WS TLS   :" 
echo -e " http://${domain}:81/ss-ws-$username.txt"
echo -e "-------------------------------------"
echo -e " CONFIG JSON SS GRPC :"
echo -e " http://${domain}:81/ss-grpc-$username.txt"
echo -e "====================================="
echo -e " TROJAN TCP TLS LINK :"
echo -e " ${ttcp_tls_link}"
echo -e "-------------------------------------"
echo -e " TROJAN WS TLS LINK :"
echo -e " ${tws_tls_link}"
echo -e "-------------------------------------"
echo -e " TROJAN GRPC LINK :"
echo -e " ${tgrpc_link}"
echo -e "====================================="
echo -e " VLESS WS TLS LINK :"
echo -e " ${vless_tls}"
echo -e "-------------------------------------"
echo -e " VLESS WS NTLS LINK :"
echo -e " ${vless_nontls}"
echo -e "-------------------------------------"
echo -e " VLESS GRPC LINK :"
echo -e " ${vless_grpc}"
echo -e "====================================="
echo -e " VMESS WS TLS LINK :"
echo -e " ${ws_tls_link}"
echo -e "-------------------------------------"
echo -e " VMESS WS NTLS LINK :"
echo -e " ${ws_nontls_link}"
echo -e "-------------------------------------"
echo -e " VMESS GRPC LINK"
echo -e " ${grpc_link}"
echo -e "====================================="
}

function deal(){
#!/bin/sh

clear
IPNYA=$(wget --inet4-only -qO- https://ipinfo.io/ip)
ISPNYA=$(wget --inet4-only -qO- https://ipinfo.io/org | cut -d " " -f 2-100)

# // Start
CLIENT_001=$(grep -c -E "^Shadowsocks " "/etc/xray/ss-client.conf")
echo "    =================================================="
echo "              LIST XRAY CLIENT ON THIS VPS"
echo "    =================================================="
grep -e "^Shadowsocks " "/etc/xray/ss-client.conf" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_002} -ge 1 && ${CLIENT_002} -le ${CLIENT_001} ]]; do
    if [[ ${CLIENT_002} == '1' ]]; then
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    else
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    fi
done

# // SS
client=$(grep "^Shadowsocks " "/etc/xray/ss-client.conf" | cut -d ' ' -f 2 | sed -n "${CLIENT_002}"p)
expired=$(grep "^Shadowsocks " "/etc/xray/ss-client.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_002}"p)

printf "y\n" | cp /etc/xray/config/xray/tls.json /etc/xray/xray-cache/cache-nya.json
cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[7].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[8].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json

sed -i "/\b$client\b/d" /etc/xray/ss-client.conf
rm -f /home/vps/public_html/ss-gr-${client}.txt
rm -f /home/vps/public_html/ss-ws-${client}.txt

# // TROJAN
client=$(grep "^Trojan " "/etc/xray/trojan-client.conf" | cut -d ' ' -f 2 | sed -n "${CLIENT_002}"p)
expired=$(grep "^Trojan " "/etc/xray/trojan-client.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_002}"p)

printf "y\n" | cp /etc/xray/config/xray/tls.json /etc/xray/xray-cache/cache-nya.json
cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[0].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[1].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[4].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json

sed -i "/\b$client\b/d" /etc/xray/trojan-client.conf

# // VLESS
client=$(grep "^Vless " "/etc/xray/vless-client.conf" | cut -d ' ' -f 2 | sed -n "${CLIENT_002}"p)
expired=$(grep "^Vless " "/etc/xray/vless-client.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_002}"p)

cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[3].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[6].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/nontls.json | jq 'del(.inbounds[1].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/nontls.json.tmp && mv /etc/xray/config/xray/nontls.json.tmp /etc/xray/config/xray/nontls.json

sed -i "/\b$client\b/d" /etc/xray/vless-client.conf

# // VMESS
client=$(grep "^Vmess " "/etc/xray/vmess-client.conf" | cut -d ' ' -f 2 | sed -n "${CLIENT_002}"p)
expired=$(grep "^Vmess " "/etc/xray/vmess-client.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_002}"p)

cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[2].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[5].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/nontls.json | jq 'del(.inbounds[0].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/nontls.json.tmp && mv /etc/xray/config/xray/nontls.json.tmp /etc/xray/config/xray/nontls.json
rm -f /etc/xray/xray-cache/vmess-tls-gun-$client.json /etc/xray/xray-cache/vmess-tls-ws-$client.json /etc/xray/xray-cache/vmess-nontls-$client.json
sed -i "/\b$client\b/d" /etc/xray/vmess-client.conf

systemctl restart xray@tls
systemctl restart xray@nontls

clear
echo -e "${OKEY} Username ( ${YELLOW}$client${NC} ) Has Been Removed !"
}

function real(){
#!/bin/sh

clear
IPNYA=$(wget --inet4-only -qO- https://ipinfo.io/ip)
ISPNYA=$(wget --inet4-only -qO- https://ipinfo.io/org | cut -d " " -f 2-100)

# // Start
CLIENT_001=$(grep -c -E "^Shadowsocks " "/etc/xray/ss-client.conf")
echo "    =================================================="
echo "              LIST XRAY CLIENT ON THIS VPS"
echo "    =================================================="
grep -e "^Shadowsocks " "/etc/xray/ss-client.conf" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_002} -ge 1 && ${CLIENT_002} -le ${CLIENT_001} ]]; do
    if [[ ${CLIENT_002} == '1' ]]; then
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    else
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    fi
done

# // String For Username && Expired Date
client=$(grep "^Shadowsocks " "/etc/xray/ss-client.conf" | cut -d ' ' -f 2 | sed -n "${CLIENT_002}"p)
expired=$(grep "^Shadowsocks " "/etc/xray/ss-client.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_002}"p)
uuidnta=$(grep "^Shadowsocks " "/etc/xray/ss-client.conf" | cut -d ' ' -f 4 | sed -n "${CLIENT_002}"p)

# // Extending Days
clear
read -p "Expired  : " Jumlah_Hari
if [[ $Jumlah_Hari == "" ]]; then
    clear
    echo -e "${FAIL} Mohon Masukan Jumlah Hari perpanjangan !"
    exit 1
fi

# // Date Configuration
now=$(date +%Y-%m-%d)
d1=$(date -d "$expired" +%s)
d2=$(date -d "$now" +%s)
exp2=$(((d1 - d2) / 86400))
exp3=$(($exp2 + $Jumlah_Hari))
exp4=$(date -d "$exp3 days" +"%Y-%m-%d")

# // SHADOWSOCKS
sed -i "/\b$client\b/d" /etc/xray/ss-client.conf
echo -e "Shadowsocks $client $exp4 $uuidnta" >>/etc/xray/ss-client.conf

# // TROJAN
sed -i "/\b$client\b/d" /etc/xray/trojan-client.conf
echo -e "Trojan $client $exp4 $uuidnta" >>/etc/xray/trojan-client.conf

# // VLESS
sed -i "/\b$client\b/d" /etc/xray/vless-client.conf
echo -e "Vless $client $exp4 $uuidnta" >>/etc/xray/vless-client.conf

# // VMESS
sed -i "/\b$client\b/d" /etc/xray/vmess-client.conf
echo -e "Vmess $client $exp4 $uuidnta" >>/etc/xray/vmess-client.conf

# // Clear
clear

# // Successfull
echo -e "${OKEY} User ( ${YELLOW}${client}${NC} ) Renewed Then Expired On ( ${YELLOW}$exp4${NC} )"
}

echo -e ""
echo -e " ${YELLOW} ----------==[${NC} ${RED}PANEL XRAY SERVICE${NC} ${YELLOW}]==---------- ${NC}"
echo -e ""
echo -e "    ${GREEN} 1${NC}${LIGHT})${NC} ${LIGHT}CREATE ALL USER${NC}"
echo -e "    ${GREEN} 2${NC}${LIGHT})${NC} ${LIGHT}DELETE ALL USER${NC}"
echo -e "    ${GREEN} 3${NC}${LIGHT})${NC} ${LIGHT}RENEW ALL USER${NC}"
echo -e " ${YELLOW} ---------------------------------------------- ${NC}"
echo -e "       ${GREEN} x${NC}${LIGHT})${NC} ${LIGHT}Exit or Back to main Menu${NC}"
echo -e " ${YELLOW} ---------------------------------------------- ${NC}"
echo -e ""
echo -e "    ${LIGHT} Select From Options ${NC}"
read -p "     [1-2 or type x to return to main menu] : "  menualm
echo -e ""
case $menualm in
1)
adal
echo ""
read -p "Click Enter To Return To The Menu..."
clear
alm
;;
2)
deal
echo ""
read -p "Click Enter To Return To The Menu..."
clear
alm
;;
3)
real
echo ""
read -p "Click Enter To Return To The Menu..."
clear
alm
;;
x)
menu
;;
*)
alm
;;
esac
}
alm
echo ""
read -p "Click enter to return to the main menu..."
clear
menu
;;
2)
function ssw(){
#!/bin/sh

dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
=============================================

clear

function import_data() {
    export RED="\033[0;31m"
    export GREEN="\033[0;32m"
    export YELLOW="\033[0;33m"
    export BLUE="\033[0;34m"
    export PURPLE="\033[0;35m"
    export CYAN="\033[0;36m"
    export LIGHT="\033[0;37m"
    export NC="\033[0m"
    export ERROR="[${RED} ERROR ${NC}]"
    export INFO="[${YELLOW} INFO ${NC}]"
    export FAIL="[${RED} FAIL ${NC}]"
    export OKEY="[${GREEN} OKEY ${NC}]"
    export PENDING="[${YELLOW} PENDING ${NC}]"
    export SEND="[${YELLOW} SEND ${NC}]"
    export RECEIVE="[${YELLOW} RECEIVE ${NC}]"
    export RED_BG="\e[41m"
    export BOLD="\e[1m"
    export WARNING="${RED}\e[5m"
    export UNDERLINE="\e[4m"
}

import_data

function addss(){
#!/bin/sh

clear
IPNYA=$(wget --inet4-only -qO- https://ipinfo.io/ip)
ISPNYA=$(wget --inet4-only -qO- https://ipinfo.io/org | cut -d " " -f 2-100)

read -p "Username : " username
username="$(echo ${username} | sed 's/ //g' | tr -d '\r' | tr -d '\r\n')"

# // Validate Input
if [[ $username == "" ]]; then
    clear
    echo -e "${FAIL} Silakan Masukan Username terlebih dahulu !"
    exit 1
fi

# // Checking User already on vps or no
if [[ "$(cat /etc/xray/ss-client.conf | grep -w ${username})" != "" ]]; then
    clear
    echo -e "${FAIL} User [ ${Username} ] sudah ada !"
    exit 1
fi

# // Expired Date
read -p "Expired  : " Jumlah_Hari
exp=$(date -d "$Jumlah_Hari days" +"%Y-%m-%d")
hariini=$(date -d "0 days" +"%Y-%m-%d")

# // Get UUID
uuid=$(uuidgen)

# // Generate New UUID & Domain
domain=$(cat /etc/xray/domain.conf)


# // Getting Vmess port using grep from config
tls_port=443

# // Input Your Data to server
cat /etc/xray/config/xray/tls.json | jq '.inbounds[7].settings.clients += [{"method": "'"aes-256-gcm"'","password": "'${uuid}'","email":"'${username}'" }]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq '.inbounds[8].settings.clients += [{"method": "'"aes-256-gcm"'","password": "'${uuid}'","email":"'${username}'" }]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
echo -e "Shadowsocks $username $exp $uuid" >>/etc/xray/ss-client.conf

# // Make Configruation Link
cipher="aes-256-gcm"
code=`echo -n $cipher:$uuid | base64`;
shadowsockslink="ss://${code}@$domain:$tls?plugin=xray-plugin;mux=0;path=/ss-ws;host=$domain;tls#${username}"
shadowsockslink1="ss://${code}@$domain:$tls?plugin=xray-plugin;mux=0;serviceName=ss-grpc;host=$domain;tls#${username}"

# // Restarting XRay Service
systemctl restart xray@tls
cat > /home/vps/public_html/ss-ws-$username.txt <<-END
{ 
 "dns": {
    "servers": [
      "8.8.8.8",
      "8.8.4.4"
    ]
  },
 "inbounds": [
   {
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true,
        "userLevel": 8
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls"
        ],
        "enabled": true
      },
      "tag": "socks"
    },
    {
      "port": 10809,
      "protocol": "http",
      "settings": {
        "userLevel": 8
      },
      "tag": "http"
    }
  ],
  "log": {
    "loglevel": "none"
  },
  "outbounds": [
    {
      "mux": {
        "enabled": true
      },
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          {
            "address": "$domain",
            "level": 8,
            "method": "$cipher",
            "password": "$uuid",
            "port": 443
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "allowInsecure": true,
          "serverName": "isi_bug_disini"
        },
        "wsSettings": {
          "headers": {
            "Host": "$domain"
          },
          "path": "/ss-ws"
        }
      },
      "tag": "proxy"
    },
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      },
      "tag": "block"
    }
  ],
  "policy": {
    "levels": {
      "8": {
        "connIdle": 300,
        "downlinkOnly": 1,
        "handshake": 4,
        "uplinkOnly": 1
      }
    },
    "system": {
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "routing": {
    "domainStrategy": "Asls",
"rules": []
  },
  "stats": {}
}
END
cat > /home/vps/public_html/ss-grpc-$username.txt <<-END
{
    "dns": {
    "servers": [
      "8.8.8.8",
      "8.8.4.4"
    ]
  },
 "inbounds": [
   {
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true,
        "userLevel": 8
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls"
        ],
        "enabled": true
      },
      "tag": "socks"
    },
    {
      "port": 10809,
      "protocol": "http",
      "settings": {
        "userLevel": 8
      },
      "tag": "http"
    }
  ],
  "log": {
    "loglevel": "none"
  },
  "outbounds": [
    {
      "mux": {
        "enabled": true
      },
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          {
            "address": "$domain",
            "level": 8,
            "method": "$cipher",
            "password": "$uuid",
            "port": 443
          }
        ]
      },
      "streamSettings": {
        "grpcSettings": {
          "multiMode": true,
          "serviceName": "ss-grpc"
        },
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "allowInsecure": true,
          "serverName": "isi_bug_disini"
        }
      },
      "tag": "proxy"
    },
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      },
      "tag": "block"
    }
  ],
  "policy": {
    "levels": {
      "8": {
        "connIdle": 300,
        "downlinkOnly": 1,
        "handshake": 4,
        "uplinkOnly": 1
      }
    },
    "system": {
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "routing": {
    "domainStrategy": "Asls",
"rules": []
  },
  "stats": {}
}
END

# // Successfully
clear
echo -e "==============================="
echo -e "  SHADOWSOCKS ACCOUNT DETAILS"
echo -e "==============================="
echo -e " ISP         : ${ISPNYA}"
echo -e " Remarks     : ${username}"
echo -e " IP          : ${IPNYA}"
echo -e " Address     : ${domain}"
echo -e " Port        : ${tls_port}"
echo -e " Password    : ${uuid}"
echo -e " Path WS     : /ss-ws"
echo -e " ServiceName : ss-grpc"
echo -e " Expired On  : ${exp}"
echo -e "==============================="
echo -e " SHADOWSOCKS GRPC LINK :"
echo -e " ${shadowsockslink1}"
echo -e "-------------------------------"
echo -e " SHADOWSOCKS WS TLS LINK :"
echo -e " ${shadowsockslink}"
echo -e "-------------------------------"
echo -e " CONFIG JSON WS TLS   :"
echo -e " http://${domain}:81/ss-ws-$username.txt"
echo -e "-------------------------------"
echo -e " CONFIG JSON GRPC TLS :"
echo -e " http://${domain}:81/ss-grpc-$username.txt"
echo -e "==============================="
}

function delss(){
#!/bin/sh

clear
IPNYA=$(wget --inet4-only -qO- https://ipinfo.io/ip)
ISPNYA=$(wget --inet4-only -qO- https://ipinfo.io/org | cut -d " " -f 2-100)

# // Start
CLIENT_001=$(grep -c -E "^Shadowsocks " "/etc/xray/ss-client.conf")
echo "    =================================================="
echo "              LIST Shadowsocks CLIENT ON THIS VPS"
echo "    =================================================="
grep -e "^Shadowsocks " "/etc/xray/ss-client.conf" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_002} -ge 1 && ${CLIENT_002} -le ${CLIENT_001} ]]; do
    if [[ ${CLIENT_002} == '1' ]]; then
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    else
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    fi
done

client=$(grep "^Shadowsocks " "/etc/xray/ss-client.conf" | cut -d ' ' -f 2 | sed -n "${CLIENT_002}"p)
expired=$(grep "^Shadowsocks " "/etc/xray/ss-client.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_002}"p)

printf "y\n" | cp /etc/xray/config/xray/tls.json /etc/xray/xray-cache/cache-nya.json
cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[7].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[8].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json

sed -i "/\b$client\b/d" /etc/xray/ss-client.conf
rm -f /home/vps/public_html/ss-gr-${client}.txt
rm -f /home/vps/public_html/ss-ws-${client}.txt
systemctl restart xray@tls

clear
echo -e "${OKEY} Username ( ${YELLOW}$client${NC} ) Has Been Removed !"
}

function renewss(){
#!/bin/sh

clear
IPNYA=$(wget --inet4-only -qO- https://ipinfo.io/ip)
ISPNYA=$(wget --inet4-only -qO- https://ipinfo.io/org | cut -d " " -f 2-100)

# // Start
CLIENT_001=$(grep -c -E "^Shadowsocks " "/etc/xray/ss-client.conf")
echo "    =================================================="
echo "              LIST SHADOWSOCKS CLIENT ON THIS VPS"
echo "    =================================================="
grep -e "^Shadowsocks " "/etc/xray/ss-client.conf" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_002} -ge 1 && ${CLIENT_002} -le ${CLIENT_001} ]]; do
    if [[ ${CLIENT_002} == '1' ]]; then
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    else
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    fi
done

# // String For Username && Expired Date
client=$(grep "^Shadowsocks " "/etc/xray/ss-client.conf" | cut -d ' ' -f 2 | sed -n "${CLIENT_002}"p)
expired=$(grep "^Shadowsocks " "/etc/xray/ss-client.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_002}"p)
uuidnta=$(grep "^Shadowsocks " "/etc/xray/ss-client.conf" | cut -d ' ' -f 4 | sed -n "${CLIENT_002}"p)

# // Extending Days
clear
read -p "Expired  : " Jumlah_Hari
if [[ $Jumlah_Hari == "" ]]; then
    clear
    echo -e "${FAIL} Mohon Masukan Jumlah Hari perpanjangan !"
    exit 1
fi

# // Date Configuration
now=$(date +%Y-%m-%d)
d1=$(date -d "$expired" +%s)
d2=$(date -d "$now" +%s)
exp2=$(((d1 - d2) / 86400))
exp3=$(($exp2 + $Jumlah_Hari))
exp4=$(date -d "$exp3 days" +"%Y-%m-%d")

# // Input To System Configuration
sed -i "/\b$client\b/d" /etc/xray/ss-client.conf
echo -e "Shadowsocks $client $exp4 $uuidnta" >>/etc/xray/ss-client.conf

# // Clear
clear

# // Successfully
echo -e "${OKEY} User ( ${YELLOW}${client}${NC} ) Renewed Then Expired On ( ${YELLOW}$exp4${NC} )"
}

echo -e ""
echo -e " ${YELLOW} --------==[${NC} ${RED}PANEL XRAY SHADOWSOCKS${NC} ${YELLOW}]==-------- ${NC}"
echo -e ""
echo -e "    ${GREEN} 1${NC}${LIGHT})${NC} ${LIGHT}CREATE USER SHADOWSOCKS${NC}"
echo -e "    ${GREEN} 2${NC}${LIGHT})${NC} ${LIGHT}DELETE USER SHADOWSOCKS${NC}"
echo -e "    ${GREEN} 3${NC}${LIGHT})${NC} ${LIGHT}RENEW USER SHADOWSOCKS${NC}"
echo -e " ${YELLOW} ---------------------------------------------- ${NC}"
echo -e "       ${GREEN} x${NC}${LIGHT})${NC} ${LIGHT}Exit or Back to main Menu${NC}"
echo -e " ${YELLOW} ---------------------------------------------- ${NC}"
echo -e ""
echo -e "    ${LIGHT} Select From Options ${NC}"
read -p "     [1-3 or type x to return to main menu] : "  menuss
echo -e ""
case $menuss in
1)
addss
echo ""
read -p "Click Enter To Return To The Menu..."
clear
ssw
;;
2)
delss
echo ""
read -p "Click Enter To Return To The Menu..."
clear
ssw
;;
3)
renewss
echo ""
read -p "Click Enter To Return To The Menu..."
clear
ssw
;;
x)
menu
;;
*)
ssw
;;
esac
}
ssw
echo ""
read -p "Click enter to return to the main menu..."
clear
menu
;;
3)
function mtr(){
#!/bin/sh

dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
=============================================

clear

function import_data() {
    export RED="\033[0;31m"
    export GREEN="\033[0;32m"
    export YELLOW="\033[0;33m"
    export BLUE="\033[0;34m"
    export PURPLE="\033[0;35m"
    export CYAN="\033[0;36m"
    export LIGHT="\033[0;37m"
    export NC="\033[0m"
    export ERROR="[${RED} ERROR ${NC}]"
    export INFO="[${YELLOW} INFO ${NC}]"
    export FAIL="[${RED} FAIL ${NC}]"
    export OKEY="[${GREEN} OKEY ${NC}]"
    export PENDING="[${YELLOW} PENDING ${NC}]"
    export SEND="[${YELLOW} SEND ${NC}]"
    export RECEIVE="[${YELLOW} RECEIVE ${NC}]"
    export RED_BG="\e[41m"
    export BOLD="\e[1m"
    export WARNING="${RED}\e[5m"
    export UNDERLINE="\e[4m"
}

import_data

function addtr(){
#!/bin/sh

clear
IPNYA=$(wget --inet4-only -qO- https://ipinfo.io/ip)
ISPNYA=$(wget --inet4-only -qO- https://ipinfo.io/org | cut -d " " -f 2-100)

read -p "Username : " username
username="$(echo ${username} | sed 's/ //g' | tr -d '\r' | tr -d '\r\n')"

# // Validate Input
if [[ $username == "" ]]; then
    clear
    echo -e "${FAIL} Silakan Masukan Username terlebih dahulu !"
    exit 1
fi

# // Checking User already on vps or no
if [[ "$(cat /etc/xray/trojan-client.conf | grep -w ${username})" != "" ]]; then
    clear
    echo -e "${FAIL} User [ ${Username} ] sudah ada !"
    exit 1
fi

# // Expired Date
read -p "Expired  : " Jumlah_Hari
exp=$(date -d "$Jumlah_Hari days" +"%Y-%m-%d")
hariini=$(date -d "0 days" +"%Y-%m-%d")

# // Get UUID
uuid=$(uuidgen)

# // Generate New UUID & Domain
domain=$(cat /etc/xray/domain.conf)


# // Getting Vmess port using grep from config
tls_port=$(cat /etc/xray/config/xray/tls.json | grep -w port | awk '{print $2}' | head -n1 | sed 's/,//g' | tr '\n' ' ' | tr -d '\r' | tr -d '\r\n' | sed 's/ //g')

# // Input Your Data to server
cat /etc/xray/config/xray/tls.json | jq '.inbounds[0].settings.clients += [{"password": "'${uuid}'","flow": "xtls-rprx-direct","email":"'${username}'","level": 0 }]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq '.inbounds[1].settings.clients += [{"password": "'${uuid}'","email":"'${username}'" }]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq '.inbounds[4].settings.clients += [{"password": "'${uuid}'","email":"'${username}'" }]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
echo -e "Trojan $username $exp $uuid" >>/etc/xray/trojan-client.conf

# // Make Configruation Link
grpc_link="trojan://${uuid}@${domain}:${tls_port}?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc#${username}"
tcp_tls_link="trojan://${uuid}@${domain}:${tls_port}?security=tls&headerType=none&type=tcp#${username}"
ws_tls_link="trojan://${uuid}@${domain}:${tls_port}?path=%2Ftrojan&security=tls&type=ws#${username}"

# // Restarting XRay Service
systemctl restart xray@tls

# // Success
clear
echo -e "==============================="
echo -e "    TROJAN ACCOUNT DETAILS"
echo -e "==============================="
echo -e " ISP         : ${ISPNYA}"
echo -e " Remarks     : ${username}"
echo -e " IP          : ${IPNYA}"
echo -e " Address     : ${domain}"
echo -e " Port        : ${tls_port}"
echo -e " Password    : ${uuid}"
echo -e " Path WS     : /trojan"
echo -e " ServiceName : trojan-grpc"
echo -e " Expired On  : ${exp}"
echo -e "==============================="
echo -e " TROJAN TCP TLS LINK :"
echo -e " ${tcp_tls_link}"
echo -e "-------------------------------"
echo -e " TROJAN WS TLS LINK :"
echo -e " ${ws_tls_link}"
echo -e "-------------------------------"
echo -e " TROJAN GRPC LINK :"
echo -e " ${grpc_link}"
echo -e "==============================="
}

function deltr(){
#!/bin/sh

clear
IPNYA=$(wget --inet4-only -qO- https://ipinfo.io/ip)
ISPNYA=$(wget --inet4-only -qO- https://ipinfo.io/org | cut -d " " -f 2-100)

# // Start
CLIENT_001=$(grep -c -E "^Trojan " "/etc/xray/trojan-client.conf")
echo "    =================================================="
echo "              LIST TROJAN CLIENT ON THIS VPS"
echo "    =================================================="
grep -e "^Trojan " "/etc/xray/trojan-client.conf" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_002} -ge 1 && ${CLIENT_002} -le ${CLIENT_001} ]]; do
    if [[ ${CLIENT_002} == '1' ]]; then
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    else
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    fi
done

# // String For Username && Expired Date
client=$(grep "^Trojan " "/etc/xray/trojan-client.conf" | cut -d ' ' -f 2 | sed -n "${CLIENT_002}"p)
expired=$(grep "^Trojan " "/etc/xray/trojan-client.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_002}"p)

printf "y\n" | cp /etc/xray/config/xray/tls.json /etc/xray/xray-cache/cache-nya.json
cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[0].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[1].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[4].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json

sed -i "/\b$client\b/d" /etc/xray/trojan-client.conf
systemctl restart xray@tls
}

function renewtr(){
#!/bin/sh

clear
IPNYA=$(wget --inet4-only -qO- https://ipinfo.io/ip)
ISPNYA=$(wget --inet4-only -qO- https://ipinfo.io/org | cut -d " " -f 2-100)

# // Start
CLIENT_001=$(grep -c -E "^Trojan " "/etc/xray/trojan-client.conf")
echo "    =================================================="
echo "              LIST TROJAN CLIENT ON THIS VPS"
echo "    =================================================="
grep -e "^Trojan " "/etc/xray/trojan-client.conf" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_002} -ge 1 && ${CLIENT_002} -le ${CLIENT_001} ]]; do
    if [[ ${CLIENT_002} == '1' ]]; then
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    else
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    fi
done

# // String For Username && Expired Date
client=$(grep "^Trojan " "/etc/xray/trojan-client.conf" | cut -d ' ' -f 2 | sed -n "${CLIENT_002}"p)
expired=$(grep "^Trojan " "/etc/xray/trojan-client.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_002}"p)
uuidnta=$(grep "^Trojan " "/etc/xray/trojan-client.conf" | cut -d ' ' -f 4 | sed -n "${CLIENT_002}"p)

# // Extending Days
clear
read -p "Expired  : " Jumlah_Hari
if [[ $Jumlah_Hari == "" ]]; then
    clear
    echo -e "${FAIL} Mohon Masukan Jumlah Hari perpanjangan !"
    exit 1
fi

# // Date Configuration
now=$(date +%Y-%m-%d)
d1=$(date -d "$expired" +%s)
d2=$(date -d "$now" +%s)
exp2=$(((d1 - d2) / 86400))
exp3=$(($exp2 + $Jumlah_Hari))
exp4=$(date -d "$exp3 days" +"%Y-%m-%d")

# // Input To System Configuration
sed -i "/\b$client\b/d" /etc/xray/trojan-client.conf
echo -e "Trojan $client $exp4 $uuidnta" >>/etc/xray/trojan-client.conf

# // Clear
clear

# // Successfull
echo -e "${OKEY} User ( ${YELLOW}${client}${NC} ) Renewed Then Expired On ( ${YELLOW}$exp4${NC} )"

clear
echo -e "${OKEY} Username ( ${YELLOW}$client${NC} ) Has Been Removed !"
}

echo -e ""
echo -e " ${YELLOW} ----------==[${NC} ${RED}PANEL XRAY TROJAN${NC} ${YELLOW}]==---------- ${NC}"
echo -e ""
echo -e "    ${GREEN} 1${NC}${LIGHT})${NC} ${LIGHT}CREATE USER TROJAN${NC}"
echo -e "    ${GREEN} 2${NC}${LIGHT})${NC} ${LIGHT}DELETE USER TROJAN${NC}"
echo -e "    ${GREEN} 3${NC}${LIGHT})${NC} ${LIGHT}RENEW USER TROJAN${NC}"
echo -e " ${YELLOW} --------------------------------------------- ${NC}"
echo -e "       ${GREEN} x${NC}${LIGHT})${NC} ${LIGHT}Exit or Back to main Menu${NC}"
echo -e " ${YELLOW} --------------------------------------------- ${NC}"
echo -e ""
echo -e "    ${LIGHT} Select From Options ${NC}"
read -p "     [1-3 or type x to return to main menu] : " menutr
echo -e ""
case $menutr in
1)
addtr
echo ""
read -p "Click Enter To Return To The Menu..."
clear
mtr
;;
2)
deltr
echo ""
read -p "Click Enter To Return To The Menu..."
clear
mtr
;;
3)
renewtr
echo ""
read -p "Click Enter To Return To The Menu..."
clear
mtr
;;
x)
menu
;;
*)
mtr
;;
esac
}
mtr
echo ""
read -p "Click enter to return to the main menu..."
clear
menu
;;
4)
function vls(){
#!/bin/bash

dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
=============================================

clear

function import_data() {
    export RED="\033[0;31m"
    export GREEN="\033[0;32m"
    export YELLOW="\033[0;33m"
    export BLUE="\033[0;34m"
    export PURPLE="\033[0;35m"
    export CYAN="\033[0;36m"
    export LIGHT="\033[0;37m"
    export NC="\033[0m"
    export ERROR="[${RED} ERROR ${NC}]"
    export INFO="[${YELLOW} INFO ${NC}]"
    export FAIL="[${RED} FAIL ${NC}]"
    export OKEY="[${GREEN} OKEY ${NC}]"
    export PENDING="[${YELLOW} PENDING ${NC}]"
    export SEND="[${YELLOW} SEND ${NC}]"
    export RECEIVE="[${YELLOW} RECEIVE ${NC}]"
    export RED_BG="\e[41m"
    export BOLD="\e[1m"
    export WARNING="${RED}\e[5m"
    export UNDERLINE="\e[4m"
}

import_data

function addvl(){
#!/bin/sh

clear
IPNYA=$(wget --inet4-only -qO- https://ipinfo.io/ip)
ISPNYA=$(wget --inet4-only -qO- https://ipinfo.io/org | cut -d " " -f 2-100)

read -p "Username : " username
username="$(echo ${username} | sed 's/ //g' | tr -d '\r' | tr -d '\r\n')"

# // Validate Input
if [[ $username == "" ]]; then
    clear
    echo -e "${FAIL} Silakan Masukan Username terlebih dahulu !"
    exit 1
fi

# // Checking User already on vps or no
if [[ "$(cat /etc/xray/vless-client.conf | grep -w ${username})" != "" ]]; then
    clear
    echo -e "${FAIL} User [ ${username} ] sudah ada !"
    exit 1
fi

# // Expired Date
read -p "Expired  : " Jumlah_Hari
exp=$(date -d "$Jumlah_Hari days" +"%Y-%m-%d")
hariini=$(date -d "0 days" +"%Y-%m-%d")

# // Get UUID
uuid=$(uuidgen)

# // Generate New UUID & Domain
domain=$(cat /etc/xray/domain.conf)

# // Getting Vless port using grep from config
tls_port=$(cat /etc/xray/config/xray/tls.json | grep -w port | awk '{print $2}' | head -n1 | sed 's/,//g' | tr '\n' ' ' | tr -d '\r' | tr -d '\r\n' | sed 's/ //g')
nontls_port=$(cat /etc/xray/config/xray/nontls.json | grep -w port | awk '{print $2}' | head -n1 | sed 's/,//g' | tr '\n' ' ' | tr -d '\r' | tr -d '\r\n' | sed 's/ //g')

# // Input Your Data to server
cat /etc/xray/config/xray/tls.json | jq '.inbounds[3].settings.clients += [{"id": "'${uuid}'","email": "'${username}'"}]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq '.inbounds[6].settings.clients += [{"id": "'${uuid}'","email": "'${username}'"}]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/nontls.json | jq '.inbounds[1].settings.clients += [{"id": "'${uuid}'","email": "'${username}'"}]' >/etc/config/config/xray/nontls.json.tmp && mv /etc/xray/config/xray/nontls.json.tmp /etc/xray/config/xray/nontls.json
echo -e "Vless $username $exp $uuid" >>/etc/xray/vless-client.conf

# // Vless Link
vless_nontls="vless://${uuid}@${domain}:${nontls_port}?path=%2Fvless&security=none&encryption=none&type=ws#${username}"
vless_tls="vless://${uuid}@${domain}:${tls_port}?path=%2Fvless&security=tls&encryption=none&type=ws#${username}"
vless_grpc="vless://${uuid}@${domain}:${tls_port}?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc#${username}"

# // Restarting Xray Service
systemctl restart xray@tls
systemctl restart xray@nontls

# // Success
clear
echo -e "==============================="
echo -e "     VLESS ACCOUNT DETAILS"
echo -e "==============================="
echo -e " ISP         : ${ISPNYA}"
echo -e " Remarks     : ${username}"
echo -e " IP          : ${IPNYA}"
echo -e " Address     : ${domain}"
echo -e " Port TLS    : ${tls_port}"
echo -e " Port NonTLS : ${nontls_port}"
echo -e " UUID        : ${uuid}"
echo -e " Path WS     : /vless"
echo -e " ServiceName : vless-grpc"
echo -e " Expired On  : ${exp}"
echo -e "==============================="
echo -e " VLESS WS TLS LINK :"
echo -e " ${vless_tls}"
echo -e "-------------------------------"
echo -e " VLESS WS NTLS LINK :"
echo -e " ${vless_nontls}"
echo -e "-------------------------------"
echo -e " VLESS GRPC LINK :"
echo -e " ${vless_grpc}"
echo -e "==============================="
}

function delvl(){
#!/bin/sh

clear
IPNYA=$(wget --inet4-only -qO- https://ipinfo.io/ip)
ISPNYA=$(wget --inet4-only -qO- https://ipinfo.io/org | cut -d " " -f 2-100)

# // Start
CLIENT_001=$(grep -c -E "^Vless " "/etc/xray/vless-client.conf")
echo "    =================================================="
echo "              LIST VLESS CLIENT ON THIS VPS"
echo "    =================================================="
grep -e "^Vless " "/etc/xray/vless-client.conf" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_002} -ge 1 && ${CLIENT_002} -le ${CLIENT_001} ]]; do
    if [[ ${CLIENT_002} == '1' ]]; then
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    else
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    fi
done

# // String For Username && Expired Date
client=$(grep "^Vless " "/etc/xray/vless-client.conf" | cut -d ' ' -f 2 | sed -n "${CLIENT_002}"p)
expired=$(grep "^Vless " "/etc/xray/vless-client.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_002}"p)

cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[3].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[6].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/nontls.json | jq 'del(.inbounds[1].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/nontls.json.tmp && mv /etc/xray/config/xray/nontls.json.tmp /etc/xray/config/xray/nontls.json

sed -i "/\b$client\b/d" /etc/xray/vless-client.conf
systemctl restart xray@tls
systemctl restart xray@nontls

clear
echo -e "${OKEY} Username ( ${YELLOW}$client${NC} ) Has Been Removed !"
}

function renewvl(){
#!/bin/sh

clear
IPNYA=$(wget --inet4-only -qO- https://ipinfo.io/ip)
ISPNYA=$(wget --inet4-only -qO- https://ipinfo.io/org | cut -d " " -f 2-100)

# // Start
CLIENT_001=$(grep -c -E "^Vless " "/etc/xray/vless-client.conf")
echo "    =================================================="
echo "               LIST VLESS CLIENT ON THIS VPS"
echo "    =================================================="
grep -e "^Vless " "/etc/xray/vless-client.conf" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_002} -ge 1 && ${CLIENT_002} -le ${CLIENT_001} ]]; do
    if [[ ${CLIENT_002} == '1' ]]; then
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    else
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    fi
done

# // String For Username && Expired Date
client=$(grep "^Vless " "/etc/xray/vless-client.conf" | cut -d ' ' -f 2 | sed -n "${CLIENT_002}"p)
expired=$(grep "^Vless " "/etc/xray/vless-client.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_002}"p)
uuidnta=$(grep "^Vless " "/etc/xray/vless-client.conf" | cut -d ' ' -f 4 | sed -n "${CLIENT_002}"p)

# // Extending Days
clear
read -p "Expired  : " Jumlah_Hari
if [[ $Jumlah_Hari == "" ]]; then
    clear
    echo -e "${FAIL} Mohon Masukan Jumlah Hari perpanjangan !"
    exit 1
fi

# // Date Configuration
now=$(date +%Y-%m-%d)
d1=$(date -d "$expired" +%s)
d2=$(date -d "$now" +%s)
exp2=$(((d1 - d2) / 86400))
exp3=$(($exp2 + $Jumlah_Hari))
exp4=$(date -d "$exp3 days" +"%Y-%m-%d")

# // Input To System Configuration
sed -i "/\b$client\b/d" /etc/xray/vless-client.conf
echo -e "Vless $client $exp4 $uuidnta" >>/etc/xray/vless-client.conf

# // Clear
clear

# // Successfull
echo -e "${OKEY} User ( ${YELLOW}${client}${NC} ) Renewed Then Expired On ( ${YELLOW}$exp4${NC} )"
}

echo -e ""
echo -e " ${YELLOW} -----------==[${NC} ${RED}PANEL XRAY VLESS${NC} ${YELLOW}]==----------- ${NC}"
echo -e ""
echo -e "    ${GREEN} 1${NC}${LIGHT})${NC} ${LIGHT}CREATE USER VLESS${NC}"
echo -e "    ${GREEN} 2${NC}${LIGHT})${NC} ${LIGHT}DELETE USER VLESS${NC}"
echo -e "    ${GREEN} 3${NC}${LIGHT})${NC} ${LIGHT}RENEW USER VLESS${NC}"
echo -e " ${YELLOW} ---------------------------------------------- ${NC}"
echo -e "       ${GREEN} x${NC}${LIGHT})${NC} ${LIGHT}Exit or Back to main Menu${NC}"
echo -e " ${YELLOW} ---------------------------------------------- ${NC}"
echo -e ""
echo -e "    ${LIGHT} Select From Options ${NC}"
read -p "     [1-3 or type x to return to main menu] : "  menuvl
echo -e ""
case $menuvl in
1)
addvl
echo ""
read -p "Click Enter To Return To The Menu..."
clear
vls
;;
2)
delvl
echo ""
read -p "Click Enter To Return To The Menu..."
clear
vls
;;
3)
renewvl
echo ""
read -p "Click Enter To Return To The Menu..."
clear
vls
;;
x)
menu
;;
*)
vls
;;
esac
}
vls
echo ""
read -p "Click enter to return to the main menu..."
clear
menu
;;
5)
function vms(){
#!/bin/bash

dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
=============================================

clear

function import_data() {
    export RED="\033[0;31m"
    export GREEN="\033[0;32m"
    export YELLOW="\033[0;33m"
    export BLUE="\033[0;34m"
    export PURPLE="\033[0;35m"
    export CYAN="\033[0;36m"
    export LIGHT="\033[0;37m"
    export NC="\033[0m"
    export ERROR="[${RED} ERROR ${NC}]"
    export INFO="[${YELLOW} INFO ${NC}]"
    export FAIL="[${RED} FAIL ${NC}]"
    export OKEY="[${GREEN} OKEY ${NC}]"
    export PENDING="[${YELLOW} PENDING ${NC}]"
    export SEND="[${YELLOW} SEND ${NC}]"
    export RECEIVE="[${YELLOW} RECEIVE ${NC}]"
    export RED_BG="\e[41m"
    export BOLD="\e[1m"
    export WARNING="${RED}\e[5m"
    export UNDERLINE="\e[4m"
}

import_data

function addvm(){
#!/bin/sh

clear
IPNYA=$(wget --inet4-only -qO- https://ipinfo.io/ip)
ISPNYA=$(wget --inet4-only -qO- https://ipinfo.io/org | cut -d " " -f 2-100)

read -p "Username : " username
username="$(echo ${username} | sed 's/ //g' | tr -d '\r' | tr -d '\r\n')"

# // Validate Input
if [[ $username == "" ]]; then
    clear
    echo -e "${FAIL} Silakan Masukan Username terlebih dahulu !"
    exit 1
fi

# // Checking User already on vps or no
if [[ "$(cat /etc/xray/vmess-client.conf | grep -w ${username})" != "" ]]; then
    clear
    echo -e "${FAIL} User [ ${username} ] sudah ada !"
    exit 1
fi

# // Expired Date
read -p "Expired  : " Jumlah_Hari
exp=$(date -d "$Jumlah_Hari days" +"%Y-%m-%d")
hariini=$(date -d "0 days" +"%Y-%m-%d")

# // Get UUID
uuid=$(uuidgen)

# // Generate New UUID & Domain
domain=$(cat /etc/xray/domain.conf)

# // Getting Vmess port using grep from config
tls_port=$(cat /etc/xray/config/xray/tls.json | grep -w port | awk '{print $2}' | head -n1 | sed 's/,//g' | tr '\n' ' ' | tr -d '\r' | tr -d '\r\n' | sed 's/ //g')
nontls_port=$(cat /etc/xray/config/xray/nontls.json | grep -w port | awk '{print $2}' | head -n1 | sed 's/,//g' | tr '\n' ' ' | tr -d '\r' | tr -d '\r\n' | sed 's/ //g')

# // Input Your Data to server
cat /etc/xray/config/xray/tls.json | jq '.inbounds[2].settings.clients += [{"id": "'${uuid}'","email": "'${username}'","alterid": '"0"'}]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq '.inbounds[5].settings.clients += [{"id": "'${uuid}'","email": "'${username}'","alterid": '"0"'}]' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/nontls.json | jq '.inbounds[0].settings.clients += [{"id": "'${uuid}'","email": "'${username}'","alterid": '"0"'}]' >/etc/xray/config/xray/nontls.json.tmp && mv /etc/xray/config/xray/nontls.json.tmp /etc/xray/config/xray/nontls.json
echo -e "Vmess $username $exp $uuid" >>/etc/xray/vmess-client.conf

cat >/etc/xray/xray-cache/vmess-tls-gun-$username.json <<END
{"add":"${domain}","aid":"0","host":"","id":"${uuid}","net":"grpc","path":"vmess-grpc","port":"${tls_port}","ps":"${username}","scy":"none","sni":"","tls":"tls","type":"gun","v":"2"}
END

cat >/etc/xray/xray-cache/vmess-tls-ws-$username.json <<END
{"add":"${domain}","aid":"0","host":"","id":"${uuid}","net":"ws","path":"/vmess","port":"${tls_port}","ps":"${username}","scy":"none","sni":"${domain}","tls":"tls","type":"","v":"2"}
END

cat >/etc/xray/xray-cache/vmess-nontls-$username.json <<END
{"add":"${domain}","aid":"0","host":"","id":"${uuid}","net":"ws","path":"/vmess","port":"${nontls_port}","ps":"${username}","scy":"none","sni":"","tls":"","type":"","v":"2"}
END

# // Vmess Link
grpc_link="vmess://$(base64 -w 0 /etc/xray/xray-cache/vmess-tls-gun-$username.json)"
ws_tls_link="vmess://$(base64 -w 0 /etc/xray/xray-cache/vmess-tls-ws-$username.json)"
ws_nontls_link="vmess://$(base64 -w 0 /etc/xray/xray-cache/vmess-nontls-$username.json)"

# // Restarting XRay Service
systemctl restart xray@tls
systemctl restart xray@nontls

# // Success
clear
echo -e "==============================="
echo -e "     VMESS ACCOUNT DETAILS"
echo -e "==============================="
echo -e " ISP         : ${ISPNYA}"
echo -e " Remarks     : ${username}"
echo -e " IP          : ${IPNYA}"
echo -e " Address     : ${domain}"
echo -e " Port TLS    : ${tls_port}"
echo -e " Port NonTLS : ${nontls_port}"
echo -e " UUID        : ${uuid}"
echo -e " Path WS     : /vmess"
echo -e " ServiceName : vmess-grpc"
echo -e " Expired On  : ${exp}"
echo -e "==============================="
echo -e " VMESS WS TLS LINK :"
echo -e " ${ws_tls_link}"
echo -e "-------------------------------"
echo -e " VMESS WS NTLS LINK :"
echo -e " ${ws_nontls_link}"
echo -e "-------------------------------"
echo -e " VMESS GRPC LINK"
echo -e " ${grpc_link}"
echo -e "==============================="
}

function delvm(){
#!/bin/sh

clear
IPNYA=$(wget --inet4-only -qO- https://ipinfo.io/ip)
ISPNYA=$(wget --inet4-only -qO- https://ipinfo.io/org | cut -d " " -f 2-100)

# // Start
CLIENT_001=$(grep -c -E "^Vmess " "/etc/xray/vmess-client.conf")
echo "    =================================================="
echo "              LIST VMESS CLIENT ON THIS VPS"
echo "    =================================================="
grep -e "^Vmess " "/etc/xray/vmess-client.conf" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_002} -ge 1 && ${CLIENT_002} -le ${CLIENT_001} ]]; do
    if [[ ${CLIENT_002} == '1' ]]; then
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    else
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    fi
done

# // String For Username && Expired Date
client=$(grep "^Vmess " "/etc/xray/vmess-client.conf" | cut -d ' ' -f 2 | sed -n "${CLIENT_002}"p)
expired=$(grep "^Vmess " "/etc/xray/vmess-client.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_002}"p)

cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[2].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/tls.json | jq 'del(.inbounds[5].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/tls.json.tmp && mv /etc/xray/config/xray/tls.json.tmp /etc/xray/config/xray/tls.json
cat /etc/xray/config/xray/nontls.json | jq 'del(.inbounds[0].settings.clients[] | select(.email == "'${client}'"))' >/etc/xray/config/xray/nontls.json.tmp && mv /etc/xray/config/xray/nontls.json.tmp /etc/xray/config/xray/nontls.json
rm -f /etc/xray/xray-cache/vmess-tls-gun-$client.json /etc/xray/xray-cache/vmess-tls-ws-$client.json /etc/xray/xray-cache/vmess-nontls-$client.json
sed -i "/\b$client\b/d" /etc/xray/vmess-client.conf
systemctl restart xray@tls
systemctl restart xray@nontls

clear
echo -e "${OKEY} Username ( ${YELLOW}$client${NC} ) Has Been Removed !"
}

function renewvm(){
#!/bin/sh

clear
IPNYA=$(wget --inet4-only -qO- https://ipinfo.io/ip)
ISPNYA=$(wget --inet4-only -qO- https://ipinfo.io/org | cut -d " " -f 2-100)

# // Start
CLIENT_001=$(grep -c -E "^Vmess " "/etc/xray/vmess-client.conf")
echo "    =================================================="
echo "               LIST VMESS CLIENT ON THIS VPS"
echo "    =================================================="
grep -e "^Vmess " "/etc/xray/vmess-client.conf" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_002} -ge 1 && ${CLIENT_002} -le ${CLIENT_001} ]]; do
    if [[ ${CLIENT_002} == '1' ]]; then
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    else
        echo "    =================================================="
        read -rp "    Please Input an Client Number (1-${CLIENT_001}) : " CLIENT_002
    fi
done

# // String For Username && Expired Date
client=$(grep "^Vmess " "/etc/xray/vmess-client.conf" | cut -d ' ' -f 2 | sed -n "${CLIENT_002}"p)
expired=$(grep "^Vmess " "/etc/xray/vmess-client.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_002}"p)
uuidnta=$(grep "^Vmess " "/etc/xray/vmess-client.conf" | cut -d ' ' -f 4 | sed -n "${CLIENT_002}"p)

# // Extending Days
clear
read -p "Expired  : " Jumlah_Hari
if [[ $Jumlah_Hari == "" ]]; then
    clear
    echo -e "${FAIL} Mohon Masukan Jumlah Hari perpanjangan !"
    exit 1
fi

# // Date Configuration
now=$(date +%Y-%m-%d)
d1=$(date -d "$expired" +%s)
d2=$(date -d "$now" +%s)
exp2=$(((d1 - d2) / 86400))
exp3=$(($exp2 + $Jumlah_Hari))
exp4=$(date -d "$exp3 days" +"%Y-%m-%d")

# // Input To System Configuration
sed -i "/\b$client\b/d" /etc/xray/vmess-client.conf
echo -e "Vmess $client $exp4 $uuidnta" >>/etc/xray/vmess-client.conf

# // Clear
clear

# // Successfull
echo -e "${OKEY} User ( ${YELLOW}${client}${NC} ) Renewed Then Expired On ( ${YELLOW}$exp4${NC} )"
}

echo -e ""
echo -e " ${YELLOW} -----------==[${NC} ${RED}PANEL XRAY VMESS${NC} ${YELLOW}]==----------- ${NC}"
echo -e ""
echo -e "    ${GREEN} 1${NC}${LIGHT})${NC} ${LIGHT}CREATE USER VMESS${NC}"
echo -e "    ${GREEN} 2${NC}${LIGHT})${NC} ${LIGHT}DELETE USER VMESS${NC}"
echo -e "    ${GREEN} 3${NC}${LIGHT})${NC} ${LIGHT}RENEW USER VMESS${NC}"
echo -e " ${YELLOW} ---------------------------------------------- ${NC}"
echo -e "       ${GREEN} x${NC}${LIGHT})${NC} ${LIGHT}Exit or Back to main Menu${NC}"
echo -e " ${YELLOW} ---------------------------------------------- ${NC}"
echo -e ""
echo -e "    ${LIGHT} Select From Options ${NC}"
read -p "     [1-3 or type x to return to main menu] : " menuvm
echo -e ""
case $menuvm in
1)
addvm
echo ""
read -p "Click Enter To Return To The Menu..."
clear
vms
;;
2)
delvm
echo ""
read -p "Click Enter To Return To The Menu..."
clear
vms
;;
3)
renewvm
echo ""
read -p "Click Enter To Return To The Menu..."
clear
vms
;;
x)
menu
;;
*)
vms
;;
esac
}
vms
echo ""
read -p "Click enter to return to the main menu..."
clear
menu
;;
6)
#!/bin/bash
clear

read -rp "Input ur domain : " -e domain

echo "$domain" >/etc/xray/domain.conf
sleep 1
domain=$(cat /etc/xray/domain.conf)

# Menghentikan Port 443 & 80 jika berjalan
lsof -t -i tcp:80 -s tcp:listen | xargs kill >/dev/null 2>&1
lsof -t -i tcp:443 -s tcp:listen | xargs kill >/dev/null 2>&1
sleep 0.5
systemctl stop nginx
cd
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    
systemctl daemon-reload
systemctl restart nginx
systemctl restart xray@tls
systemctl restart xray@nontls
echo ""
read -p "Click enter to return to the main menu..."
clear
menu
;;
7)
#!/bin/bash
clear

domain=$(cat /etc/xray/domain.conf)

# Menghentikan Port 443 & 80 jika berjalan
lsof -t -i tcp:80 -s tcp:listen | xargs kill >/dev/null 2>&1
lsof -t -i tcp:443 -s tcp:listen | xargs kill >/dev/null 2>&1
sleep 0.5
systemctl stop nginx
cd
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    
systemctl daemon-reload
systemctl restart nginx
systemctl restart xray@tls
systemctl restart xray@nontls
echo ""
read -p "Click enter to return to the main menu..."
clear
menu
;;
8)
clear
speedtest
echo ""
read -p "Click enter to return to the main menu..."
clear
menu
;;
9)
clear
vnstat
echo ""
read -p "Click enter to return to the main menu..."
clear
menu
;;
10)
#!/bin/bash

red="\033[0;32m"
green="\033[0;32m"
NC="\e[0m"
clear
echo ""
echo -e "\e[94m    .----------------------------------------------------.\e[0m    "
echo -e "\e[94m    |              DISPLAYING RUNNING SYSTEM             |\e[0m    "
echo -e "\e[94m    '----------------------------------------------------'\e[0m    "
status="$(systemctl show xray@tls.service --no-page)"
status_text=$(echo "${status}" | grep 'ActiveState=' | cut -f2 -d=)
if [ "${status_text}" == "active" ]
then
echo -e "           XRAY SHADOWSOCKS : Service is "$green"running"$NC""
else
echo -e "           XRAY SHADOWSOCKS : Service is "$red"not running (Error)"$NC""
fi
status="$(systemctl show xray@tls.service --no-page)"
status_text=$(echo "${status}" | grep 'ActiveState=' | cut -f2 -d=)
if [ "${status_text}" == "active" ]
then
echo -e "           XRAY TROJAN      : Service is "$green"running"$NC""
else
echo -e "           XRAY TROJAN      : Service is "$red"not running (Error)"$NC""
fi
status="$(systemctl show xray@tls.service --no-page)"
status_text=$(echo "${status}" | grep 'ActiveState=' | cut -f2 -d=)
if [ "${status_text}" == "active" ]
then
echo -e "           XRAY VLESS       : Service is "$green"running"$NC""
else
echo -e "           XRAY VLESS       : Service is "$red"not running (Error)"$NC""
fi
status="$(systemctl show xray@tls.service --no-page)"
status_text=$(echo "${status}" | grep 'ActiveState=' | cut -f2 -d=)
if [ "${status_text}" == "active" ]
then
echo -e "           XRAY VMESS       : Service is "$green"running"$NC""
else
echo -e "           XRAY VMESS       : Service is "$red"not running (Error)"$NC""
fi
tatus="$(systemctl show xray@tls.service --no-page)"
status_text=$(echo "${status}" | grep 'ActiveState=' | cut -f2 -d=)
if [ "${status_text}" == "active" ]
then
echo -e "           XRAY MULTI       : Service is "$green"running"$NC""
else
echo -e "           XRAY MULTI       : Service is "$red"not running (Error)"$NC""
fi
status="$(systemctl show nginx.service --no-page)"
status_text=$(echo "${status}" | grep 'ActiveState=' | cut -f2 -d=)
if [ "${status_text}" == "active" ]
then
echo -e "           NGINX            : Service is "$green"running"$NC""
else
echo -e "           NGINX            : Service is "$red"not running (Error)"$NC""
fi
status="$(systemctl show cron.service --no-page)"
status_text=$(echo "${status}" | grep 'ActiveState=' | cut -f2 -d=)
if [ "${status_text}" == "active" ]
then
echo -e "           CRON             : Service is "$green"running"$NC""
else
echo -e "           CRON             : Service is "$red"not running (Error)"$NC""
fi
echo -e "\e[94m    ------------------------------------------------------   \e[0m "
echo ""
read -p "Click enter to return to the main menu..."
clear
menu
;;
11)
#!/bin/bash

RED="\033[0;32m"
GREEN="\033[0;32m"
NC="\e[0m"
clear

echo ""
echo -e "=============================================================="
echo -e " ------------------------------------------------------------" 
echo "   >>> Service & Port"
echo "   - Nginx                   : 81"
echo "   - XRAY Vmess TLS          : 443"
echo "   - XRAY Vmess Non TLS      : 80"
echo "   - XRAY Vmess GRPC         : 443"
echo "   - XRAY Vless TLS          : 443"
echo "   - XRAY Vless Non TLS      : 80"
echo "   - XRAY Vless GRPC         : 443"
echo "   - Trojan TCP TLS          : 443"
echo "   - Trojan GRPC             : 443"
echo "   - Trojan WS               : 443"
echo "   - Shadowsocks WS TLS      : 443"
echo "   - Shadowsocks GRPC        : 443"
echo ""
echo "   >>> Server Information & Other Features"
echo "   - Timezone                : Asia/Jakarta (GMT +7)"
echo "   - Fail2Ban                : [ON]"
echo "   - Dflate                  : [ON]"
echo "   - IPtables                : [ON]"
echo "   - Auto-Reboot             : [ON]"
echo "   - IPv6                    : [OFF]"
echo "   - Autoreboot On           : 05:00 WIB GMT +7"
echo "   - Auto Delete Expired Account"
echo "   - Fully automatic script"
echo "   - VPS settings"
echo "   - Admin Control"
echo "   - Full Orders For Various Services"
echo -e " ------------------------------------------------------------"
echo -e " =============================================================="
echo ""
read -p "Click enter to return to the main menu..."
clear
menu
;;
12)
echo "Reboot System In 10 Seconds..."
sleep 10
reboot
;;
x)
exit
bash
;;
*)
menu
;;
esac
