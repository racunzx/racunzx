#!/bin/bash

#MIT License
#Copyright (c) 2020 h31105

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

#====================================================
# System Request:Debian 9+/Ubuntu 18.04+/Centos 7+
# Author: Miroku/h31105
# Dscription: TLS-Shunt-Proxy&Trojan-Go&V2Ray Script
# Official document:
# https://www.v2ray.com/
# https://github.com/p4gefau1t/trojan-go
# https://github.com/liberal-boy/tls-shunt-proxy
# https://www.docker.com/
# https://github.com/containrrr/watchtower
# https://github.com/portainer/portainer
# https://github.com/wulabing/V2Ray_ws-tls_bash_onekey
#====================================================

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

cd "$(
    cd "$(dirname "$0")" || exit
    pwd
)" || exit

#Fonts Color
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
GreenBG="\033[42;30m"
RedBG="\033[41;30m"
Font="\033[0m"

#Notification Information
OK="${Green}[OK]${Font}"
WARN="${Yellow}[警告]${Font}"
Error="${Red}[error]${Font}"

#Version, initialization variables
shell_version="1.180"
tsp_cfg_version="0.61.1"
#install_mode="docker"
upgrade_mode="none"
github_branch="master"
version_cmp="/tmp/version_cmp.tmp"
tsp_conf_dir="/etc/tls-shunt-proxy"
trojan_conf_dir="/etc/trojan-go"
v2ray_conf_dir="/etc/v2ray"
tsp_conf="${tsp_conf_dir}/config.yaml"
tsp_cert_dir="/etc/ssl/tls-shunt-proxy/certificates/acme-v02.api.letsencrypt.org-directory"
trojan_conf="${trojan_conf_dir}/config.json"
v2ray_conf="${v2ray_conf_dir}/config.json"
web_dir="/home/wwwroot"
random_num=$((RANDOM % 3 + 7))

#shellcheck disable=SC1091
source '/etc/os-release'

#Extract the English name of the release system from VERSION
VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -eq 7 ]]; then
        echo -e "${OK} ${GreenBG} The current system is Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum -y -q"
        yum install epel-release -y -q
    elif [[ "${ID}" == "centos" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} The current system is Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="dnf -y"
        dnf install epel-release -y -q
        dnf config-manager --set-enabled PowerTools
	dnf upgrade libseccomp
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} The current system is Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt -y -qq"
        $INS update
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        echo -e "${OK} ${GreenBG} The current system is Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt -y -qq"
        $INS update
    else
        echo -e "${Error} ${RedBG} The current system is ${ID} ${VERSION_ID} is not in the list of supported systems, the installation is interrupted ${Font}"
        exit 1
    be

    $INS install dbus
    systemctl stop firewalld
    echo -e "${OK} ${GreenBG} Firewalld is closed ${Font}"
    systemctl stop ufw
    echo -e "${OK} ${GreenBG} UFW has closed ${Font}"
}

is_root() {
    if [ 0 == $UID ]; then
        echo -e "${OK} ${GreenBG} The current user is the root user, continue to execute ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} The current user is not the root user, please switch to the root user and re-execute the script ${Font}"
        exit 1
    be
}

judge() {
    #shellcheck disable=SC2181
    if [[ 0 -eq $? ]]; then
        echo -e "${OK} ${GreenBG} $1 complete ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 failed ${Font}"
        exit 1
    be
}

urlEncode() {
    jq -R -r @uri <<<"$1"
}

chrony_install() {
    ${INS} install chrony
    judge "Install Chrony Time Synchronization Service"
    timedatectl set-ntp true
    if [[ "${ID}" == "centos" ]]; then
        systemctl enable chronyd && systemctl restart chronyd
    else
        systemctl enable chrony && systemctl restart chrony
    be
    judge "Chrony 启动"
    timedatectl set-timezone Asia/Shanghai
    echo -e "${OK} ${GreenBG} waiting time synchronization ${Font}"
    sleep 10
    chronyc sourcestats -v
    chronyc tracking -v
    date
    read -rp "Please confirm whether the time is accurate, the error range is ±3 minutes (Y/N) [Y]: "chrony_install
    [[ -z ${chrony_install} ]] && chrony_install="Y"
    case $chrony_install in
    [yY][eE][sS] | [yY])
        echo -e "${GreenBG} continue to execute ${Font}"
        sleep 2
        ;;
    *)
        echo -e "${RedBG} terminate the execution of ${Font}"
        exit 2
        ;;
    esac
}

dependency_install() {
    ${INS} install curl git lsof unzip
    judge "install dependency package curl git lsof unzip"
    ${INS} install haveged
    systemctl start haveged && systemctl enable haveged
    command -v bc >/dev/null 2>&1 || ${INS} install bc
    judge "Install dependency package bc"
    command -v jq >/dev/null 2>&1 || ${INS} install jq
    judge "Install dependency package jq"
    command -v sponge >/dev/null 2>&1 || ${INS} install moreutils
    judge "install dependency package moreutils"
    command -v qrencode >/dev/null 2>&1 || ${INS} install qrencode
    judge "install dependent package qrencode"
}

basic_optimization() {
    # Maximum number of open files
    sed -i '/ ^ \ * \ * soft \ * nofile \ * [[: digit:]] * / d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf
    # Close Selinux
    if [[ "${ID}" == "centos" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    be
}

config_exist_check() {
    if [[ -f "$1" ]]; then
        echo -e "${OK} ${GreenBG} detects the old configuration file, automatically backs up the old file configuration ${Font}"
        cp "$1" "$1.$(date +%Y%m%d%H)"
        echo -e "${OK} ${GreenBG} has backed up the old configuration ${Font}"
    be
}

domain_port_check() {
    read -rp "Please enter the TLS port (default 443):" tspport
    [[ -z ${tspport} ]] && tspport="443"
    read -rp "Please enter your domain name information (for example: fk.gfw.com):" domain
    domain=$(echo "${domain}" | tr '[:upper:]' '[:lower:]')
    domain_ip=$(ping -q -c 1 -t 1 "${domain}" | grep PING | sed -e "s/).*//" | sed -e "s/.*(//")
    echo -e "${OK} ${GreenBG} is getting public network ip information, please wait patiently ${Font}"
    local_ip=$(curl -s https://api64.ipify.org)
    echo -e "Domain name DNS resolution IP: ${domain_ip}"
    echo -e "本机IP: ${local_ip}"
    sleep 2
    if [[ "${local_ip}" = "${domain_ip}" ]]; then
        echo -e "${OK} ${GreenBG} The DNS resolution IP of the domain name matches the local IP ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} Please make sure that the correct A/AAAA record is added to the domain name, otherwise you will not be able to connect normally ${Font}"
        echo -e "${Error} ${RedBG} The DNS resolution IP of the domain name does not match the local IP, which will cause the SSL certificate application to fail. Do you want to continue the installation? (Y/N)[N]${Font}" && read -r install
        case $install in
        [yY][eE][sS] | [yY])
            echo -e "${GreenBG} continue to install ${Font}"
            sleep 2
            ;;
        *)
            echo -e "${RedBG} installation terminated ${Font}"
            exit 2
            ;;
        esac
    be
}

port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        echo -e "${OK} ${GreenBG} $1 Port is not occupied ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} detected that $1 port is occupied, the following is the occupation information of $1 port ${Font}"
        lsof -i:"$1"
        echo -e "${OK} ${GreenBG} will try to automatically kill the occupied process ${Font} after 5s"
        sleep 5
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        echo -e "${OK} ${GreenBG} kill 完成 ${Font}"
        sleep 1
    be
}

service_status_check() {
    if systemctl is-active "$1" &>/dev/null; then
        echo -e "${OK} ${GreenBG} $1 has started ${Font}"
        if systemctl is-enabled "$1" &>/dev/null; then
            echo -e "${OK} ${GreenBG} $1 is the startup item ${Font}"
        else
            echo -e "${WARN} ${Yellow} $1 is not a startup item ${Font}"
            systemctl enable "$1"
            judge "Set $1 to start at boot"
        be
    else
        echo -e "${Error} ${RedBG} detected that the $1 service is not started, and is trying to start... ${Font}"
        systemctl restart "$1" && systemctl enable "$1"
        judge "Try to start $1"
        sleep 5
        if systemctl is-active "$1" &>/dev/null; then
            echo -e "${OK} ${GreenBG} $1 has started ${Font}"
        else
            echo -e "${WARN} ${Yellow} Please try to reinstall and repair $1 and try again after ${Font}"
            exit 4
        be
    be
}

prereqcheck() {
    service_status_check docker
    if [[ -f ${tsp_conf} ]]; then
        service_status_check tls-shunt-proxy
    else
        echo -e "${Error} ${RedBG} TLS-Shunt-Proxy configuration is abnormal, please try to reinstall ${Font}"
        exit 4
    be
}

trojan_reset() {
    config_exist_check ${trojan_conf}
    [[ -f ${trojan_conf} ]] && rm -rf ${trojan_conf}
    if [[ -f ${tsp_conf} ]]; then
        TSP_Domain=$(grep'#TSP_Domain' ${tsp_conf} | sed -r's/.*: (.*) #.*/\1/') && echo -e "The detected TLS domain name is: ${TSP_Domain }"
    else
        echo -e "${Error} ${RedBG} TLS-Shunt-Proxy configuration is abnormal, TLS domain name information cannot be detected, please reinstall and try again ${Font}"
        exit 4
    be
    read -rp "Please enter the password (Trojan-Go), the default is random:" tjpasswd
    [[ -z ${tjpasswd} ]] && tjpasswd=$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})
    echo -e "${OK} ${GreenBG} Trojan-Go password: ${tjpasswd} ${Font}"
    read -rp "Whether to enable WebSocket mode support (Y/N) [N]:" trojan_ws_mode
    [[ -z ${trojan_ws_mode} ]] && trojan_ws_mode=false
    case $trojan_ws_mode in
    [yY][eE][sS] | [yY])
        tjwspath="/trojan/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"
        echo -e "${OK} ${GreenBG} Trojan-Go WebSocket mode is on, WSPATH: ${tjwspath} ${Font}"
        trojan_ws_mode=true
        ;;
    *)
        trojan_ws_mode=false
        ;;
    esac
    trojan_tcp_mode=true
    tjport=$((RANDOM% 6666 + 10000)) && echo -e "${OK} ${GreenBG} Trojan-Go listening port is: $tjport ${Font}"
    mkdir -p $ trojan_conf_dir
    cat >$trojan_conf <<-EOF
{
    "run_type": "server",
    "disable_http_check": true,
    "local_addr": "127.0.0.1",
    "local_port": ${tjport},
    "remote_addr": "1.1.1.1",
    "remote_port": 80,
    "fallback_addr": "1.1.1.1",
    "fallback_port": 443,
    "password": ["${tjpasswd}"],
    "transport_plugin": {
        "enabled": true,
        "type": "plaintext"
    },
    "websocket": {
        "enabled": ${trojan_ws_mode},
        "path": "${tjwspath}",
        "host": "${TSP_Domain}"
    }
}
EOF
    judge "Trojan-Go configuration generation"
    port_exist_check $tjport
    trojan_sync
    judge "Synchronize Trojan-Go configuration settings"
    systemctl restart tls-shunt-proxy && service_status_check tls-shunt-proxy
    judge "TLS-Shunt-Proxy application settings"
}

modify_trojan() {
    deployed_status_check
    echo -e "${WARN} ${Yellow} Modifying the Trojan-Go configuration will reset the existing proxy configuration information, do you want to continue (Y/N) [N]? ${Font}"
    read -r modify_confirm
    [[ -z ${modify_confirm} ]] && modify_confirm="No"
    case $modify_confirm in
    [yY][eE][sS] | [yY])
        prereqcheck
        trojan_reset
        docker restart Trojan-Go
        ;;
    *) ;;
    esac
}

trojan_sync() {
    [[-z $ tjport]] && tjport = 40001
    [[ -z $tjwspath ]] && tjwspath=/trojan/none
    [[ -z $trojan_tcp_mode ]] && trojan_tcp_mode=none
    [[ -z $trojan_ws_mode ]] && trojan_ws_mode=none
    if [[ ${trojan_tcp_mode} = true ]]; then
        sed -i "/trojan: #Trojan_TCP/c \\    trojan: #Trojan_TCP" ${tsp_conf}
        sed -i "/handler: proxyPass #Trojan_TCP/c \\      handler: proxyPass #Trojan_TCP" ${tsp_conf}
        sed -i "/#Trojan_TCP_Port/c \\      args: 127.0.0.1:${tjport} #Trojan_TCP_Port:${trojan_tcp_mode}" ${tsp_conf}
    else
        sed -i "/trojan: #Trojan_TCP/c \\    #trojan: #Trojan_TCP" ${tsp_conf}
        sed -i "/handler: proxyPass #Trojan_TCP/c \\      #handler: proxyPass #Trojan_TCP" ${tsp_conf}
        sed -i "/#Trojan_TCP_Port/c \\      #args: 127.0.0.1:${tjport} #Trojan_TCP_Port:${trojan_tcp_mode}" ${tsp_conf}
    be
    if [[ ${trojan_ws_mode} = true ]]; then
        sed -i "/#Trojan_WS_Path/c \\      - path: ${tjwspath} #Trojan_WS_Path" ${tsp_conf}
        sed -i "/handler: proxyPass #Trojan_WS/c \\        handler: proxyPass #Trojan_WS" ${tsp_conf}
        sed -i "/#Trojan_WS_Port/c \\        args: 127.0.0.1:${tjport} #Trojan_WS_Port:${trojan_ws_mode}" ${tsp_conf}
    else
        sed -i "/#Trojan_WS_Path/c \\      #- path: ${tjwspath} #Trojan_WS_Path" ${tsp_conf}
        sed -i "/handler: proxyPass #Trojan_WS/c \\        #handler: proxyPass #Trojan_WS" ${tsp_conf}
        sed -i "/#Trojan_WS_Port/c \\        #args: 127.0.0.1:${tjport} #Trojan_WS_Port:${trojan_ws_mode}" ${tsp_conf}
    be
}

v2ray_mode_type() {
    read -rp "Please select V2Ray TCP mode protocol type: VMess(M)/VLESS(L), skip by default, (M/L) [Skip]:" v2ray_tcp_mode
    [[ -z ${v2ray_tcp_mode} ]] && v2ray_tcp_mode="none"
    case $v2ray_tcp_mode in
    [mM])
        echo -e "${GreenBG} has selected TCP mode protocol VMess ${Font}"
        v2ray_tcp_mode="vmess"
        ;;
    [lL])
        echo -e "${GreenBG} has selected TCP mode protocol VLESS ${Font}"
        v2ray_tcp_mode="vless"
        ;;
    none)
        echo -e "${GreenBG} skip TCP mode deployment ${Font}"
        v2ray_tcp_mode="none"
        ;;
    *)
        echo -e "${RedBG} Please enter the correct letter (M/L) ${Font}"
        ;;
    esac
    read -rp "Please select the V2Ray WebSocket mode protocol type: VMess(M)/VLESS(L), skip by default, (M/L) [Skip]:" v2ray_ws_mode
    [[ -z ${v2ray_ws_mode} ]] && v2ray_ws_mode="none"
    case $v2ray_ws_mode in
    [mM])
        echo -e "${GreenBG} has selected WS mode VMess ${Font}"
        v2ray_ws_mode="vmess"
        ;;
    [lL])
        echo -e "${GreenBG} has selected WS mode VLESS ${Font}"
        v2ray_ws_mode="vless"
        ;;
    none)
        echo -e "${GreenBG} skip WS mode deployment ${Font}"
        v2ray_ws_mode="none"
        ;;
    *)
        echo -e "${RedBG} Please enter the correct letter (M/L) ${Font}"
        ;;
    esac
}

v2ray_reset() {
    config_exist_check ${v2ray_conf}
    [[ -f ${v2ray_conf} ]] && rm -rf ${v2ray_conf}
    mkdir -p $ v2ray_conf_dir
    cat >$v2ray_conf <<-EOF
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds":[
    ], 
    "outbounds": [
      {
        "protocol": "freedom", 
        "settings": {}, 
        "tag": "direct"
      }, 
      {
        "protocol": "blackhole", 
        "settings": {}, 
        "tag": "blocked"
      }
    ], 
    "dns": {
      "servers": [
        "https+local://1.1.1.1/dns-query",
	    "1.1.1.1",
	    "1.0.0.1",
	    "8.8.8.8",
	    "8.8.4.4",
	    "localhost"
      ]
    },
    "routing": {
      "rules": [
        {
            "ip": [
            "geoip:private"
            ],
            "outboundTag": "blocked",
            "type": "field"
        },
        {
          "type": "field",
          "outboundTag": "blocked",
          "protocol": ["bittorrent"]
        },
        {
          "type": "field",
          "inboundTag": [
          ],
          "outboundTag": "direct"
        }
      ]
    }
}
EOF
    if [[ "${v2ray_ws_mode}" = v*ess ]]; then
        UUID=$(cat /proc/sys/kernel/random/uuid)
        echo -e "${OK} ${GreenBG} UUID:${UUID} ${Font}"
        v2wspath="/v2ray/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"
        echo -e "${OK} ${GreenBG} Open V2Ray WS mode, WSPATH: ${v2wspath} ${Font}"
        v2wsport=$((RANDOM % 6666 + 30000))
        echo -e "${OK} ${GreenBG} V2Ray WS listening port is ${v2wsport} ${Font}"
        if [[ "${v2ray_ws_mode}" = "vmess" ]]; then
            #read -rp "Please enter AlterID in WS mode (default: 10, only non-zero numbers allowed):" alterID
            [[ -z ${alterID} ]] && alterID="10"
            jq '.inbounds += [{"sniffing":{"enabled":true,"destOverride":["http","tls"]},"port":'${v2wsport}',"listen":"127.0.0.1","tag":"vmess-ws-in","protocol":"vmess","settings":{"clients":[{"id":"'"${UUID}"'","alterId":'${alterID}'}]},"streamSettings":{"network":"ws","wsSettings":{"acceptProxyProtocol":true,"path":"'"${v2wspath}"'"}}}]' ${v2ray_conf} | sponge ${v2ray_conf} &&
                jq '.routing.rules[2].inboundTag += ["vmess-ws-in"]' ${v2ray_conf} | sponge ${v2ray_conf}
            judge "V2Ray VMess WS configuration generation"
        be
        if [[ "${v2ray_ws_mode}" = "vless" ]]; then
            jq '.inbounds += [{"sniffing":{"enabled":true,"destOverride":["http","tls"]},"port":'${v2wsport}',"listen":"127.0.0.1","tag":"vless-ws-in","protocol":"vless","settings":{"clients":[{"id":"'"${UUID}"'","level":0}],"decryption":"none"},"streamSettings":{"network":"ws","wsSettings":{"acceptProxyProtocol":true,"path":"'"${v2wspath}"'"}}}]' ${v2ray_conf} | sponge ${v2ray_conf} &&
                jq '.routing.rules[2].inboundTag += ["vless-ws-in"]' ${v2ray_conf} | sponge ${v2ray_conf}
            judge "V2Ray VLESS WS configuration generation"
        be
        port_exist_check ${v2wsport}
    be
    if [[ "${v2ray_tcp_mode}" = v*ess ]]; then
        UUID=$(cat /proc/sys/kernel/random/uuid)
        echo -e "${OK} ${GreenBG} UUID:${UUID} ${Font}"
        v2port=$((RANDOM % 6666 + 20000))
        echo -e "${OK} ${GreenBG} V2Ray TCP listening port is ${v2port} ${Font}"
        if [[ "${v2ray_tcp_mode}" = "vmess" ]]; then
            #read -rp "Please enter the AlterID of the TCP mode (default: 10, only non-zero numbers allowed):" alterID
            [[ -z ${alterID} ]] && alterID="10"
            jq '.inbounds += [{"sniffing":{"enabled":true,"destOverride":["http","tls"]},"port":'${v2port}',"listen":"127.0.0.1","tag":"vmess-tcp-in","protocol":"vmess","settings":{"clients":[{"id":"'"${UUID}"'","alterId":'${alterID}'}]},"streamSettings":{"network":"tcp","tcpSettings":{"acceptProxyProtocol":true}}}]' ${v2ray_conf} | sponge ${v2ray_conf} &&
                jq '.routing.rules[2].inboundTag += ["vmess-tcp-in"]' ${v2ray_conf} | sponge ${v2ray_conf}
            judge "V2Ray VMess TCP configuration generation"
        be
        if [[ "${v2ray_tcp_mode}" = "vless" ]]; then
            jq '.inbounds += [{"sniffing":{"enabled":true,"destOverride":["http","tls"]},"port":'${v2port}',"listen":"127.0.0.1","tag":"vless-tcp-in","protocol":"vless","settings":{"clients":[{"id":"'"${UUID}"'","level":0}],"decryption":"none"},"streamSettings":{"network":"tcp","tcpSettings":{"acceptProxyProtocol":true}}}]' ${v2ray_conf} | sponge ${v2ray_conf} &&
                jq '.routing.rules[2].inboundTag += ["vless-tcp-in"]' ${v2ray_conf} | sponge ${v2ray_conf}
            judge "V2Ray VLESS TCP configuration generation"
        be
        port_exist_check ${v2port}
    be
    if [[ -f ${tsp_conf} ]]; then
        v2ray_sync
        judge "Synchronize V2Ray configuration"
        systemctl restart tls-shunt-proxy && service_status_check tls-shunt-proxy
        judge "TLS-Shunt-Proxy application settings"
    else
        echo -e "${Error} ${RedBG} TLS-Shunt-Proxy configuration is abnormal, please reinstall and try again ${Font}"
        exit 4
    be
}

modify_v2ray() {
    deployed_status_check
    echo -e "${WARN} ${Yellow} Modifying the V2Ray configuration will reset the existing proxy configuration information, do you want to continue (Y/N) [N]? ${Font}"
    read -r modify_confirm
    [[ -z ${modify_confirm} ]] && modify_confirm="No"
    case $modify_confirm in
    [yY][eE][sS] | [yY])
        prereqcheck
        v2ray_mode_type
        [[ $v2ray_tcp_mode != "none" || $v2ray_ws_mode != "none" ]] && v2ray_reset
        docker restart V2Ray
        ;;
    *) ;;
    esac
}

v2ray_sync() {
    [[-z $ v2port]] && v2port = 40003
    [[ -z $v2wsport ]] && v2wsport=40002
    [[ -z $v2wspath ]] && v2wspath=/v2ray/none
    [[ -z $v2ray_tcp_mode ]] && v2ray_tcp_mode=none
    [[ -z $v2ray_ws_mode ]] && v2ray_ws_mode=none
    if [[ ${v2ray_tcp_mode} = v*ess ]]; then
        sed -i "/default: #V2Ray_TCP/c \\    default: #V2Ray_TCP" ${tsp_conf}
        sed -i "/handler: proxyPass #V2Ray_TCP/c \\      handler: proxyPass #V2Ray_TCP" ${tsp_conf}
        sed -i "/#V2Ray_TCP_Port/c \\      args: 127.0.0.1:${v2port};proxyProtocol #V2Ray_TCP_Port:${v2ray_tcp_mode}" ${tsp_conf}
    else
        sed -i "/default: #V2Ray_TCP/c \\    #default: #V2Ray_TCP" ${tsp_conf}
        sed -i "/handler: proxyPass #V2Ray_TCP/c \\      #handler: proxyPass #V2Ray_TCP" ${tsp_conf}
        sed -i "/#V2Ray_TCP_Port/c \\      #args: 127.0.0.1:${v2port};proxyProtocol #V2Ray_TCP_Port:${v2ray_tcp_mode}" ${tsp_conf}
    be
    if [[ ${v2ray_ws_mode} = v*ess ]]; then
        sed -i "/#V2Ray_WS_Path/c \\      - path: ${v2wspath} #V2Ray_WS_Path" ${tsp_conf}
        sed -i "/handler: proxyPass #V2Ray_WS/c \\        handler: proxyPass #V2Ray_WS" ${tsp_conf}
        sed -i "/#V2Ray_WS_Port/c \\        args: 127.0.0.1:${v2wsport};proxyProtocol #V2Ray_WS_Port:${v2ray_ws_mode}" ${tsp_conf}
    else
        sed -i "/#V2Ray_WS_Path/c \\      #- path: ${v2wspath} #V2Ray_WS_Path" ${tsp_conf}
        sed -i "/handler: proxyPass #V2Ray_WS/c \\        #handler: proxyPass #V2Ray_WS" ${tsp_conf}
        sed -i "/#V2Ray_WS_Port/c \\        #args: 127.0.0.1:${v2wsport};proxyProtocol #V2Ray_WS_Port:${v2ray_ws_mode}" ${tsp_conf}
    be
}

web_camouflage() {
    ##Please note that this conflicts with the default path of the LNMP script. Do not use this script in an environment where LNMP is installed, otherwise you will be responsible for the consequences
    rm -rf $ web_dir
    mkdir -p $ web_dir
    cd $ web_dir || success
    websites[0]="https://github.com/h31105/LodeRunner_TotalRecall.git"
    websites[1]="https://github.com/h31105/adarkroom.git"
    websites[2]="https://github.com/h31105/webosu"
    selectedwebsite=${websites[$RANDOM % ${#websites[@]}]}
    git clone ${selectedwebsite} web_camouflage
    judge "WebSite disguise"
}

install_docker() {
    echo -e "${GreenBG} start to install the latest version of Docker... ${Font}"
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh
    judge "安装 Docker "
    systemctl daemon-reload
    systemctl enable docker && systemctl restart docker
    judge "Docker start"
}

install_tsp() {
    bash <(curl -L -s https://raw.githubusercontent.com/liberal-boy/tls-shunt-proxy/master/dist/install.sh)
    judge "安装 TLS-Shunt-Proxy"
    chown -R tls-shunt-proxy:tls-shunt-proxy /etc/ssl/tls-shunt-proxy
    command -v setcap >/dev/null 2>&1 && setcap "cap_net_bind_service=+ep" /usr/local/bin/tls-shunt-proxy
    config_exist_check ${tsp_conf}
    [[ -f ${tsp_conf} ]] && rm -rf ${tsp_conf}
    mkdir -p $ tsp_conf_dir
    cat >$tsp_conf <<-EOF
#TSP_CFG_Ver:${tsp_cfg_version}
listen: 0.0.0.0:${tspport} #TSP_Port
redirecthttps: 0.0.0.0:80
inboundbuffersize: 4
outboundbuffersize: 32
vhosts:
  - name: ${domain} #TSP_Domain
    tlsoffloading: true
    managedcert: true
    keytype: p256
    alpn: h2,http/1.1
    protocols: tls12,tls13
    http:
      paths:
      #- path: /trojan/none #Trojan_WS_Path
        #handler: proxyPass #Trojan_WS
        #args: 127.0.0.1:40000 #Trojan_WS_Port:${trojan_ws_mode}
      #- path: /v2ray/none #V2Ray_WS_Path
        #handler: proxyPass #V2Ray_WS
        #args: 127.0.0.1:40002;proxyProtocol #V2Ray_WS_Port:${v2ray_ws_mode}
      handler: fileServer
      args: ${web_dir}/web_camouflage #Website_camouflage
    #trojan: #Trojan_TCP
      #handler: proxyPass #Trojan_TCP
      #args: 127.0.0.1:40001 #Trojan_TCP_Port:${trojan_tcp_mode}
    #default: #V2Ray_TCP
      #handler: proxyPass #V2Ray_TCP
      #args: 127.0.0.1:40003;proxyProtocol #V2Ray_TCP_Port:${v2ray_tcp_mode}
EOF
    judge "配置 TLS-Shunt-Proxy"
    systemctl daemon-reload && systemctl reset-failed
    systemctl enable tls-shunt-proxy && systemctl restart tls-shunt-proxy
    judge "启动 TLS-Shunt-Proxy"
}

modify_tsp() {
    domain_port_check
    sed -i "/#TSP_Port/c \\listen: 0.0.0.0:${tspport} #TSP_Port" ${tsp_conf}
    sed -i "/#TSP_Domain/c \\  - name: ${domain} #TSP_Domain" ${tsp_conf}
    tsp_sync
}

tsp_sync() {
    echo -e "${OK} ${GreenBG} Detect and synchronize existing proxy configuration... ${Font}"
    if [[ $trojan_stat = "installed" && -f ${trojan_conf} ]]; then
        tjport="$(grep '"local_port"' ${trojan_conf} | sed -r 's/.*: (.*),.*/\1/')" && trojan_tcp_mode=true &&
            tjwspath="$(grep '"path":' ${trojan_conf} | awk -F '"' '{print $4}')" && trojan_ws_mode="$(jq -r '.websocket.enabled' ${trojan_conf})"
        judge "Check Trojan-Go configuration"
        [[ -z $tjport ]] && trojan_tcp_mode=false
        [[ $trojan_ws_mode = null ]] && trojan_ws_mode=false
        [[ -z $tjwspath ]] && tjwspath=/trojan/none
        echo -e "Detected: Trojan-Go Agent: TCP: ${Green}${trojan_tcp_mode}${Font} / WebSocket: ${Green}${trojan_ws_mode}${Font} / Port: ${Green}${ tjport}${Font} / WebSocket Path: ${Green}${tjwspath}${Font}"
    be

    if [[ $v2ray_stat = "installed" && -f ${v2ray_conf} ]]; then
        sed -i '/\#\"/d' ${v2ray_conf}
        v2port="$(jq -r '[.inbounds[] | select(.streamSettings.network=="tcp") | .port][0]' ${v2ray_conf})" &&
            v2wsport="$(jq -r '[.inbounds[] | select(.streamSettings.network=="ws") | .port][0]' ${v2ray_conf})" &&
            v2ray_tcp_mode="$(jq -r '[.inbounds[] | select(.streamSettings.network=="tcp") | .protocol][0]' ${v2ray_conf})" &&
            v2ray_ws_mode="$(jq -r '[.inbounds[] | select(.streamSettings.network=="ws") | .protocol][0]' ${v2ray_conf})" &&
            v2wspath="$(jq -r '[.inbounds[] | select(.streamSettings.network=="ws") | .streamSettings.wsSettings.path][0]' ${v2ray_conf})"
        judge "Check V2Ray configuration"
        [[ $v2port = null ]] && v2port=40003
        [[ $v2wsport = null ]] && v2wsport=40002
        [[ $v2ray_tcp_mode = null ]] && v2ray_tcp_mode=none
        [[ $v2ray_ws_mode = null ]] && v2ray_ws_mode=none
        [[ $v2wspath = null ]] && v2wspath=/v2ray/none
        echo -e "Detected: V2Ray Proxy: TCP: ${Green}${v2ray_tcp_mode}${Font} Port: ${Green}${v2port}${Font} / WebSocket: ${Green}${v2ray_ws_mode}$ {Font} Port: ${Green}${v2wsport}${Font} / WebSocket Path: ${Green}${v2wspath}${Font}"
    be

    if [[ -f ${tsp_conf} ]]; then
        trojan_sync
        v2ray_sync
        tsp_config_stat="synchronized"
        systemctl restart tls-shunt-proxy
        judge "Split configuration synchronization"
        menu_req_check tls-shunt-proxy
    else
        echo -e "${Error} ${RedBG} TLS-Shunt-Proxy configuration is abnormal, please reinstall and try again ${Font}"
        exit 4
    be
}

install_trojan() {
    systemctl is-active "docker" &>/dev/null || install_docker
    prereqcheck
    trojan_reset
    docker pull teddysun/trojan-go
    docker run -d --network host --name Trojan-Go --restart=always -v /etc/trojan-go:/etc/trojan-go teddysun/trojan-go
    judge "Trojan-Go Container Installation"
}

install_v2ray() {
    systemctl is-active "docker" &>/dev/null || install_docker
    prereqcheck
    v2ray_mode_type
    [[ $v2ray_tcp_mode = "vmess" || $v2ray_ws_mode = "vmess" ]] && check_system && chrony_install
    if [[ $v2ray_tcp_mode != "none" || $v2ray_ws_mode != "none" ]]; then
        v2ray_reset
        docker pull teddysun/v2ray
        docker run -d --network host --name V2Ray --restart=always -v /etc/v2ray:/etc/v2ray teddysun/v2ray
        judge "V2Ray container installation"
    be
}

install_watchtower() {
    docker pull containrrr/watchtower
    docker run -d --name WatchTower --restart=always -v /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower --cleanup
    judge "WatchTower container installation"
}

install_portainer() {
    docker volume create portainer_data
    docker pull portainer / portainer-ce
    docker run -d -p 9080:9000 --name Portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce
    judge "Portainer Container Installation"
    echo -e "${OK} ${GreenBG} Portainer management address is http://$TSP_Domain:9080 Please open the firewall port yourself! ${Font}"
}

install_tls_shunt_proxy() {
    check_system
    dependency_install
    basic_optimization
    domain_port_check
    port_exist_check "${tspport}"
    port_exist_check 80
    config_exist_check "${tsp_conf}"
    web_camouflage
    install_tsp
}

uninstall_all() {
    echo -e "${RedBG} !!! This operation will delete TLS-Shunt-Proxy, Docker platform and the container data installed by this script!!! ${Font}"
    read -rp "Please enter YES after confirming (case sensitive):" uninstall
    [[ -z ${uninstall} ]] && uninstall="No"
    case $uninstall in
    YES)
        echo -e "${GreenBG} start uninstalling ${Font}"
        sleep 2
        ;;
    *)
        echo -e "${RedBG} I think about ${Font}"
        exit 1
        ;;
    esac
    check_system
    uninstall_proxy_server
    uninstall_watchtower
    uninstall_portainer
    systemctl stop docker && systemctl disable docker
    if [[ "${ID}" == "centos" ]]; then
        ${INS} remove docker-ce docker-ce-cli containerd.io docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine
    else
        ${INS} remove docker-ce docker-ce-cli containerd.io docker docker-engine docker.io containerd runc
    be
    #rm -rf /var/lib/docker #Removes all docker data
    rm -rf /etc/systemd/system/docker.service
    uninstall_tsp
    echo -e "${OK} ${GreenBG} uninstallation of all components is complete, welcome to use this script again! ${Font}"
    exit 0
}

uninstall_tsp() {
    systemctl stop tls-shunt-proxy && systemctl disable tls-shunt-proxy
    rm -rf /etc/systemd/system/tls-shunt-proxy.service
    rm -rf /usr/local/bin/tls-shunt-proxy
    rm -rf $tsp_conf_dir
    userdel -rf tls-shunt-proxy
    tsp_stat="none"
    rm -rf $ {web_dir} / web_camouflage
    echo -e "${OK} ${GreenBG} TLS-Shunt-Proxy uninstallation complete! ${Font}"
    sleep 3
}

uninstall_proxy_server() {
    uninstall_trojan
    uninstall_v2ray
    echo -e "${OK} ${GreenBG} Uninstall (Trojan-Go/V2Ray) TCP/WS proxy completed! ${Font}"
    sleep 3
}

uninstall_trojan() {
    rm -rf $trojan_conf_dir
    trojan_ws_mode="none" && trojan_tcp_mode="none"
    [ -f ${tsp_conf} ] && trojan_sync
    systemctl start docker
    [[ $trojan_stat = "installed" ]] && docker stop Trojan-Go && docker rm -f Trojan-Go &&
        echo -e "${OK} ${GreenBG} Uninstalling Trojan-Go TCP/WS proxy completed! ${Font}"
}

uninstall_v2ray() {
    rm -rf $v2ray_conf_dir
    v2ray_ws_mode="none" && v2ray_tcp_mode="none"
    [ -f ${tsp_conf} ] && v2ray_sync
    systemctl start docker
    [[ $v2ray_stat = "installed" ]] && docker stop V2Ray && docker rm -f V2Ray &&
        echo -e "${OK} ${GreenBG} Uninstall V2Ray TCP/WS proxy completed! ${Font}"
}
uninstall_watchtower() {
    docker stop WatchTower && docker rm -f WatchTower && watchtower_stat="none" &&
        echo -e "${OK} ${GreenBG} Uninstalling WatchTower is complete! ${Font}"
    sleep 3
}

uninstall_portainer() {
    docker stop Portainer && docker rm -fv Portainer && portainer_stat="none" &&
        echo -e "${OK} ${GreenBG} Uninstalling Portainer is complete! ${Font}"
    sleep 3
}

upgrade_tsp() {
    current_version="$(/usr/local/bin/tls-shunt-proxy --version 2>&1 | awk 'NR==1{gsub(/"/,"");print $3}')"
    echo -e "${GreenBG} TLS-Shunt-Proxy current version: ${current_version}, start checking the latest version... ${Font}"
    latest_version="$(wget --no-check-certificate -qO- https://api.github.com/repos/liberal-boy/tls-shunt-proxy/tags | grep 'name' | cut -d\" -f4 | head -1)"
    [[ -z ${latest_version} ]] && echo -e "${Error} Failed to detect the latest version! ${Font}" && menu
    if [[ ${latest_version} != "${current_version}" ]]; then
        echo -e "${OK} ${GreenBG} Current version: ${current_version} Latest version: ${latest_version}, update (Y/N) [N]? ${Font}"
        read -r update_confirm
        [[ -z ${update_confirm} ]] && update_confirm="No"
        case $update_confirm in
        [yY][eE][sS] | [yY])
            config_exist_check "${tsp_conf}"
            bash <(curl -L -s https://raw.githubusercontent.com/liberal-boy/tls-shunt-proxy/master/dist/install.sh)
            judge "TLS-Shunt-Proxy 更新"
            systemctl daemon-reload && systemctl reset-failed
            systemctl enable tls-shunt-proxy && systemctl restart tls-shunt-proxy
            judge "TLS-Shunt-Proxy restart"
            ;;
        *) ;;
        esac
    else
        echo -e "${OK} ${GreenBG} The current TLS-Shunt-Proxy is already the latest version ${current_version} ${Font}"
    be
}

update_sh() {
    ol_version=$(curl -L -s https://raw.githubusercontent.com/h31105/trojan_v2_docker_onekey/${github_branch}/deploy.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
    echo "$ol_version" >$version_cmp
    echo "$shell_version" >>$version_cmp
    if [[ "$shell_version" < "$(sort -rV $version_cmp | head -1)" ]]; then
        echo -e "${OK} ${GreenBG} Update: ${Font}"
        echo -e "${Yellow}$(curl --silent https://api.github.com/repos/h31105/trojan_v2_docker_onekey/releases/latest | grep body | head -n 1 | awk -F '"' '{print $4}')${Font}"
        echo -e "${OK} ${GreenBG} There is a new version, do you want to update (Y/N) [N]? ${Font}"
        read -r update_confirm
        case $update_confirm in
        [yY][eE][sS] | [yY])
            wget -N --no-check-certificate https://raw.githubusercontent.com/h31105/trojan_v2_docker_onekey/${github_branch}/deploy.sh
            echo -e "${OK} ${GreenBG} update is complete, please re-run the script:\n#./deploy.sh ${Font}"
            exit 0
            ;;
        *) ;;
        esac
    else
        echo -e "${OK} ${GreenBG} The current version is the latest version ${Font}"
    be
}

list() {
    case $1 in
    uninstall)
        deployed_status_check
        uninstall_all
        ;;
    sync)
        deployed_status_check
        tsp_sync
        ;;
    debug)
        debug="enable"
        #set -xv
        menu
        ;;
    *)
        menu
        ;;
    esac
}

deployed_status_check() {
    tsp_stat="none" && trojan_stat="none" && v2ray_stat="none" && watchtower_stat="none" && portainer_stat="none"
    trojan_tcp_mode="none" && v2ray_tcp_mode="none" && trojan_ws_mode="none" && v2ray_ws_mode="none"
    tsp_config_stat="synchronized" && chrony_stat="none"

    echo -e "${OK} ${GreenBG} check the shunt configuration information... ${Font}"
    [[ -f ${tsp_conf} || -f '/usr/local/bin/tls-shunt-proxy' ]] &&
        tsp_template_version=$(grep '#TSP_CFG_Ver' ${tsp_conf} | sed -r 's/.*TSP_CFG_Ver:(.*) */\1/') && tsp_stat="installed" &&
        TSP_Port=$(grep '#TSP_Port' ${tsp_conf} | sed -r 's/.*0:(.*) #.*/\1/') && TSP_Domain=$(grep '#TSP_Domain' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/') &&
        trojan_tcp_port=$(grep '#Trojan_TCP_Port' ${tsp_conf} | sed -r 's/.*:(.*) #.*/\1/') &&
        trojan_tcp_mode=$(grep '#Trojan_TCP_Port' ${tsp_conf} | sed -r 's/.*Trojan_TCP_Port:(.*) */\1/') &&
        trojan_ws_port=$(grep '#Trojan_WS_Port' ${tsp_conf} | sed -r 's/.*:(.*) #.*/\1/') &&
        trojan_ws_mode=$(grep '#Trojan_WS_Port' ${tsp_conf} | sed -r 's/.*Trojan_WS_Port:(.*) */\1/') &&
        trojan_ws_path=$(grep '#Trojan_WS_Path' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/') &&
        v2ray_tcp_port=$(grep '#V2Ray_TCP_Port' ${tsp_conf} | sed -r 's/.*:(.*);.*/\1/') &&
        v2ray_tcp_mode=$(grep '#V2Ray_TCP_Port' ${tsp_conf} | sed -r 's/.*V2Ray_TCP_Port:(.*) */\1/') &&
        v2ray_ws_port=$(grep '#V2Ray_WS_Port' ${tsp_conf} | sed -r 's/.*:(.*);.*/\1/') &&
        v2ray_ws_mode=$(grep '#V2Ray_WS_Port' ${tsp_conf} | sed -r 's/.*V2Ray_WS_Port:(.*) */\1/') &&
        v2ray_ws_path=$(grep '#V2Ray_WS_Path' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/') &&
        menu_req_check tls-shunt-proxy

    echo -e "${OK} ${GreenBG} Check component deployment status... ${Font}"
    systemctl is-active "docker" &>/dev/null && docker ps -a | grep Trojan-Go &>/dev/null && trojan_stat="installed"
    systemctl is-active "docker" &>/dev/null && docker ps -a | grep V2Ray &>/dev/null && v2ray_stat="installed"
    systemctl is-active "docker" &>/dev/null && docker ps -a | grep WatchTower &>/dev/null && watchtower_stat="installed"
    systemctl is-active "docker" &>/dev/null && docker ps -a | grep Portainer &>/dev/null && portainer_stat="installed"

    echo -e "${OK} ${GreenBG} detection agent configuration information... ${Font}"

    if [[ -f ${trojan_conf} && $trojan_stat = "installed" ]]; then
        tjport=$(grep '"local_port"' ${trojan_conf} | sed -r 's/.*: (.*),.*/\1/')
        tjpassword=$(grep '"password"' ${trojan_conf} | awk -F '"' '{print $4}')
        [[ $trojan_ws_mode = true ]] && tjwspath=$(grep '"path":' ${trojan_conf} | awk -F '"' '{print $4}') &&
            tjwshost=$(grep '"host":' ${trojan_conf} | awk -F '"' '{print $4}')
        [[ $trojan_tcp_mode = true && $tjport != "$trojan_tcp_port" ]] && echo -e "${Error} ${RedBG} Trojan-Go TCP port shunt configuration abnormality detected ${Font}" && tsp_config_stat="mismatched "
        [[ $trojan_ws_mode = true && $tjport != "$trojan_ws_port" ]] && echo -e "${Error} ${RedBG} Trojan-Go WS port shunt configuration abnormality detected ${Font}" && tsp_config_stat="mismatched "
        [[ $trojan_ws_mode = true && $tjwspath != "$trojan_ws_path" ]] && echo -e "${Error} ${RedBG} Trojan-Go WS path shunt configuration abnormality detected ${Font}" && tsp_config_stat="mismatched "
        [[ $tsp_config_stat = "mismatched" ]] && echo -e "${Error} ${RedBG} An inconsistent shunt configuration is detected, and it will try to automatically sync and repair... ${Font}" && tsp_sync
    be

    if [[ -f ${v2ray_conf} && $v2ray_stat = "installed" ]]; then
        [[ $v2ray_tcp_mode = "vmess" ]] &&
            v2port=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="tcp") | .port][0]' ${v2ray_conf}) &&
            VMTID=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="tcp") | .settings.clients[].id][0]' ${v2ray_conf}) &&
            VMAID=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="tcp") | .settings.clients[].alterId][0]' ${v2ray_conf})
        [[ $v2ray_tcp_mode = "vless" ]] &&
            v2port=$(jq -r '[.inbounds[] | select(.protocol=="vless") | select(.streamSettings.network=="tcp") | .port][0]' ${v2ray_conf}) &&
            VLTID=$(jq -r '[.inbounds[] | select(.protocol=="vless") | select(.streamSettings.network=="tcp") | .settings.clients[].id][0]' ${v2ray_conf})
        [[ $v2ray_ws_mode = "vmess" ]] &&
            v2wsport=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="ws") | .port][0]' ${v2ray_conf}) &&
            v2wspath=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="ws") | .streamSettings.wsSettings.path][0]' ${v2ray_conf}) &&
            VMWSID=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="ws") | .settings.clients[].id][0]' ${v2ray_conf}) &&
            VMWSAID=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="ws") | .settings.clients[].alterId][0]' ${v2ray_conf})
        [[ $v2ray_ws_mode = "vless" ]] &&
            v2wsport=$(jq -r '[.inbounds[] | select(.protocol=="vless") | select(.streamSettings.network=="ws") | .port][0]' ${v2ray_conf}) &&
            v2wspath=$(jq -r '[.inbounds[] | select(.protocol=="vless") | select(.streamSettings.network=="ws") | .streamSettings.wsSettings.path][0]' ${v2ray_conf}) &&
            VLWSID=$(jq -r '[.inbounds[] | select(.protocol=="vless") | select(.streamSettings.network=="ws") | .settings.clients[].id][0]' ${v2ray_conf})
        [[ $v2ray_tcp_mode = v*ess && $v2port != "$v2ray_tcp_port" ]] && echo -e "${Error} ${RedBG} V2Ray TCP port shunt configuration abnormality detected ${Font}" && tsp_config_stat="mismatched "
        [[ $v2ray_ws_mode = v*ess && $v2wsport != "$v2ray_ws_port" ]] && echo -e "${Error} ${RedBG} V2Ray WS port shunt configuration abnormality detected ${Font}" && tsp_config_stat="mismatched "
        [[ $v2ray_ws_mode = v*ess && $v2wspath != "$v2ray_ws_path" ]] && echo -e "${Error} ${RedBG} V2Ray WS path shunt configuration abnormality detected ${Font}" && tsp_config_stat="mismatched "
        [[ $tsp_config_stat = "mismatched" ]] && echo -e "${Error} ${RedBG} An inconsistent shunt configuration is detected, and it will try to automatically sync and repair... ${Font}" && tsp_sync
        if [[ $v2ray_tcp_mode = "vmess" || $v2ray_ws_mode = "vmess" ]]; then
            if [[ "${ID}" == "centos" ]]; then
                systemctl is-active "chronyd" &>/dev/null || chrony_stat=inactive
            else
                systemctl is-active "chrony" &>/dev/null || chrony_stat=inactive
            be
            if [[ $chrony_stat = inactive ]]; then
                echo -e "${Error} ${RedBG} It is detected that the Chrony time synchronization service is not started. If the system time is not accurate, it will seriously affect the availability of the V2Ray VMess protocol. ${Font}\n${WARN} ${Yellow} Current System time: $(date), please confirm whether the time is accurate, within ±3 minutes (Y) or try to repair the time synchronization service (R) [R]: ${Font}"
                read -r chrony_confirm
                [[ -z ${chrony_confirm} ]] && chrony_confirm="R"
                case $chrony_confirm in
                [rR])
                    echo -e "${GreenBG} install Chrony time synchronization service${Font}"
                    check_system
                    chrony_install
                    ;;
                *) ;;
                esac
            be
        be
    be

    [[ -f ${trojan_conf} || -f ${v2ray_conf} || $trojan_stat = "installed" || $v2ray_stat = "installed" ]] && menu_req_check docker
    [[ $trojan_stat = "installed" &&! -f $trojan_conf ]] && echo -e "\n${Error} ${RedBG} Trojan-Go proxy configuration abnormality has been detected. The following options will be blocked. Please try again Retry after installation and repair... ${Font}" &&
        echo -e "${WARN} ${Yellow}[Shield] Trojan-Go configuration modification ${Font}"
    [[ $v2ray_stat = "installed" &&! -f $v2ray_conf ]] && echo -e "\n${Error} ${RedBG} An abnormal V2Ray proxy configuration has been detected. The following options will be blocked, please try to reinstall and fix Try again later... ${Font}" &&
        echo -e "${WARN} ${Yellow}[Shield] V2Ray configuration modification ${Font}"

    if [[ $tsp_stat = "installed" && $tsp_template_version != "${tsp_cfg_version}" ]]; then
        echo -e "${WARN} ${Yellow} detected a critical update of TLS-Shunt-Proxy. To ensure that the script runs normally, please confirm to perform the update operation immediately (Y/N) [Y] ${Font}"
        read -r upgrade_confirm
        [[ -z ${upgrade_confirm} ]] && upgrade_confirm="Yes"
        case $upgrade_confirm in
        [yY][eE][sS] | [yY])
            uninstall_tsp
            install_tls_shunt_proxy
            tsp_sync
            deployed_status_check
            ;;
        *) ;;
        esac
    be

    [[ $debug = "enable" ]] && echo -e "\n Trojan-Go 代理：TCP：${Green}${trojan_tcp_mode}${Font} / WebSocket：${Green}${trojan_ws_mode}${Font}\n     V2Ray 代理：TCP：${Green}${v2ray_tcp_mode}${Font} / WebSocket：${Green}${v2ray_ws_mode}${Font}" &&
        echo -e "\n 代理容器：Trojan-Go：${Green}${trojan_stat}${Font} / V2Ray：${Green}${v2ray_stat}${Font}" &&
        echo -e "Other containers: WatchTower: ${Green}${watchtower_stat}${Font} / Portainer: ${Green}${portainer_stat}${Font}\n"
}

info_config() {
    deployed_status_check
    cert_stat_check tls-shunt-proxy
    echo -e "\n———————————————————— Shunt configuration information————————————————————"
    if [ -f ${tsp_conf} ]; then
        echo -e "TLS-Shunt-Proxy $(/usr/local/bin/tls-shunt-proxy --version 2>&1 | awk 'NR==1{gsub(/"/,"");print $3}')" &&
            echo -e "Server TLS port: ${TSP_Port}" && echo -e "Server TLS domain name: ${TSP_Domain}"
        [[ $trojan_tcp_mode = true ]] && echo -e "Trojan-Go TCP tap port: $trojan_tcp_port" && echo -e "Trojan-Go listening port: $tjport"
        [[ $trojan_ws_mode = true ]] && echo -e "Trojan-Go WebSocket 分流端口: $trojan_ws_port" &&
            echo -e "Trojan-Go WebSocket tap path: $trojan_ws_path"
        [[ $v2ray_tcp_mode = v*ess ]] && echo -e "V2Ray TCP tap port: $v2ray_tcp_port" && echo -e "V2Ray TCP listening port: $v2port"
        [[ $v2ray_ws_mode = v*ess ]] && echo -e "V2Ray WebSocket tap port: $v2ray_ws_port" && echo -e "V2Ray WS listening port: $v2wsport" &&
            echo -e "V2Ray WebSocket shunt path: $v2ray_ws_path"
    be

    if [[ -f ${trojan_conf} && $trojan_stat = "installed" ]]; then
        echo -e "—————————————————— Trojan-Go 配置 ——————————————————" &&
            echo -e "$(docker exec Trojan-Go sh -c 'trojan-go --version' 2>&1 | awk 'NR==1{gsub(/"/,"");print}')" &&
            echo -e "Server port: ${TSP_Port}" && echo -e "Server address: ${TSP_Domain}"
        [[ $trojan_tcp_mode = true ]] && echo -e "Trojan-Go 密码: ${tjpassword}"
        [[ $trojan_ws_mode = true ]] &&
            echo -e "Trojan-Go WebSocket Path: ${tjwspath}" && echo -e "Trojan-Go WebSocket Host: ${tjwshost}"
    be

    if [[ -f ${v2ray_conf} && $v2ray_stat = "installed" ]]; then
        echo -e "\n———————————————————— V2Ray 配置 ————————————————————" &&
            echo -e "$(docker exec V2Ray sh -c 'v2ray --version' 2>&1 | awk 'NR==1{gsub(/"/,"");print}')" &&
            echo -e "Server port: ${TSP_Port}" && echo -e "Server address: ${TSP_Domain}"
        [[ $v2ray_tcp_mode = "vmess" ]] && echo -e "\nVMess TCP UUID: ${VMTID}" &&
            echo -e "VMess AlterID: ${VMAID}" && echo -e "VMess 加密方式: Auto" && echo -e "VMess Host: ${TSP_Domain}"
        [[ $v2ray_tcp_mode = "vless" ]] && echo -e "\nVLESS TCP UUID: ${VLTID}" &&
            echo -e "VLESS encryption method: none" && echo -e "VLESS Host: ${TSP_Domain}"
        [[ $v2ray_ws_mode = "vmess" ]] && echo -e "\nVMess WS UUID: ${VMWSID}" && echo -e "VMess AlterID: $VMWSAID" &&
            echo -e "VMess 加密方式: Auto" && echo -e "VMess WebSocket Host: ${TSP_Domain}" && echo -e "VMess WebSocket Path: ${v2wspath}"
        [[ $v2ray_ws_mode = "vless" ]] && echo -e "\nVLESS WS UUID: ${VLWSID}" &&
            echo -e "VLESS 加密方式: none" && echo -e "VLESS WebSocket Host: ${TSP_Domain}" && echo -e "VLESS WebSocket Path: ${v2wspath}"
    be

    echo -e "————————————————————————————————————————————————————\n"
    read -t 60 -n 1 -s -rp "Press any key to continue (60s)..."
    clear
}

info_links() {
    deployed_status_check
    cert_stat_check tls-shunt-proxy
    if [[ -f ${trojan_conf} && $trojan_stat = "installed" ]]; then
        echo -e "———————————————— Trojan-Go Share Link————————————————" &&
            [[ $trojan_tcp_mode = true ]] && echo -e "\n Trojan-Go TCP TLS share link:" &&
            echo -e " Trojan 客户端：\n trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?sni=${TSP_Domain}&allowinsecure=0&mux=0#${HOSTNAME}-TCP" &&
            echo -e "Qv2ray client (Trojan-Go plug-in is required):\n trojan-go://${tjpassword}@${TSP_Domain}:${TSP_Port}/?sni=${TSP_Domain}&type=original&host= ${TSP_Domain}#${HOSTNAME}-TCP" &&
            echo -e "Shadowrocket QR code:" &&
            qrencode -t ANSIUTF8 -s 1 -m 2 "trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?sni=${TSP_Domain}&peer=${TSP_Domain}&allowinsecure=0&mux=0#${HOSTNAME}-TCP"
        [[ $trojan_ws_mode = true ]] && echo -e "\n Trojan-Go WebSocket TLS share link:" &&
            echo -e " Trojan-Qt5 客户端：\n trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?sni=${TSP_Domain}&peer=${TSP_Domain}&allowinsecure=0&mux=1&ws=1&wspath=${tjwspath}&wshost=${TSP_Domain}#${HOSTNAME}-WS" &&
            echo -e "Qv2ray client (Trojan-Go plug-in is required):\n trojan-go://${tjpassword}@${TSP_Domain}:${TSP_Port}/?sni=${TSP_Domain}&type=ws&host= ${TSP_Domain}&path=${tjwspath}#${HOSTNAME}-WS" &&
            echo -e "Shadowrocket QR code:" &&
            qrencode -t ANSIUTF8 -s 1 -m 2 "trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?peer=${TSP_Domain}&mux=1&plugin=obfs-local;obfs=websocket;obfs-host=${TSP_Domain};obfs-uri=${tjwspath}#${HOSTNAME}-WS"
	read -t 60 -n 1 -s -rp "Press any key to continue (60s)..."
    be

    if [[ -f ${v2ray_conf} && $v2ray_stat = "installed" ]]; then
        echo -e "\n—————————————————— V2Ray share link————————————————" &&
            [[ $v2ray_tcp_mode = "vmess" ]] && echo -e "\n VMess TCP TLS share link:" &&
            echo -e " V2RayN 格式：\n vmess://$(echo "{\"add\":\"${TSP_Domain}\",\"aid\":\"0\",\"host\":\"${TSP_Domain}\",\"peer\":\"${TSP_Domain}\",\"id\":\"${VMTID}\",\"net\":\"tcp\",\"port\":\"${TSP_Port}\",\"ps\":\"${HOSTNAME}-TCP\",\"tls\":\"tls\",\"type\":\"none\",\"v\":\"2\"}" | base64 -w 0)" &&
            echo -e " VMess 新版格式：\n vmess://tcp+tls:${VMTID}-0@${TSP_Domain}:${TSP_Port}/?tlsServerName=${TSP_Domain}#$(urlEncode "${HOSTNAME}-TCP")" &&
            echo -e "Shadowrocket QR code:" &&
            qrencode -t ANSIUTF8 -s 1 -m 2 "vmess://$(echo "auto:${VMTID}@${TSP_Domain}:${TSP_Port}" | base64 -w 0)?tls=1&mux=1&peer=${TSP_Domain}&allowInsecure=0&tfo=0&remarks=${HOSTNAME}-TCP"
        [[ $v2ray_ws_mode = "vmess" ]] && echo -e "\n VMess WebSocket TLS share link:" &&
            echo -e " V2RayN 格式：\n vmess://$(echo "{\"add\":\"${TSP_Domain}\",\"aid\":\"0\",\"host\":\"${TSP_Domain}\",\"peer\":\"${TSP_Domain}\",\"id\":\"${VMWSID}\",\"net\":\"ws\",\"path\":\"${v2wspath}\",\"port\":\"${TSP_Port}\",\"ps\":\"${HOSTNAME}-WS\",\"tls\":\"tls\",\"type\":\"none\",\"v\":\"2\"}" | base64 -w 0)" &&
            echo -e " VMess 新版格式：\n vmess://ws+tls:${VMWSID}-0@${TSP_Domain}:${TSP_Port}/?path=$(urlEncode "${v2wspath}")&host=${TSP_Domain}&tlsServerName=${TSP_Domain}#$(urlEncode "${HOSTNAME}-WS")" &&
            echo -e "Shadowrocket QR code:" &&
            qrencode -t ANSIUTF8 -s 1 -m 2 "vmess://$(echo "auto:${VMWSID}@${TSP_Domain}:${TSP_Port}" | base64 -w 0)?tls=1&mux=1&peer=${TSP_Domain}&allowInsecure=0&tfo=0&remarks=${HOSTNAME}-WS&obfs=websocket&obfsParam=${TSP_Domain}&path=${v2wspath}"
        [[ $v2ray_tcp_mode = "vless" ]] && echo -e "\n VLESS TCP TLS share link: The official specification has not been released yet, please follow the proxy configuration information in the script option "9" to manually configure the client."
        [[ $v2ray_ws_mode = "vless" ]] && echo -e "\n VLESS WebSocket TLS share link: The official specification has not been released yet, please follow the proxy configuration information in the script option "9" to manually configure the client."
	read -t 60 -n 1 -s -rp "Press any key to continue (60s)..."
    be

    if [[ -f ${v2ray_conf} || -f ${trojan_conf} ]]; then
        echo -e "\n——————————————————— Subscribe to link information——————————————————"
        rm -rf "$(grep '#Website' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/')"/subscribe*
        cat >"$(grep '#Website' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/')"/robots.txt <<-EOF
User-agent: *
Disallow: /
EOF
        subscribe_file="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        subscribe_links | base64 -w 0 >"$(grep '#Website' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/')"/subscribe"${subscribe_file}"
        echo -e "Subscription link:\n https://${TSP_Domain}/subscribe${subscribe_file} \n${Yellow} Please note: The subscription link generated by the script includes all the protocols currently deployed on the server (except VLESS) proxy For configuration information, for information security considerations, the link address will be randomly refreshed every time you view it!\nIn addition, since different clients have different levels of compatibility and support for proxy protocols, please adjust them according to the actual situation!${Font} "
	read -t 60 -n 1 -s -rp "Press any key to continue (60s)..."
    be

    clear
}

subscribe_links() {
    if [[ -f ${trojan_conf} && $trojan_stat = "installed" ]]; then
        [[ $trojan_tcp_mode = true ]] &&
            echo -e "trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?sni=${TSP_Domain}&peer=${TSP_Domain}&allowinsecure=0&mux=0#${HOSTNAME}-TCP" &&
            echo -e "trojan-go://${tjpassword}@${TSP_Domain}:${TSP_Port}/?sni=${TSP_Domain}&type=original&host=${TSP_Domain}#${HOSTNAME}-Trojan-Go-TCP"
        [[ $trojan_ws_mode = true ]] &&
            echo -e "trojan-go://${tjpassword}@${TSP_Domain}:${TSP_Port}/?sni=${TSP_Domain}&type=ws&host=${TSP_Domain}&path=${tjwspath}#${HOSTNAME}-Trojan-Go-WS" &&
            echo -e "trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?peer=${TSP_Domain}&mux=1&plugin=obfs-local;obfs=websocket;obfs-host=${TSP_Domain};obfs-uri=${tjwspath}#${HOSTNAME}-Trojan-Go-WS"
    be

    if [[ -f ${v2ray_conf} && $v2ray_stat = "installed" ]]; then
        [[ $v2ray_tcp_mode = "vmess" ]] &&
            echo -e "vmess://$(echo "{\"add\":\"${TSP_Domain}\",\"aid\":\"0\",\"host\":\"${TSP_Domain}\",\"peer\":\"${TSP_Domain}\",\"id\":\"${VMTID}\",\"net\":\"tcp\",\"port\":\"${TSP_Port}\",\"ps\":\"${HOSTNAME}-TCP\",\"tls\":\"tls\",\"type\":\"none\",\"v\":\"2\"}" | base64 -w 0)" &&
            echo -e "vmess://tcp+tls:${VMTID}-0@${TSP_Domain}:${TSP_Port}/?tlsServerName=${TSP_Domain}#$(urlEncode "${HOSTNAME}-新版格式-TCP")"
        [[ $v2ray_ws_mode = "vmess" ]] &&
            echo -e "vmess://$(echo "{\"add\":\"${TSP_Domain}\",\"aid\":\"0\",\"host\":\"${TSP_Domain}\",\"peer\":\"${TSP_Domain}\",\"id\":\"${VMWSID}\",\"net\":\"ws\",\"path\":\"${v2wspath}\",\"port\":\"${TSP_Port}\",\"ps\":\"${HOSTNAME}-WS\",\"tls\":\"tls\",\"type\":\"none\",\"v\":\"2\"}" | base64 -w 0)" &&
            echo -e "vmess://ws+tls:${VMWSID}-0@${TSP_Domain}:${TSP_Port}/?path=$(urlEncode "${v2wspath}")&host=${TSP_Domain}&tlsServerName=${TSP_Domain}#$(urlEncode "${HOSTNAME}-新版格式-WS")"
    be
}

cert_stat_check () {
    echo -e "${OK} ${GreenBG} check certificate status information... ${Font}"
    if systemctl is-active "$1" &>/dev/null; then
        [[ $1 = "tls-shunt-proxy" ]] && [[ ! -f ${tsp_cert_dir}/${TSP_Domain}/${TSP_Domain}.crt || ! -f ${tsp_cert_dir}/${TSP_Domain}/${TSP_Domain}.json || ! -f ${tsp_cert_dir}/${TSP_Domain}/${TSP_Domain}.key ]] &&
            echo -e "${Yellow} did not detect a valid SSL certificate, please execute the following command:\n#systemctl restart tls-shunt-proxy\n#journalctl -u tls-shunt-proxy.service\nCheck the log and wait After completing the certificate application, re-run the script ${Font}" && exit 4
    be
}

menu_req_check() {
    if systemctl is-active "$1" &>/dev/null; then
        [[ $debug = "enable" ]] && echo -e "${OK} ${GreenBG} $1 has started ${Font}"
    else
        echo -e "\n${Error} ${RedBG} detected that the $1 service did not start successfully. According to the dependencies, the following options will be blocked, please fix and try again... ${Font}"
        [[ $1 = "tls-shunt-proxy" ]] && echo -e "${Yellow}[Shield] Install (Trojan-Go/V2Ray) TCP/WS proxy\n[Shield] (Trojan-Go/V2Ray) configuration Modify\n[Shield] View configuration information ${Font}"
        [[ $1 = "docker" ]] && echo -e "${Yellow}[Shield] Install/Uninstall WatchTower (Automatic Update Container)\n[Shield] Install/Uninstall Portainer (Web Management Container)${Font}"
        read -t 60 -n 1 -s -rp "Press any key to continue (60s)..."
    be
}

menu() {
    deployed_status_check
    echo -e "\n${Green} TSP & Trojan-Go/V2Ray deployment script version: ${shell_version} ${Font}"
    echo -e "${Yellow} Telegram exchange group: https://t.me/trojanv2${Font}\n"
    echo -e "——————————————————————Deployment Management—————————————————————— "
    if [[ $tsp_stat = "installed" ]]; then
        echo -e "${Green}1.${Font} ${Yellow} uninstall ${Font} TLS-Shunt-Proxy (website & automatic management certificate)"
    else
        echo -e "${Green}1.${Font} Install TLS-Shunt-Proxy (website & automatic management certificate)"
    be
    systemctl is-active "tls-shunt-proxy" &>/dev/null &&
        if [[ $trojan_stat = "none" ]]; then
            echo -e "${Green}2.${Font} install Trojan-Go TCP/WS proxy"
        else
            echo -e "${Green}2.${Font} ${Yellow} uninstall ${Font} Trojan-Go TCP/WS proxy"
        be
    systemctl is-active "tls-shunt-proxy" &>/dev/null &&
        if [[ $v2ray_stat = "none" ]]; then
            echo -e "${Green}3.${Font} install V2Ray TCP/WS proxy"
        else
            echo -e "${Green}3.${Font} ${Yellow} uninstall ${Font} V2Ray TCP/WS proxy"
        be
    systemctl is-active "docker" &>/dev/null &&
        if [[ $watchtower_stat = "none" ]]; then
            echo -e "${Green}4.${Font} Install WatchTower (automatically update the container)"
        else
            echo -e "${Green}4.${Font} ${Yellow} uninstall ${Font} WatchTower (automatically update the container)"
        be
    systemctl is-active "docker" &>/dev/null &&
        if [[ $portainer_stat = "none" ]]; then
            echo -e "${Green}5.${Font} Install Portainer (Web Management Container)"
        else
            echo -e "${Green}5.${Font} ${Yellow} Uninstall ${Font} Portainer (Web Management Container)"
        be
    systemctl is-active "tls-shunt-proxy" &>/dev/null &&
        echo -e "—————————————————————— Configuration modification—————————————————————— "&&
        echo -e "${Green}6.${Font} modify TLS port/domain name" &&
        [[ $trojan_stat = "installed" && -f ${trojan_conf} ]] && echo -e "${Green}7.${Font} modify Trojan-Go proxy configuration"
    systemctl is-active "tls-shunt-proxy" &>/dev/null &&
        [[ $v2ray_stat = "installed" && -f ${v2ray_conf} ]] && echo -e "${Green}8.${Font} modify V2Ray proxy configuration"
    systemctl is-active "tls-shunt-proxy" &>/dev/null &&
        echo -e "—————————————————————— View information—————————————————————— "&&
        echo -e "${Green}9.${Font} View configuration information" &&
        [[ $trojan_stat = "installed" || $v2ray_stat = "installed" ]] && echo -e "${Green}10.${Font} View sharing/subscription links"
    echo -e "—————————————————————— Miscellaneous Management—————————————————————— "
    [-f ${tsp_conf}] && echo -e "${Green}11.${Font} Upgrade TLS-Shunt-Proxy/Docker base platform" &&
        echo -e "${Green}12.${Font} ${Yellow} uninstall all components installed by ${Font}"
    echo -e "${Green}13.${Font} install 4 in 1 BBR sharp speed script"
    echo -e "${Green}14.${Font} Run SuperSpeed ​​test script"
    echo -e "${Green}0.${Font} Exit script"
    echo -e "————————————————————————————————————————————————————\n"
    read -rp "Please enter a number:" menu_num
    case "$menu_num" in
    1)
        if [[ $tsp_stat = "installed" ]]; then
            uninstall_tsp
        else
            install_tls_shunt_proxy
            tsp_sync
        be
        ;;
    2)
        systemctl is-active "tls-shunt-proxy" &>/dev/null &&
            if [[ $trojan_stat = "none" ]]; then
                install_trojan
            else
                uninstall_trojan
            be
        ;;
    3)
        systemctl is-active "tls-shunt-proxy" &>/dev/null &&
            if [[ $v2ray_stat = "none" ]]; then
                install_v2ray
            else
                uninstall_v2ray
            be
        ;;
    4)
        systemctl is-active "docker" &>/dev/null &&
            if [[ $watchtower_stat = "none" ]]; then
                install_watchtower
            else
                uninstall_watchtower
            be
        ;;
    5)
        systemctl is-active "docker" &>/dev/null &&
            if [[ $portainer_stat = "none" ]]; then
                install_portainer
            else
                uninstall_portainer
            be
        ;;
    6)
        systemctl is-active "tls-shunt-proxy" &>/dev/null && modify_tsp
        ;;
    7)
        systemctl is-active "tls-shunt-proxy" &>/dev/null && [[ -f ${trojan_conf} && $trojan_stat = "installed" ]] && modify_trojan
        ;;
    8)
        systemctl is-active "tls-shunt-proxy" &>/dev/null && [[ -f ${v2ray_conf} && $v2ray_stat = "installed" ]] && modify_v2ray
        ;;
    9)
        systemctl is-active "tls-shunt-proxy" &>/dev/null && info_config
        ;;
    10)
        systemctl is-active "tls-shunt-proxy" &>/dev/null && info_links
        ;;
    11)
        [-f ${tsp_conf}] && read -rp "Please confirm whether to upgrade the TLS-Shunt-Proxy shunt component, (Y/N) [N]:" upgrade_mode
        [[ -z ${upgrade_mode} ]] && upgrade_mode="none"
        case $upgrade_mode in
        [yY])
            echo -e "${GreenBG} start to upgrade TLS-Shunt-Proxy shunt component${Font}"
            upgrade_mode="Tsp"
            sleep 1
            upgrade_tsp
            ;;
        *)
            echo -e "${GreenBG} Skip to upgrade TLS-Shunt-Proxy shunt component ${Font}"
            ;;
        esac
        [-f ${tsp_conf}] && read -rp "Please confirm whether to upgrade the Docker platform components, (Y/N) [N]:" upgrade_mode
        [[ -z ${upgrade_mode} ]] && upgrade_mode="none"
        case $upgrade_mode in
        [yY])
            echo -e "${GreenBG} began to upgrade the Docker platform components ${Font}"
            upgrade_mode="Docker"
            sleep 1
            install_docker
            ;;
        *)
            echo -e "${GreenBG} skip upgrading Docker platform components ${Font}"
            ;;
        esac
        ;;
    12)
        [ -f ${tsp_conf} ] && uninstall_all
        ;;
    13)
        kernel_change="YES"
        systemctl is-active "docker" &>/dev/null && echo -e "${RedBG} !!! Since Docker is closely related to the system kernel, changing the system kernel may cause Docker to not work normally!!! ${Font}\ n${WARN} ${Yellow} If Docker cannot start normally after the kernel is replaced, please try to fix it through the script <Option 10: Upgrade Docker> or <Option 11: Complete uninstall> and redeploy ${Font}" &&
            read -rp "Please enter YES after confirmation (case sensitive):" kernel_change
        [[ -z ${kernel_change} ]] && kernel_change="no"
        case $kernel_change in
        YES)
            [ -f "tcp.sh" ] && rm -rf ./tcp.sh
            wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh" && chmod +x tcpx.sh && ./tcpx.sh
            ;;
        *)
            echo -e "${RedBG} I think about ${Font}"
            exit 0
            ;;
        esac
        ;;
    14)
        bash <(curl -Lso- https://git.io/superspeed)
        ;;
    0)
        exit 0
        ;;
    *)
        echo -e "${RedBG} Please enter the correct number ${Font}"
        sleep 3
        ;;
    esac
    menu
}

clear
is_root
update_sh
list "$1"
