#!/bin/bash
###############################################################################
# Скрипт установки StrongSwan (IKEv2) с поддержкой IPv4 и IPv6 (Dual Stack).
# ВНИМАНИЕ: Меняйте "ens3" на свой сетевой интерфейс в нужных местах!
###############################################################################

# Обновляем пакеты
apt update

# Определяем основной публичный IPv4 (для сертификата)
myip=$(wget -qO - eth0.me)

# Устанавливаем пакеты StrongSwan и необходимые плагины
apt install -y strongswan strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins

# Создаём структуры каталогов для сертификатов
mkdir -p ~/pki/cacerts
mkdir -p ~/pki/certs
mkdir -p ~/pki/private
chmod 700 ~/pki

###############################################################################
# Генерируем корневой сертификат (CA)
###############################################################################
pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/ca-key.pem

pki --self --ca --lifetime 3650 \
   --in ~/pki/private/ca-key.pem \
   --type rsa \
   --dn "CN=VPN root CA" \
   --outform pem > ~/pki/cacerts/ca-cert.pem

###############################################################################
# Генерируем ключ сервера и сам сертификат
###############################################################################
pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/server-key.pem

pki --pub --in ~/pki/private/server-key.pem --type rsa \
    | pki --issue --lifetime 1825 \
        --cacert ~/pki/cacerts/ca-cert.pem \
        --cakey ~/pki/private/ca-key.pem \
        --dn "CN=$myip" \
        --san @$myip \
        --san $myip \
        --flag serverAuth \
        --flag ikeIntermediate \
        --outform pem >  ~/pki/certs/server-cert.pem

# Переносим сертификаты в /etc/ipsec.d/
cp -r ~/pki/* /etc/ipsec.d/

###############################################################################
# Конфиг StrongSwan (/etc/ipsec.conf)
###############################################################################
# Делаем бэкап оригинального файла, если ещё не сделан
[ ! -f /etc/ipsec.conf.original ] && mv /etc/ipsec.conf /etc/ipsec.conf.original

cat << EOF > /etc/ipsec.conf
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

# Подключение IKEv2
conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes

    # Мониторинг соединений
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
    rekey=yes

    # Время жизни SA
    ikelifetime=60m
    keylife=20m

    # Локальная (серверная) сторона
    left=%any
    leftid=$myip
    leftcert=server-cert.pem
    leftsendcert=always
    
    # Обратите внимание: теперь отдаем маршруты и по IPv4, и по IPv6
    leftsubnet=0.0.0.0/0,::/0

    # Удалённая (клиентская) сторона
    right=%any
    rightid=%any
    rightauth=eap-mschapv2

    # Пулы адресов IPv4 и IPv6, которые будут получать клиенты
    rightsourceip=10.10.10.0/24,fd00:10:10:10::/64

    # DNS-серверы (включая IPv6 адреса Google DNS)
    rightdns=8.8.8.8,8.8.4.4,2001:4860:4860::8888,2001:4860:4860::8844

    rightsendcert=never
    eap_identity=%identity

    # Шифры
    ike=chacha20poly1305-sha512-curve25519-prfsha512,aes256gcm16-sha384-prfsha384-ecp384,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024,aes256-sha256-modp2048!
    esp=chacha20poly1305-sha512,aes256gcm16-ecp384,aes256-sha256,aes256-sha1,3des-sha1!
EOF

###############################################################################
# ipsec.secrets (логин/пароль пользователей)
###############################################################################
cat << EOF > /etc/ipsec.secrets
: RSA "server-key.pem"
# Добавляйте внизу пользователя в формате:
# your_username : EAP "your_password"
# Затем: sudo systemctl restart strongswan-starter
EOF

###############################################################################
# Настройка Firewall (UFW)
###############################################################################
ufw allow OpenSSH
# Включаем UFW, если ещё не включен
ufw enable

# Разрешаем порты 500 и 4500 по UDP (оба протокола, IPv4 и IPv6)
ufw allow 500/udp
ufw allow 4500/udp

# Вносим правила NAT и другие важные настройки в /etc/ufw/before.rules
# (NAT только для IPv4, для IPv6 обычно NAT не требуется и не рекомендуется)
cat << EOF > /etc/ufw/before.rules
*nat
# Измените ens3 на ваш интерфейс!
-A POSTROUTING -s 10.10.10.0/24 -o ens3 -m policy --pol ipsec --dir out -j ACCEPT
-A POSTROUTING -s 10.10.10.0/24 -o ens3 -j MASQUERADE
COMMIT

*mangle
# Измените ens3 на ваш интерфейс!
-A FORWARD --match policy --pol ipsec --dir in -s 10.10.10.0/24 -o ens3 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360
COMMIT

#
# rules.before (стандартные правила UFW ниже)
#
# Rules that should be run before the ufw command line added rules.
# ...
*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
:ufw-not-local - [0:0]

# Разрешаем ESP-трафик (IPsec) во внутренней цепочке
-A ufw-before-forward --match policy --pol ipsec --dir in --proto esp -s 10.10.10.0/24 -j ACCEPT
-A ufw-before-forward --match policy --pol ipsec --dir out --proto esp -d 10.10.10.0/24 -j ACCEPT

# Разрешаем петлю (loopback)
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT

# Разрешаем уже установленный трафик
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Отбрасываем неверные пакеты
-A ufw-before-input -m conntrack --ctstate INVALID -j ufw-logging-deny
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP

# Разрешаем ICMP (echo-request и т.д.)
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT

# Разрешаем DHCP (67->68)
-A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT

# ufw-not-local
-A ufw-before-input -j ufw-not-local

# Если пакет локальный - RETURN
-A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN
-A ufw-not-local -m addrtype --dst-type MULTICAST -j RETURN
-A ufw-not-local -m addrtype --dst-type BROADCAST -j RETURN

# Остальные не-локальные пакеты дропаем
-A ufw-not-local -m limit --limit 3/min --limit-burst 10 -j ufw-logging-deny
-A ufw-not-local -j DROP

# Разрешаем mDNS и UPnP (по необходимости)
-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT
-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT

COMMIT
EOF

###############################################################################
# Разрешаем форвардинг IPv4 и IPv6 в sysctl
###############################################################################
cat << EOF >> /etc/ufw/sysctl.conf
# IPv4
net/ipv4/ip_forward=1
net/ipv4/conf/all/accept_redirects=0
net/ipv4/conf/all/send_redirects=0
net/ipv4/ip_no_pmtu_disc=1

# IPv6
net/ipv6/conf/all/forwarding=1
EOF

# Перезагружаем UFW (правила + sysctl)
ufw disable
ufw enable

echo "========================================"
echo "Установка StrongSwan с поддержкой IPv6 завершена!"
echo "Отредактируйте /etc/ipsec.secrets, добавьте пользователей и перезапустите strongSwan:"
echo "  sudo nano /etc/ipsec.secrets"
echo "  sudo systemctl restart strongswan-starter"
echo "========================================"