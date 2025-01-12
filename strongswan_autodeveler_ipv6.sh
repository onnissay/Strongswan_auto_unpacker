#!/bin/bash
# Обновление системы
apt update
myip=$(wget -qO - eth0.me)

# Установка StrongSwan и необходимых пакетов
apt install -y strongswan strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins

# Создание PKI инфраструктуры
mkdir -p ~/pki/{cacerts,certs,private}
chmod 700 ~/pki

# Генерация ключей и сертификатов
pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/ca-key.pem

pki --self --ca --lifetime 3650 --in ~/pki/private/ca-key.pem \
--type rsa --dn "CN=VPN root CA" --outform pem > ~/pki/cacerts/ca-cert.pem

pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/server-key.pem

pki --pub --in ~/pki/private/server-key.pem --type rsa \
    | pki --issue --lifetime 1825 \
        --cacert ~/pki/cacerts/ca-cert.pem \
        --cakey ~/pki/private/ca-key.pem \
        --dn "CN=$myip" --san @$myip --san $myip \
        --flag serverAuth --flag ikeIntermediate --outform pem \
    >  ~/pki/certs/server-cert.pem

# Копирование сертификатов в StrongSwan
cp -r ~/pki/* /etc/ipsec.d/

# Резервная копия конфигурации StrongSwan
mv /etc/ipsec.conf{,.original}

# Конфигурация StrongSwan с поддержкой IPv6
cat << EOF > /etc/ipsec.conf
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
    rekey=yes
    ikelifetime=60m
    keylife=20m
    left=%any
    leftid=$myip
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0,::/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24,2001:db8:1::/64
    rightdns=8.8.8.8,8.8.4.4,2001:4860:4860::8888
    rightsendcert=never
    eap_identity=%identity
    ike=chacha20poly1305-sha512-curve25519-prfsha512,aes256gcm16-sha384-prfsha384-ecp384,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024,aes256-sha256-modp2048!
    esp=chacha20poly1305-sha512,aes256gcm16-ecp384,aes256-sha256,aes256-sha1,3des-sha1!
EOF

# Настройка пользователей для VPN
cat << EOF > /etc/ipsec.secrets
: RSA "server-key.pem"
# user : EAP "password" - добавить пользователей здесь
EOF

# Настройка UFW (включая поддержку IPv6)
ufw allow OpenSSH
ufw allow 500,4500/udp

# Добавление правил для NAT (IPv4 и IPv6)
cat << EOF > /etc/ufw/before.rules
*nat
# change eth0 / ens3 interface to yours
-A POSTROUTING -s 10.10.10.0/24 -o ens3 -m policy --pol ipsec --dir out -j ACCEPT
-A POSTROUTING -s 10.10.10.0/24 -o ens3 -j MASQUERADE
-A POSTROUTING -s 2001:db8:1::/64 -o ens3 -m policy --pol ipsec --dir out -j ACCEPT
-A POSTROUTING -s 2001:db8:1::/64 -o ens3 -j MASQUERADE
COMMIT

*mangle
# change eth0 / ens3 interface to yours
-A FORWARD --match policy --pol ipsec --dir in -s 10.10.10.0/24 -o ens3 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360
-A FORWARD --match policy --pol ipsec --dir in -s 2001:db8:1::/64 -o ens3 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360
COMMIT
EOF

# Включение форвардинга пакетов
cat << EOF >> /etc/ufw/sysctl.conf
net/ipv4/ip_forward=1
net/ipv6/conf/all/forwarding=1
net/ipv4/conf/all/accept_redirects=0
net/ipv4/conf/all/send_redirects=0
net/ipv6/conf/all/accept_redirects=0
net/ipv6/conf/default/accept_redirects=0
EOF

# Перезапуск UFW
ufw disable
ufw enable