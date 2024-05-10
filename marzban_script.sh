#!/bin/bash

clear
#domain
read -rp "Masukkan Domain: " domain
echo "$domain" > /root/domain
domain=$(cat /root/domain)

#Preparation
clear
cd;
apt-get update;


#install bbr
echo 'fs.file-max = 500000
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.rmem_max=4000000
net.ipv4.tcp_mtu_probing = 1
net.ipv4.ip_forward=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1' >> /etc/sysctl.conf
sysctl -p;

#Set Timezone GMT+7
timedatectl set-timezone Asia/Jakarta;

#Install Marzban
sudo bash -c "$(curl -sL https://github.com/claudialubowitz26/Marzban-scripts/raw/master/marzban.sh)" @ install

#Install Subs
wget -N -P /opt/marzban https://raw.githubusercontent.com/claudialubowitz26/marzbn/main/index.html

#install env
cat > "/opt/marzban/.env" << EOF
UVICORN_HOST = "0.0.0.0"
UVICORN_PORT = 8000

# SUDO_USERNAME = "admin"
# SUDO_PASSWORD = "admin"

# UVICORN_UDS: "/run/marzban.socket"
# UVICORN_SSL_CERTFILE = "/var/lib/marzban/certs/example.com/fullchain.pem"
# UVICORN_SSL_KEYFILE = "/var/lib/marzban/certs/example.com/key.pem"


XRAY_JSON = "/var/lib/marzban/xray_config.json"
XRAY_SUBSCRIPTION_URL_PREFIX = "https://$domain"
# XRAY_SUBSCRIPTION_PATH = sub
XRAY_EXECUTABLE_PATH = "/var/lib/marzban/xray-core/xray"
# XRAY_ASSETS_PATH = "/usr/local/share/xray"
# XRAY_EXCLUDE_INBOUND_TAGS = "INBOUND_X INBOUND_Y"
# XRAY_FALLBACKS_INBOUND_TAG = "VLESS_TLS_FALLBACK"


# TELEGRAM_API_TOKEN = 123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# TELEGRAM_ADMIN_ID = 987654321, 123456789
# TELEGRAM_LOGGER_CHANNEL_ID = -1234567890123
# TELEGRAM_DEFAULT_VLESS_FLOW = "xtls-rprx-vision"
# TELEGRAM_PROXY_URL = "http://localhost:8080"

# DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/xxxxxxx"

# CUSTOM_TEMPLATES_DIRECTORY="/var/lib/marzban/templates/"
# CLASH_SUBSCRIPTION_TEMPLATE="clash/my-custom-template.yml"
# SUBSCRIPTION_PAGE_TEMPLATE="subscription/index.html"
# HOME_PAGE_TEMPLATE="home/index.html"

# Set headers for subscription
# SUB_PROFILE_TITLE = "Susbcription"
# SUB_SUPPORT_URL = "https://t.me/support"
# SUB_UPDATE_INTERVAL = "12"

SQLALCHEMY_DATABASE_URL = "sqlite:////var/lib/marzban/db.sqlite3"

### for developers
# DOCS=true
# DEBUG=true

# If You Want To Send Webhook To Multiple Server Add Multi Address
# WEBHOOK_ADDRESS = "http://127.0.0.1:9000/,http://127.0.0.1:9001/"
# WEBHOOK_SECRET = "something-very-very-secret"

# VITE_BASE_API="https://example.com/api/"
# JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 1440
EOF
mkdir -p /var/lib/marzban/xray-core
wget https://github.com/XTLS/Xray-core/releases/download/v1.8.11/Xray-linux-64.zip -P /var/lib/marzban/xray-core
apt install wget unzip -y
unzip Xray-linux-64.zip
rm Xray-linux-64.zip


#profile
echo -e 'profile' >> /root/.profile
wget -O /usr/bin/profile "https://raw.githubusercontent.com/claudialubowitz26/marzbn/main/profile";
chmod +x /usr/bin/profile
apt install neofetch -y
wget -O /usr/bin/cekservice "https://raw.githubusercontent.com/claudialubowitz26/marzbn/main/cekservice.sh"
chmod +x /usr/bin/cekservice

#install compose
cat > "/opt/marzban/docker-compose.yml" << EOF
services:
  marzban:
    image: gozargah/marzban:latest
    restart: always
    env_file: .env
    network_mode: host
    volumes:
      - /var/lib/marzban:/var/lib/marzban
      - /opt/marzban/index.html:/code/app/templates/subscription/index.html
EOF

#Install VNSTAT
apt -y install vnstat
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev
wget https://github.com/claudialubowitz26/marzbn/raw/main/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install 
cd
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
rm -f /root/vnstat-2.6.tar.gz 
rm -rf /root/vnstat-2.6

#Install Speedtest
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | sudo bash
sudo apt-get install speedtest -y

#install nginx
apt install nginx -y
rm /etc/nginx/conf.d/default.conf

domain=hase.lumine.mu.id
cat > "/etc/nginx/nginx.conf" << EOF
#user nobody nogroup;
worker_processes auto;

error_log /var/log/nginx/error.log; 

pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include mime.types;
    default_type application/octet-stream;

    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    sendfile on;

    keepalive_timeout 65;

    server {
        listen 80;
        listen [::]:80;
        listen 443 ssl http2 default_server;
        listen [::]:443 ssl http2 default_server; 
        
		set_real_ip_from   103.21.244.0/22;
		set_real_ip_from   103.22.200.0/22;
		set_real_ip_from   103.31.4.0/22;
		set_real_ip_from   104.16.0.0/13;
		set_real_ip_from   104.24.0.0/14;
		set_real_ip_from   108.162.192.0/18;
		set_real_ip_from   131.0.72.0/22;
		set_real_ip_from   141.101.64.0/18;
		set_real_ip_from   162.158.0.0/15;
		set_real_ip_from   172.64.0.0/13;
		set_real_ip_from   173.245.48.0/20;
		set_real_ip_from   188.114.96.0/20;
		set_real_ip_from   190.93.240.0/20;
		set_real_ip_from   197.234.240.0/22;
		set_real_ip_from   198.41.128.0/17;

		set_real_ip_from   2400:cb00::/32;
		set_real_ip_from   2606:4700::/32;
		set_real_ip_from   2803:f800::/32;
		set_real_ip_from   2405:b500::/32;
		set_real_ip_from   2405:8100::/32;
		set_real_ip_from   2a06:98c0::/29;
		set_real_ip_from   2c0f:f248::/32;
		real_ip_header X-Forwarded-For;
		
		
        server_name $domain; 

        ssl_certificate /var/lib/marzban/certs/$domain/fullchain.cer; 
        ssl_certificate_key /var/lib/marzban/certs/$domain/privkey.key; 

        ssl_protocols TLSv1.2 TLSv1.3; 
        ssl_prefer_server_ciphers on; 
        ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305; 

        location = /vlessws { 
            if (\$http_upgrade != "websocket") {
                return 404;
            } 
            proxy_redirect off;
            proxy_pass http://127.0.0.1:20651; 
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }
        
        location = /vmessws { 
            if (\$http_upgrade != "websocket") {
                return 404;
            } 
            proxy_redirect off;
            proxy_pass http://127.0.0.1:20652; 
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }

        location = /trojanws { 
            if (\$http_upgrade != "websocket") {
                return 404;
            } 
            proxy_redirect off;
            proxy_pass http://127.0.0.1:20653; 
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }

        location = /vlesshu { 
            if (\$http_upgrade != "websocket") {
                return 404;
            } 
            proxy_redirect off;
            proxy_pass http://127.0.0.1:2021;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }

        location = /vmesshu { 
            if (\$http_upgrade != "websocket") {
                return 404;
            } 
            proxy_redirect off;
            proxy_pass http://127.0.0.1:2022;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }

        location = /trojanhu { 
            if (\$http_upgrade != "websocket") {
                return 404;
            } 
            proxy_redirect off;
            proxy_pass http://127.0.0.1:2023;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }

        location /vlessgrpc {
            if (\$request_method != "POST") {
                return 404;
            } 
            client_body_buffer_size 1m;
            client_body_timeout 1h;
            client_max_body_size 0;
            grpc_pass grpc://127.0.0.1:3001;
            grpc_read_timeout 1h;
            grpc_send_timeout 1h;
            grpc_set_header Host \$host;
            grpc_set_header X-Real-IP \$remote_addr;
        }
		
		location /vmessgrpc {
            if (\$request_method != "POST") {
                return 404;
            }
            client_body_buffer_size 1m;
            client_body_timeout 1h;
            client_max_body_size 0;
            grpc_pass grpc://127.0.0.1:3002;
            grpc_read_timeout 1h;
            grpc_send_timeout 1h;
            grpc_set_header Host \$host;
            grpc_set_header X-Real-IP \$remote_addr;
        }
		
		location /trojangrpc {
            if (\$request_method != "POST") {
                return 404;
            }
            client_body_buffer_size 1m;
            client_body_timeout 1h;
            client_max_body_size 0;
            grpc_pass grpc://127.0.0.1:3003;
            grpc_read_timeout 1h;
            grpc_send_timeout 1h;
            grpc_set_header Host \$host;
            grpc_set_header X-Real-IP \$remote_addr;
        }

        location ~* /(sub|dashboard|api|docs|redoc|openapi.json) {
            proxy_redirect off;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_pass http://0.0.0.0:8000;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }

        
        location / {
            add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
            root /var/www/html;
            index index.html index.htm;
        }
    }
}
EOF



systemctl enable nginx
mkdir -p /var/www/html
echo "<pre>Hello World</pre>" > /var/www/html/index.html
systemctl start nginx

#install socat
apt install iptables -y
apt install curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release -y 
apt install socat cron bash-completion -y

#install cert
systemctl stop nginx
curl https://get.acme.sh | sh -s
/root/.acme.sh/acme.sh --server letsencrypt --register-account -m helpers@lumine.my.id --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /var/lib/marzban/certs/$domain/fullchain.cer --keypath /var/lib/marzban/certs/$domain/privkey.key --ecc
systemctl start nginx

cat > "/var/lib/marzban/xray_config.json" << EOF
{
    "log": {
      "loglevel": "info"
    },
    "inbounds": [
      {
        "tag": "VLESS_WS",
        "listen": "127.0.0.1",
        "port": 20651,
        "protocol": "vless",
        "settings": {
          "clients": [],
          "decryption": "none"
        },
        "streamSettings": {
          "network": "ws",
          "wsSettings": {
            "path": "/vlessws"
          },
          "security": "none"
        },
        "sniffing": {
          "enabled": true,
          "destOverride": [
            "http",
            "tls"
          ]
        }
      },
      {
        "tag": "VMESS_WS",
        "listen": "127.0.0.1",
        "port": 20652,
        "protocol": "vmess",
        "settings": {
          "clients": []
        },
        "streamSettings": {
          "network": "ws",
          "security": "none",
          "wsSettings": {
            "path": "/vmessws"
          }
        },
        "sniffing": {
          "enabled": true,
          "destOverride": [
            "http",
            "tls"
          ]
        }
      },
      {
        "tag": "TROJAN_WS",
        "listen": "127.0.0.1",
        "port": 20653,
        "protocol": "trojan",
        "settings": {
          "clients": []
        },
        "streamSettings": {
          "network": "ws",
          "wsSettings": {
            "path": "/trojanws"
          },
          "security": "none"
        },
        "sniffing": {
          "enabled": true,
          "destOverride": [
            "http",
            "tls"
          ]
        }
      },
      {
        "tag": "VLESS_HTTP_UPGRADE",
        "listen": "127.0.0.1",
        "port": 2021,
        "protocol": "vless",
        "settings": {
          "clients": [],
          "decryption": "none"
        },
        "streamSettings": {
          "network": "httpupgrade",
          "security": "none",
          "httpupgradeSettings": {
            "path": "/vlesshu"
          }
        },
        "sniffing": {
          "enabled": true,
          "destOverride": [
            "http",
            "tls"
          ]
        }
      },
      {
        "tag": "VMESS_HTTP_UPGRADE",
        "listen": "127.0.0.1",
        "port": 2022,
        "protocol": "vmess",
        "settings": {
          "clients": []
        },
        "streamSettings": {
          "network": "httpupgrade",
          "security": "none",
          "httpupgradeSettings": {
            "path": "/vmesshu"
          }
        },
        "sniffing": {
          "enabled": true,
          "destOverride": [
            "http",
            "tls"
          ]
        }
      },
      {
        "tag": "TROJAN_HTTP_UPGRADE",
        "listen": "127.0.0.1",
        "port": 2023,
        "protocol": "trojan",
        "settings": {
          "clients": []
        },
        "streamSettings": {
          "network": "httpupgrade",
          "security": "none",
          "httpupgradeSettings": {
            "path": "/trojanhu"
          }
        },
        "sniffing": {
          "enabled": true,
          "destOverride": [
            "http",
            "tls"
          ]
        }
      },
      {
        "tag": "VLESS-gRPC",
        "listen": "127.0.0.1",
        "port": 3001,
        "protocol": "vless",
        "settings": {
          "clients": [],
          "decryption": "none"
        },
        "streamSettings": {
          "network": "grpc",
          "security": "none",
          "grpcSettings": {
            "serviceName": "vlessgrpc"
          }
        }
      },
      {
        "tag": "VMESS-gRPC",
        "listen": "127.0.0.1",
        "port": 3002,
        "protocol": "vmess",
        "settings": {
          "clients": []
        },
        "streamSettings": {
          "network": "grpc",
          "security": "none",
          "grpcSettings": {
            "serviceName": "vmessgrpc"
          }
        }
      },
      {
        "tag": "TROJAN-gRPC",
        "listen": "127.0.0.1",
        "port": 3003,
        "protocol": "trojan",
        "settings": {
          "clients": []
        },
        "streamSettings": {
          "network": "grpc",
          "security": "none",
          "grpcSettings": {
            "serviceName": "trojangrpc"
          }
        }
      }
    ],
    "outbounds": [
      {
        "protocol": "freedom",
        "tag": "DIRECT"
      },
      {
        "protocol": "blackhole",
        "tag": "BLOCK"
      }
    ],
    "routing": {
      "rules": [
        {
          "ip": [
            "geoip:private"
          ],
          "outboundTag": "BLOCK",
          "type": "field"
        },
        {
          "domain": [
            "geosite:private"
          ],
          "outboundTag": "DIRECT",
          "type": "field"
        },
        {
          "protocol": [
            "bittorrent"
          ],
          "outboundTag": "BLOCK",
          "type": "field"
        }
      ]
    }
}
EOF

#install firewall
apt install ufw -y
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
yes | sudo ufw enable

#install database
wget -O /var/lib/marzban/db.sqlite3 "https://github.com/claudialubowitz26/marzbn/raw/main/db.sqlite3"

#finishing
apt autoremove -y
apt clean
systemctl restart nginx
cd /opt/marzban
docker compose down && docker compose up -d
cd
rm /root/mar.sh


