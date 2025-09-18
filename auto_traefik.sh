#!/bin.bash
#
# Docker & Traefik Setup Script
#
# This script automates the setup of a Docker host with Traefik based on the provided guide.
# It will prompt for a new username and hostname.
#
# IMPORTANT:
# - Run this script with sudo privileges.
# - Review the script before execution.
# - Some manual steps are still required and will be noted at the end.
#

# Exit immediately if a command exits with a non-zero status.
set -e

# --- User Input ---
echo "--- Docker & Traefik Setup ---"
read -p "Please enter the username for the new user: " NEW_USER
read -p "Please enter the hostname for this server (e.g., 'stack'): " HOSTNAME
echo "--------------------------------"
echo

# --- 1. System Preparation ---

echo "--- Step 1: Preparing System and Creating User ---"

# Create a new user and add to sudo group
if id "$NEW_USER" &>/dev/null; then
    echo "User $NEW_USER already exists. Skipping user creation."
else
    echo "Creating new user: $NEW_USER"
    adduser --quiet --gecos "" "$NEW_USER"
    usermod -aG sudo "$NEW_USER"
    echo "User $NEW_USER created and added to the sudo group."
fi

# Lock the root account's password
passwd -l root
echo "Root account password locked."
echo "--------------------------------"
echo

# --- 2. Secure SSH ---

echo "--- Step 2: Securing SSH Server ---"
SSH_PORT=2053
echo "Updating SSH configuration..."
# Create a backup of the original sshd_config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Automate SSH configuration changes
sed -i "s/^#?Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
sed -i "s/^#?PasswordAuthentication .*/PasswordAuthentication no/" /etc/ssh/sshd_config
sed -i "s/^#?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/" /etc/ssh/sshd_config
sed -i "s/^#?PubkeyAuthentication .*/PubkeyAuthentication yes/" /etc/ssh/sshd_config

# Restart SSH service
systemctl restart ssh
echo "SSH server configured on port $SSH_PORT and restarted."
echo "IMPORTANT: Before logging out, test SSH login for '$NEW_USER' in a new terminal."
echo "--------------------------------"
echo

# --- 3. Firewall Setup ---

echo "--- Step 3: Configuring UFW Firewall ---"
# Set default policies
ufw default deny incoming
ufw default allow outgoing

# Allow necessary ports
ufw allow $SSH_PORT/tcp comment 'Custom SSH Port'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw allow 81/tcp comment 'Traefik Alt HTTP'
ufw allow 444/tcp comment 'Traefik Alt HTTPS'

# Enable the firewall without prompt
ufw --force enable
echo "UFW Firewall enabled and configured."
ufw status verbose
echo "--------------------------------"
echo

# --- 4. OS & Package Management ---

echo "--- Step 4: Updating OS and Installing Packages ---"
# Update OS
apt-get update && apt-get upgrade -y

# Install required packages
apt-get install -y acl apache2-utils apt-transport-https argon2 ca-certificates curl gnupg htop libnss-resolve lsb-release nano ncdu net-tools netcat-traditional ntp pwgen software-properties-common ufw unzip zip
echo "System updated and required packages installed."
echo "--------------------------------"
echo

# --- 5. System Tweaks ---

echo "--- Step 5: Applying System Tweaks ---"
# Add performance tweaks to sysctl.conf
cat <<EOF >> /etc/sysctl.conf
# Custom Tweaks for Docker Host
vm.swappiness=10
vm.vfs_cache_pressure = 50
fs.inotify.max_user_watches=262144
EOF
sysctl -p # Apply tweaks immediately
echo "System performance tweaks have been applied."
echo "--------------------------------"
echo

# --- 6. Docker Installation ---

echo "--- Step 6: Installing Docker and Docker Compose ---"
# Install Docker using the convenience script
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
    echo "Docker installed successfully."
else
    echo "Docker is already installed."
fi

# Add the new user to the docker group
usermod -aG docker "$NEW_USER"
echo "User '$NEW_USER' added to the 'docker' group."
echo "You will need to log out and log back in for this change to take effect."
echo "--------------------------------"
echo

# --- 7. Directory and File Setup ---
# This section must be run as the new user, so we use sudo -u
echo "--- Step 7: Creating Docker Directory Structure for user $NEW_USER ---"
USER_HOME=$(eval echo ~$NEW_USER)
DOCKER_BASE_DIR="$USER_HOME/docker"

sudo -u "$NEW_USER" bash <<EOF
mkdir -p "$DOCKER_BASE_DIR"/{appdata,compose,logs,scripts,secrets,shared}
touch "$DOCKER_BASE_DIR"/.env
touch "$DOCKER_BASE_DIR"/docker-compose-stack.yml
EOF

# Set permissions for sensitive files
chown "$NEW_USER":"$NEW_USER" "$DOCKER_BASE_DIR"/secrets
chmod 600 "$DOCKER_BASE_DIR"/secrets
chown "$NEW_USER":"$NEW_USER" "$DOCKER_BASE_DIR"/.env
chmod 600 "$DOCKER_BASE_DIR"/.env

echo "Docker directories and base files created."

# Set Docker root folder permissions with ACL
chmod 775 "$DOCKER_BASE_DIR"
setfacl -Rdm u:"$NEW_USER":rwx "$DOCKER_BASE_DIR"
setfacl -Rm u:"$NEW_USER":rwx "$DOCKER_BASE_DIR"
setfacl -Rdm g:docker:rwx "$DOCKER_BASE_DIR"
setfacl -Rm g:docker:rwx "$DOCKER_BASE_DIR"

echo "ACL permissions set for Docker directory."
echo "--------------------------------"
echo

# --- 8. Configuration File Creation ---
echo "--- Step 8: Creating Configuration Files ---"

# Create .env file with placeholders
PUID=$(id -u "$NEW_USER")
PGID=$(id -g "$NEW_USER")

cat <<EOF > "$DOCKER_BASE_DIR"/.env
# --- General Settings ---
PUID='$PUID'
PGID='$PGID'
TZ='Asia/Bangkok' # Change to your timezone

# --- Paths ---
USERDIR='$USER_HOME'
DOCKERDIR='$DOCKER_BASE_DIR'
# MEDIADIR1='/media/storage/media1' # Example media directory, uncomment and change if needed

# --- Hostname and Domain ---
HOSTNAME='$HOSTNAME'
DOMAINNAME_1='your_domain.com' # IMPORTANT: Change this to your domain

# --- Networking ---
# Find your server's LAN IP with 'ip a'
SERVER_LAN_IP='192.168.1.100' # IMPORTANT: Change this to your server's LAN IP
LOCAL_IPS='127.0.0.1/32,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12'

# --- Cloudflare ---
# Get these from https://www.cloudflare.com/ips/
CLOUDFLARE_IPS='173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22'

# --- Docker Proxy ---
# Find docker0 interface IP with 'ip a'
DOCKER_SOCKET_IP='172.17.0.1'
DOCKER_HOST='tcp://socket-proxy:2375'

# --- Service Passwords & API Keys (Fill these in) ---
REDIS_PASSWORD='generate_a_strong_password'
CROWDSEC_BOUNCER_TRAEFIK_API_KEY='generate_a_strong_api_key'
EOF
chown "$NEW_USER":"$NEW_USER" "$DOCKER_BASE_DIR"/.env
echo "Created .env file with placeholders. Please edit it with your details."

# Create main docker-compose-stack.yml
cat <<EOF > "$DOCKER_BASE_DIR"/docker-compose-stack.yml
################################################################################
# Main Docker Compose Stack File
#
# This file includes networks, secrets, and service configurations.
# Uncomment the services under 'include' that you wish to run.
################################################################################

networks:
  default:
    driver: bridge
  socket_proxy:
    name: socket_proxy
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.0.0/24
  t3_proxy:
    name: t3_proxy
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.10.0/24

secrets:
  cf_dns_api_token:
    file: \$DOCKERDIR/secrets/cf_dns_api_token
#  authelia_jwt_secret:
#    file: \$DOCKERDIR/secrets/authelia_jwt_secret
#  mariadb_root_password:
#    file: \$DOCKERDIR/secrets/mariadb_root_password

# --- Include Services ---
# Uncomment the services you want to deploy
include:
  - compose/\$HOSTNAME/socket-proxy.yml
  - compose/\$HOSTNAME/traefik.yml
  # - compose/\$HOSTNAME/portainer.yml
  # - compose/\$HOSTNAME/dozzle.yml
  # - compose/\$HOSTNAME/homepage.yml
  # - compose/\$HOSTNAME/uptime-kuma.yml
  # - compose/\$HOSTNAME/docker-gc.yml
  # - compose/\$HOSTNAME/mariadb.yml
EOF
chown "$NEW_USER":"$NEW_USER" "$DOCKER_BASE_DIR"/docker-compose-stack.yml
echo "Created main docker-compose-stack.yml."

# Create compose directory for the host
mkdir -p "$DOCKER_BASE_DIR/compose/$HOSTNAME"
chown -R "$NEW_USER":"$NEW_USER" "$DOCKER_BASE_DIR/compose"
echo "Created compose directory: compose/$HOSTNAME"

# Create socket-proxy.yml
cat <<EOF > "$DOCKER_BASE_DIR/compose/$HOSTNAME/socket-proxy.yml"
services:
  # Docker Socket Proxy - Security Enhanced Proxy for Docker Socket
  socket-proxy:
    image: lscr.io/linuxserver/socket-proxy:latest
    container_name: socket-proxy
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    profiles: ["core", "all"]
    networks:
      socket_proxy:
        ipv4_address: 172.16.0.254
    privileged: true
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock"
    read_only: true
    tmpfs:
      - /run
    environment:
      - LOG_LEVEL=warning
      - ALLOW_START=1
      - ALLOW_STOP=1
      - ALLOW_RESTARTS=1
      - EVENTS=1
      - PING=1
      - VERSION=1
      - AUTH=0
      - SECRETS=0
      - POST=1
      - BUILD=0
      - COMMIT=0
      - CONFIGS=0
      - CONTAINERS=1
      - DISTRIBUTION=0
      - EXEC=0
      - IMAGES=1
      - INFO=1
      - NETWORKS=1
      - NODES=0
      - PLUGINS=0
      - SERVICES=1
      - SESSION=0
      - SWARM=0
      - SYSTEM=0
      - TASKS=1
      - VOLUMES=1
EOF
echo "Created socket-proxy.yml."

# --- 9. Traefik Setup ---
echo "--- Step 9: Setting up Traefik Configuration ---"

# Prepare Traefik Folders and files
sudo -u "$NEW_USER" bash <<EOF
mkdir -p "$DOCKER_BASE_DIR/appdata/traefik3/rules/$HOSTNAME"
mkdir -p "$DOCKER_BASE_DIR/appdata/traefik3/acme"
touch "$DOCKER_BASE_DIR/appdata/traefik3/acme/acme.json"
chmod 600 "$DOCKER_BASE_DIR/appdata/traefik3/acme/acme.json"

mkdir -p "$DOCKER_BASE_DIR/logs/$HOSTNAME/traefik"
touch "$DOCKER_BASE_DIR/logs/$HOSTNAME/traefik/traefik.log"
touch "$DOCKER_BASE_DIR/logs/$HOSTNAME/traefik/access.log"
EOF
echo "Traefik folders and log files created."

# Ask user for Traefik setup type
read -p "Is this a 'cloud' or 'local' server setup for Traefik? [cloud/local]: " TRAEFIK_TYPE

TRAEFIK_COMPOSE_CONTENT=""
if [[ "$TRAEFIK_TYPE" == "cloud" ]]; then
# Traefik Compose for Cloud Server
TRAEFIK_COMPOSE_CONTENT=$(cat <<'EOF'
services:
  traefik:
    container_name: traefik
    image: traefik:latest
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    profiles: ["core", "all"]
    depends_on:
      - socket-proxy
    networks:
      t3_proxy:
        ipv4_address: 172.16.10.254
      socket_proxy:
    command:
      - --global.checkNewVersion=true
      - --global.sendAnonymousUsage=false
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
      - --entrypoints.web.http.redirections.entrypoint.to=websecure
      - --entrypoints.web.http.redirections.entrypoint.scheme=https
      - --api=true
      - --api.dashboard=true
      - --entrypoints.websecure.forwardedHeaders.trustedIPs=$CLOUDFLARE_IPS,$LOCAL_IPS
      - --log=true
      - --log.filePath=/logs/traefik.log
      - --log.level=INFO
      - --accessLog=true
      - --accessLog.filePath=/logs/access.log
      - --providers.docker=true
      - --providers.docker.endpoint=$DOCKER_HOST
      - --providers.docker.exposedByDefault=false
      - --providers.docker.network=t3_proxy
      - --entrypoints.websecure.http.tls=true
      - --entrypoints.websecure.http.tls.certresolver=dns-cloudflare
      - --entrypoints.websecure.http.tls.domains[0].main=$DOMAINNAME_1
      - --entrypoints.websecure.http.tls.domains[0].sans=*.$DOMAINNAME_1
      - --providers.file.directory=/rules
      - --providers.file.watch=true
      # Use Let's Encrypt production server by default. Uncomment staging for testing.
      # - --certificatesResolvers.dns-cloudflare.acme.caServer=https://acme-staging-v02.api.letsencrypt.org/directory
      - --certificatesResolvers.dns-cloudflare.acme.storage=/acme.json
      - --certificatesResolvers.dns-cloudflare.acme.dnsChallenge.provider=cloudflare
      - --certificatesResolvers.dns-cloudflare.acme.dnsChallenge.resolvers=1.1.1.1:53,1.0.0.1:53
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - $DOCKERDIR/appdata/traefik3/rules/$HOSTNAME:/rules
      - $DOCKERDIR/appdata/traefik3/acme/acme.json:/acme.json
      - $DOCKERDIR/logs/$HOSTNAME/traefik:/logs
    environment:
      - CF_DNS_API_TOKEN_FILE=/run/secrets/cf_dns_api_token
      - DOMAINNAME_1
    secrets:
      - cf_dns_api_token
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.traefik-rtr.entrypoints=websecure"
      - "traefik.http.routers.traefik-rtr.rule=Host(`traefik.$DOMAINNAME_1`)"
      - "traefik.http.routers.traefik-rtr.service=api@internal"
      - "traefik.http.routers.traefik-rtr.middlewares=chain-no-auth@file"
EOF
)
else
# Traefik Compose for Local Server
TRAEFIK_COMPOSE_CONTENT=$(cat <<'EOF'
services:
  traefik:
    container_name: traefik
    image: traefik:latest
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    profiles: ["core", "all"]
    depends_on:
      - socket-proxy
    networks:
      t3_proxy:
        ipv4_address: 172.16.10.254
      socket_proxy:
    command:
      - --global.checkNewVersion=true
      - --global.sendAnonymousUsage=false
      - --entrypoints.web-external.address=:81
      - --entrypoints.web-internal.address=:80
      - --entrypoints.websecure-external.address=:444
      - --entrypoints.websecure-internal.address=:443
      - --entrypoints.web-external.http.redirections.entrypoint.to=websecure-external
      - --entrypoints.web-external.http.redirections.entrypoint.scheme=https
      - --entrypoints.web-internal.http.redirections.entrypoint.to=websecure-internal
      - --entrypoints.web-internal.http.redirections.entrypoint.scheme=https
      - --api=true
      - --api.dashboard=true
      - --entrypoints.websecure-external.forwardedHeaders.trustedIPs=$CLOUDFLARE_IPS,$LOCAL_IPS
      - --entrypoints.websecure-internal.forwardedHeaders.trustedIPs=$CLOUDFLARE_IPS,$LOCAL_IPS
      - --log=true
      - --log.filePath=/logs/traefik.log
      - --log.level=INFO
      - --accessLog=true
      - --accessLog.filePath=/logs/access.log
      - --providers.docker=true
      - --providers.docker.endpoint=$DOCKER_HOST
      - --providers.docker.exposedByDefault=false
      - --providers.docker.network=t3_proxy
      - --entrypoints.websecure-external.http.tls=true
      - --entrypoints.websecure-external.http.tls.certresolver=dns-cloudflare
      - --entrypoints.websecure-internal.http.tls=true
      - --entrypoints.websecure-internal.http.tls.certresolver=dns-cloudflare
      - --entrypoints.websecure-external.http.tls.domains[0].main=$DOMAINNAME_1
      - --entrypoints.websecure-external.http.tls.domains[0].sans=*.$DOMAINNAME_1
      - --providers.file.directory=/rules
      - --providers.file.watch=true
      - --certificatesResolvers.dns-cloudflare.acme.storage=/acme.json
      - --certificatesResolvers.dns-cloudflare.acme.dnsChallenge.provider=cloudflare
      - --certificatesResolvers.dns-cloudflare.acme.dnsChallenge.resolvers=1.1.1.1:53,1.0.0.1:53
    ports:
      - "80:80"
      - "81:81"
      - "443:443"
      - "444:444"
    volumes:
      - $DOCKERDIR/appdata/traefik3/rules/$HOSTNAME:/rules
      - $DOCKERDIR/appdata/traefik3/acme/acme.json:/acme.json
      - $DOCKERDIR/logs/$HOSTNAME/traefik:/logs
    environment:
      - CF_DNS_API_TOKEN_FILE=/run/secrets/cf_dns_api_token
      - DOMAINNAME_1
    secrets:
      - cf_dns_api_token
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.traefik-rtr.entrypoints=websecure-internal"
      - "traefik.http.routers.traefik-rtr.rule=Host(`traefik.$DOMAINNAME_1`)"
      - "traefik.http.routers.traefik-rtr.service=api@internal"
      - "traefik.http.routers.traefik-rtr.middlewares=chain-no-auth@file"
EOF
)
fi

echo "$TRAEFIK_COMPOSE_CONTENT" > "$DOCKER_BASE_DIR/compose/$HOSTNAME/traefik.yml"
echo "Created traefik.yml for '$TRAEFIK_TYPE' setup."

# Create TLS options file
cat <<EOF > "$DOCKER_BASE_DIR/appdata/traefik3/rules/$HOSTNAME/tls-opts.yml"
tls:
  options:
    tls-opts:
      minVersion: VersionTLS12
      cipherSuites:
        - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
        - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
      curvePreferences:
        - CurveP521
        - CurveP384
      sniStrict: true
EOF
echo "Created tls-opts.yml"

# Create Middleware files
cat <<EOF > "$DOCKER_BASE_DIR/appdata/traefik3/rules/$HOSTNAME/middlewares-rate-limit.yml"
http:
  middlewares:
    middlewares-rate-limit:
      rateLimit:
        average: 100
        burst: 50
EOF

cat <<EOF > "$DOCKER_BASE_DIR/appdata/traefik3/rules/$HOSTNAME/middlewares-secure-headers.yml"
http:
  middlewares:
    middlewares-secure-headers:
      headers:
        stsSeconds: 63072000
        stsIncludeSubdomains: true
        stsPreload: true
        customFrameOptionsValue: SAMEORIGIN
        contentTypeNosniff: true
        browserXssFilter: true
        referrerPolicy: "same-origin"
        permissionsPolicy: "camera=(), microphone=(), geolocation=()"
        customResponseHeaders:
          X-Robots-Tag: "none,noarchive,nosnippet,notranslate,noimageindex,"
          server: ""
EOF

cat <<EOF > "$DOCKER_BASE_DIR/appdata/traefik3/rules/$HOSTNAME/chain-no-auth.yml"
http:
  middlewares:
    chain-no-auth:
      chain:
        middlewares:
          - middlewares-rate-limit
          - middlewares-secure-headers
EOF
echo "Created Traefik middleware files."

# Set final ownership for all created files
chown -R "$NEW_USER":"$NEW_USER" "$USER_HOME"

echo "--------------------------------"
echo

# --- 10. Final Instructions ---
echo "--- ✅ Script Finished! Next Steps: ---"
echo
echo "1. IMPORTANT: Log out and log back in as the user '$NEW_USER'."
echo "   You can do this with: su - $NEW_USER"
echo
echo "2. Edit the main environment file with your specific details:"
echo "   nano ~/docker/.env"
echo "   (Fill in DOMAINNAME_1, SERVER_LAN_IP, passwords, etc.)"
echo
echo "3. Create the Cloudflare API Token secret file:"
echo "   nano ~/docker/secrets/cf_dns_api_token"
echo "   (Paste your Cloudflare API token into this file and save.)"
echo
echo "4. Review your main compose file and uncomment the services you want:"
echo "   nano ~/docker/docker-compose-stack.yml"
echo "   (You will need to create the compose files for other apps like portainer.yml, homepage.yml, etc.)"
echo
echo "5. Once ready, navigate to the docker directory and start the stack:"
echo "   cd ~/docker"
echo "   docker compose -f docker-compose-stack.yml up -d"
echo
echo "6. Monitor the Traefik logs for any issues, especially with certificate generation:"
echo "   tail -f ~/docker/logs/$HOSTNAME/traefik/traefik.log"
echo
echo "----------------------------------------------------------------"
