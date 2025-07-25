#!/usr/bin/env bash

# A robust, idempotent script to apply comprehensive system hardening.
# This script is designed to be run with root privileges.

# --- Script Configuration ---
# Set the desired (non-standard) SSH port.
# Choose a port between 1024 and 65535.
readonly NEW_SSH_PORT="60630"

# A comma-separated list of users allowed to log in via SSH.
# The script will add the public key for the *first* user in this list.
# Example: "admin,devops,user1"
# Set to "" to not enforce user restrictions (less secure).
readonly ALLOWED_USERS="ton"

# A comma-separated list of groups allowed to log in via SSH.
# Example: "sshusers,administrators"
# Set to "" to not enforce group restrictions.
readonly ALLOWED_GROUPS="netdev"

# --- ADD YOUR PUBLIC KEY HERE ---
# Replace the placeholder with your actual SSH public key.
# The script will add this key to the authorized_keys file for the user specified above.
# Example: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB... user@host"
readonly SSH_PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIECb7zMSVVrnab22nImDBtaWcUqdy0saE9O78f1iBB+S phxcnx@gmail.com"


# --- Safety and Error Handling ---
# Exit immediately if a command exits with a non-zero status.
set -o errexit
# Treat unset variables as an error when substituting.
set -o nounset
# Pipelines return the exit status of the last command to exit with a non-zero status.
set -o pipefail

# --- Logging and Utility Functions ---
log() {
    echo "[$(date --rfc-3339=seconds)] - ${1}"
}

# Function to safely modify a key-value pair in a config file.
# Ensures the key exists and is set to the correct value.
# Creates the key if it does not exist.
# Usage: ensure_config_value "Key" "Value" "/path/to/file"
ensure_config_value() {
    local key="$1"
    local value="$2"
    local file="$3"
    log "Ensuring '${key}' is set to '${value}' in '${file}'..."
    # If the exact line already exists, do nothing.
    if grep -q "^\s*${key}\s\+${value}\s*$" "${file}"; then
        log "Configuration '${key} ${value}' already exists. No changes made."
        return 0
    fi
    # If the key exists but with a different value (or is commented out), change it.
    if grep -q "^\s*#*\s*${key}\s\+" "${file}"; then
        sed -i "s/^\s*#*\s*${key}\s\+.*/${key} ${value}/" "${file}"
        log "Updated existing key '${key}' to value '${value}'."
    # If the key does not exist, append it.
    else
        echo "${key} ${value}" >> "${file}"
        log "Added new key '${key}' with value '${value}'."
    fi
}

# Function to idempotently add a line to a file if it doesn't exist.
# Usage: ensure_line_present "line content" "/path/to/file" "grep pattern"
ensure_line_present() {
    local line_to_add="$1"
    local file_path="$2"
    local grep_pattern="${3:-$line_to_add}" # Use line itself as pattern if not specified

    if ! grep -qF -- "${grep_pattern}" "${file_path}"; then
        log "Adding line to ${file_path}..."
        echo "${line_to_add}" >> "${file_path}"
    else
        log "Line already present in ${file_path}. No changes made."
    fi
}

# --- Hardening Functions ---

configure_ssh_key() {
    log "--- Section: SSH Public Key Configuration ---"

    # Check if the public key variable is set and not a placeholder
    if [ -z "${SSH_PUBLIC_KEY}" ]; then
        log "WARNING: SSH_PUBLIC_KEY variable is not set or is a placeholder. Skipping key addition."
        return
    fi

    # Get the primary user from the ALLOWED_USERS list
    local primary_user
    primary_user=$(echo "${ALLOWED_USERS}" | cut -d ',' -f 1)

    if [ -z "${primary_user}" ]; then
        log "WARNING: No user specified in ALLOWED_USERS. Cannot add SSH key."
        return
    fi

    log "Configuring SSH public key for user: ${primary_user}"

    # Get home directory of the user
    local user_home
    user_home=$(getent passwd "${primary_user}" | cut -d: -f6)

    if [ -z "${user_home}" ] || [ ! -d "${user_home}" ]; then
        log "ERROR: Home directory for user '${primary_user}' not found. Cannot add SSH key."
        return
    fi

    local ssh_dir="${user_home}/.ssh"
    local auth_keys_file="${ssh_dir}/authorized_keys"

    log "Ensuring SSH directory exists at ${ssh_dir}"
    mkdir -p "${ssh_dir}"

    log "Adding public key to ${auth_keys_file}"
    
    # Idempotently add the key
    if ! grep -qF -- "${SSH_PUBLIC_KEY}" "${auth_keys_file}" &>/dev/null; then
        echo "${SSH_PUBLIC_KEY}" >> "${auth_keys_file}"
        log "Public key added."
    else
        log "Public key already exists. No changes made."
    fi

    log "Setting correct permissions and ownership for ${primary_user}..."
    chown -R "${primary_user}:${primary_user}" "${ssh_dir}"
    chmod 700 "${ssh_dir}"
    chmod 600 "${auth_keys_file}"
    log "Permissions set for ${ssh_dir} and ${auth_keys_file}."
}

configure_unattended_upgrades() {
    log "Configuring unattended-upgrades for automatic security patches..."
    if ! command -v apt-get &> /dev/null; then
        log "WARNING: 'apt-get' not found. Skipping unattended-upgrades configuration."
        return
    fi
    
    apt-get update > /dev/null
    apt-get install -y unattended-upgrades
    
    local auto_upgrades_config="/etc/apt/apt.conf.d/20auto-upgrades"
    log "Creating ${auto_upgrades_config} to enable unattended upgrades..."
    cat > "${auto_upgrades_config}" <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
    log "Unattended upgrades enabled."
}

configure_fail2ban() {
    log "Configuring Fail2Ban for brute-force protection..."
    if command -v apt-get &> /dev/null; then
        apt-get install -y fail2ban
    elif command -v dnf &> /dev/null; then
        dnf install -y fail2ban
    else
        log "WARNING: Neither 'apt-get' nor 'dnf' found. Skipping Fail2Ban installation."
        return
    fi

    local jail_config_dir="/etc/fail2ban/jail.d"
    local jail_config_file="${jail_config_dir}/sshd-custom.conf"
    mkdir -p "${jail_config_dir}"
    
    log "Creating custom Fail2Ban jail for SSH at ${jail_config_file}..."
    cat > "${jail_config_file}" <<EOF
[sshd]
enabled = true
port = ${NEW_SSH_PORT}
maxretry = 3
findtime = 600
bantime = 3600
EOF

    log "Enabling and restarting Fail2Ban service..."
    systemctl enable fail2ban
    systemctl restart fail2ban
    log "Fail2Ban configured for SSH on port ${NEW_SSH_PORT}."
}

secure_shared_memory() {
    log "Securing shared memory (/run/shm)..."
    local fstab_file="/etc/fstab"
    local shm_mount_point="/run/shm"
    local secure_shm_entry="tmpfs ${shm_mount_point} tmpfs rw,noexec,nosuid,nodev 0 0"

    # Backup fstab before modifying
    cp "${fstab_file}" "${fstab_file}.backup.$(date +%F-%T)"

    # Idempotently update fstab
    if grep -q "\s${shm_mount_point}\s" "${fstab_file}"; then
        log "Shared memory entry found in fstab, ensuring it is secure..."
        # Use a temporary file to avoid sed issues with in-place editing and special characters
        grep -v "\s${shm_mount_point}\s" "${fstab_file}" > "${fstab_file}.tmp"
        echo "${secure_shm_entry}" >> "${fstab_file}.tmp"
        mv "${fstab_file}.tmp" "${fstab_file}"
    else
        log "No shared memory entry found in fstab, adding secure entry..."
        echo "${secure_shm_entry}" >> "${fstab_file}"
    fi
    
    log "Remounting filesystems to apply changes..."
    mount -a
    log "Shared memory secured."
}

tune_kernel_parameters() {
    log "Tuning kernel parameters for security via sysctl..."
    local sysctl_config_file="/etc/sysctl.d/99-hardening.conf"
    
    # Create the file if it doesn't exist to avoid errors
    touch "${sysctl_config_file}"

    # Network Security
    ensure_config_value "net.ipv4.ip_forward" "0" "${sysctl_config_file}"
    ensure_config_value "net.ipv4.conf.all.send_redirects" "0" "${sysctl_config_file}"
    ensure_config_value "net.ipv4.conf.default.send_redirects" "0" "${sysctl_config_file}"
    ensure_config_value "net.ipv4.conf.all.accept_redirects" "0" "${sysctl_config_file}"
    ensure_config_value "net.ipv4.conf.default.accept_redirects" "0" "${sysctl_config_file}"
    ensure_config_value "net.ipv4.tcp_syncookies" "1" "${sysctl_config_file}"
    
    # Memory Security
    ensure_config_value "kernel.randomize_va_space" "2" "${sysctl_config_file}"

    log "Applying sysctl changes..."
    sysctl --system
    log "Kernel parameters tuned."
}

enable_apparmor() {
    log "Ensuring AppArmor is enabled and configured..."
    if ! command -v apt-get &> /dev/null; then
        log "WARNING: 'apt-get' not found. Skipping AppArmor configuration."
        return
    fi
    
    apt-get install -y apparmor apparmor-utils apparmor-profiles
    systemctl enable apparmor
    systemctl start apparmor
    
    local sshd_profile_path="/etc/apparmor.d/usr.sbin.sshd"
    if [ -f "${sshd_profile_path}" ]; then
        log "Found sshd AppArmor profile. Setting to enforce mode."
        aa-enforce /usr/sbin/sshd
    else
        log "WARNING: sshd AppArmor profile not found at ${sshd_profile_path}."
    fi
    log "AppArmor enabled."
}


# --- Main Hardening Logic ---
main() {
    log "Starting system hardening process..."

    # 1. Configure SSH Public Key
    configure_ssh_key

    # 2. Harden SSH Configuration
    log "--- Section: SSH Hardening ---"
    local sshd_config_file="/etc/ssh/sshd_config"
    local backup_file="${sshd_config_file}.backup.$(date +%F-%T)"
    if [ -f "${sshd_config_file}" ]; then
        log "Backing up ${sshd_config_file} to ${backup_file}..."
        cp "${sshd_config_file}" "${backup_file}"
    else
        log "ERROR: ${sshd_config_file} not found. Aborting."
        exit 1
    fi

    log "Applying core security configurations to ${sshd_config_file}..."
    ensure_config_value "Protocol" "2" "${sshd_config_file}"
    ensure_config_value "PermitRootLogin" "prohibit-password" "${sshd_config_file}"
    ensure_config_value "PubkeyAuthentication" "yes" "${sshd_config_file}"
    ensure_config_value "PasswordAuthentication" "no" "${sshd_config_file}"
    ensure_config_value "KbdInteractiveAuthentication" "no" "${sshd_config_file}"
    ensure_config_value "UsePAM" "yes" "${sshd_config_file}"
    ensure_config_value "PermitEmptyPasswords" "no" "${sshd_config_file}"
    ensure_config_value "ChallengeResponseAuthentication" "no" "${sshd_config_file}"
    ensure_config_value "X11Forwarding" "no" "${sshd_config_file}"
    ensure_config_value "AllowTcpForwarding" "no" "${sshd_config_file}"
    ensure_config_value "ClientAliveInterval" "300" "${sshd_config_file}"
    ensure_config_value "ClientAliveCountMax" "2" "${sshd_config_file}"
    ensure_config_value "LoginGraceTime" "30" "${sshd_config_file}"
    ensure_config_value "MaxAuthTries" "3" "${sshd_config_file}"
    ensure_config_value "MaxSessions" "10" "${sshd_config_file}"
    ensure_config_value "LogLevel" "VERBOSE" "${sshd_config_file}"

    if [ -n "${ALLOWED_USERS}" ]; then
        ensure_config_value "AllowUsers" "${ALLOWED_USERS//,/' '}" "${sshd_config_file}"
    fi

    if [ -n "${ALLOWED_GROUPS}" ]; then
        ensure_config_value "AllowGroups" "${ALLOWED_GROUPS//,/' '}" "${sshd_config_file}"
    fi

    log "Checking for systemd socket activation for SSH port..."
    if systemctl is-active --quiet ssh.socket; then
        log "Systemd socket activation detected. Modifying ssh.socket configuration."
        local socket_override_dir="/etc/systemd/system/ssh.socket.d"
        local socket_override_file="${socket_override_dir}/override.conf"
        mkdir -p "${socket_override_dir}"
        if [ ! -f "${socket_override_file}" ] || ! grep -q "ListenStream=${NEW_SSH_PORT}" "${socket_override_file}"; then
            log "Creating/updating systemd socket override for port ${NEW_SSH_PORT}."
            {
                echo ""
                echo "ListenStream="
                echo "ListenStream=${NEW_SSH_PORT}"
            } > "${socket_override_file}"
            systemctl daemon-reload
        else
            log "Systemd socket override already configured for port ${NEW_SSH_PORT}."
        fi
    else
        log "No systemd socket activation. Modifying Port in ${sshd_config_file}."
        ensure_config_value "Port" "${NEW_SSH_PORT}" "${sshd_config_file}"
    fi

    # 3. Secure Shared Memory
    log "--- Section: Filesystem Hardening ---"
    secure_shared_memory

    # 4. Tune Kernel Parameters
    log "--- Section: Kernel Hardening ---"
    tune_kernel_parameters

    # 5. Configure Automatic Updates (Debian/Ubuntu)
    log "--- Section: Patch Management ---"
    configure_unattended_upgrades

    # 6. Configure Fail2Ban
    log "--- Section: Intrusion Prevention ---"
    configure_fail2ban

    # 7. Configure AppArmor (Debian/Ubuntu)
    log "--- Section: Mandatory Access Control ---"
    enable_apparmor

    # 8. Update Firewall Rules
    log "--- Section: Firewall Configuration ---"
    log "Updating firewall rules for new SSH port ${NEW_SSH_PORT}..."
    if command -v ufw &> /dev/null; then
        log "UFW detected. Applying rules..."
        ufw default deny incoming
        ufw default allow outgoing
        ufw limit "${NEW_SSH_PORT}/tcp"
        ufw status | grep -q "22/tcp.*ALLOW" && ufw delete allow 22/tcp
        ufw status | grep -q "22/tcp.*LIMIT" && ufw delete limit 22/tcp
        ufw --force enable
        ufw reload
    elif command -v firewall-cmd &> /dev/null; then
        log "Firewalld detected. Applying rules..."
        firewall-cmd --add-port="${NEW_SSH_PORT}/tcp" --permanent
        firewall-cmd --query-port=22/tcp --permanent && firewall-cmd --remove-port=22/tcp --permanent
        firewall-cmd --reload
    else
        log "WARNING: No known firewall (ufw, firewalld) detected. Please update firewall rules manually."
    fi

    # 9. Final Validation and Service Reload
    log "--- Section: Finalization ---"
    log "Validating new SSH configuration..."
    if sshd -t; then
        log "Configuration is valid."
        log "Reloading SSH service to apply changes..."
        if systemctl is-active --quiet ssh.socket; then
            systemctl restart ssh.socket
        fi
        systemctl reload sshd.service
        log "SSH service reloaded successfully."
    else
        log "ERROR: sshd -t reported an invalid configuration. Restoring backup."
        cp "${backup_file}" "${sshd_config_file}"
        log "Backup restored. Please review ${sshd_config_file} for errors."
        exit 1
    fi

    log "System hardening process completed successfully."
}

# Execute the main function
main