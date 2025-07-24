#!/bin/bash

set -e

# =============================================================================
# CONFIGURATION - Edit these variables as needed
# =============================================================================

# Add your SSH public key here (replace with your actual public key)
PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIECb7zMSVVrnab22nImDBtaWcUqdy0saE9O78f1iBB+S phxcnx@gmail.com"

# SSH port to use (default is 22, change to desired port)
SSH_PORT="2222"

# =============================================================================
# SCRIPT FUNCTIONS - Do not modify below unless you know what you're doing
# =============================================================================

# Function to check and fix commented authentication settings
check_and_fix_commented_auth() {
    local config_file="$1"
    local backup_suffix=".bak.$(date +%Y%m%d_%H%M%S)"
    local backup_created=false
    
    if [ -f "$config_file" ]; then
        echo "Checking $config_file for commented authentication settings..."
        
        # Define the authentication settings to check
        declare -A auth_settings=(
            ["PasswordAuthentication"]="no"
            ["KbdInteractiveAuthentication"]="no"
            ["UsePAM"]="no"
            ["PermitEmptyPasswords"]="no"
        )
        
        # Process each authentication setting
        for setting in "${!auth_settings[@]}"; do
            local desired_value="${auth_settings[$setting]}"
            
            # Check for exact commented configuration lines (not general comments)
            if grep -q "^#${setting} " "$config_file"; then
                if [ "$backup_created" = false ]; then
                    sudo cp "$config_file" "${config_file}${backup_suffix}"
                    backup_created=true
                fi
                echo "Found commented ${setting} in $config_file"
                # Uncomment and set to desired value
                sudo sed -i "s/^#${setting} .*/${setting} ${desired_value}/" "$config_file"
                echo "Set ${setting} to ${desired_value} in $config_file"
            # Check for active setting with wrong value
            elif grep -q "^${setting} " "$config_file"; then
                local current_value=$(grep "^${setting} " "$config_file" | awk '{print $2}')
                if [ "$current_value" != "$desired_value" ]; then
                    if [ "$backup_created" = false ]; then
                        sudo cp "$config_file" "${config_file}${backup_suffix}"
                        backup_created=true
                    fi
                    echo "Found ${setting} ${current_value} in $config_file"
                    sudo sed -i "s/^${setting} .*/${setting} ${desired_value}/" "$config_file"
                    echo "Changed ${setting} from ${current_value} to ${desired_value} in $config_file"
                fi
            else
                # Setting not found, add it
                echo "⚠ Adding ${setting} ${desired_value} to $config_file"
                echo "${setting} ${desired_value}" | sudo tee -a "$config_file"
            fi
            
            # Verify the final state
            if grep -q "^${setting} ${desired_value}" "$config_file"; then
                echo "✓ ${setting} is properly set to '${desired_value}' in $config_file"
            fi
        done
        
        # Handle Port setting separately
        local desired_port="$SSH_PORT"
        if grep -q "^Port.*" "$config_file"; then
            if grep -q "^Port.*${desired_port}" "$config_file"; then
                echo "✓ Port is properly set to '${desired_port}' in $config_file"
            else
                if [ "$backup_created" = false ]; then
                    sudo cp "$config_file" "${config_file}${backup_suffix}"
                    backup_created=true
                fi
                echo "⚠ Updating Port to ${desired_port} in $config_file"
                sudo sed -i "s/^Port.*/Port ${desired_port}/" "$config_file"
            fi
        else
            echo "⚠ Adding Port ${desired_port} to $config_file"
            echo "Port ${desired_port}" | sudo tee -a "$config_file"
        fi
    fi
}

# (1) Add your SSH public key 
mkdir -p ~/.ssh
echo "$PUBKEY" >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys

# (2) Disable password authentication in all relevant configs
echo "Checking and fixing SSH configuration files..."

# Check main SSH config
check_and_fix_commented_auth "/etc/ssh/sshd_config"

# Check cloud-init config if it exists
check_and_fix_commented_auth "/etc/ssh/sshd_config.d/50-cloud-init.conf"

# Check for any other SSH config files in the directory
if [ -d "/etc/ssh/sshd_config.d/" ]; then
    for config_file in /etc/ssh/sshd_config.d/*.conf; do
        if [ -f "$config_file" ] && [ "$config_file" != "/etc/ssh/sshd_config.d/50-cloud-init.conf" ]; then
            check_and_fix_commented_auth "$config_file"
        fi
    done
fi

# (3) Handle systemd socket activation (for modern Ubuntu versions)
echo "Checking for systemd socket activation..."
if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
    echo "SSH socket activation detected. Configuring socket to use port ${SSH_PORT}..."
    
    # Create systemd override directory if it doesn't exist
    sudo mkdir -p /etc/systemd/system/ssh.socket.d/
    
    # Create override configuration
    sudo tee /etc/systemd/system/ssh.socket.d/override.conf > /dev/null <<EOF
[Socket]
ListenStream=
ListenStream=${SSH_PORT}
EOF
    
    echo "SSH socket override created for port ${SSH_PORT}"
    
    # Reload systemd and restart socket
    sudo systemctl daemon-reload
    sudo systemctl restart ssh.socket
    sudo systemctl restart ssh.service
    
    echo "SSH socket activation configured for port ${SSH_PORT}"
else
    echo "No SSH socket activation detected, using standard configuration"
fi

# (4) Configure firewall to allow SSH port
echo "Configuring firewall to allow SSH port ${SSH_PORT}..."
sudo ufw allow ${SSH_PORT}/tcp
echo "Firewall rule added for port ${SSH_PORT}"

# (5) Restart SSH service
sudo systemctl restart ssh

echo "SSH key setup complete. Password authentication disabled."
echo "All SSH configuration files have been checked and updated."