#!/bin/bash

set -e

# Function to check and fix commented PasswordAuthentication lines
check_and_fix_commented_auth() {
    local config_file="$1"
    local backup_suffix=".bak.$(date +%Y%m%d_%H%M%S)"
    
    if [ -f "$config_file" ]; then
        echo "Checking $config_file for commented PasswordAuthentication..."
        
        # Check for commented PasswordAuthentication yes lines
        if grep -q "^#.*PasswordAuthentication.*yes" "$config_file"; then
            echo "Found commented PasswordAuthentication yes in $config_file"
            sudo cp "$config_file" "${config_file}${backup_suffix}"
            # Uncomment and change to no
            sudo sed -i 's/^#.*PasswordAuthentication.*yes.*/PasswordAuthentication no/' "$config_file"
            echo "Fixed commented PasswordAuthentication in $config_file"
        fi
        
        # Check for any other commented PasswordAuthentication lines
        if grep -q "^#.*PasswordAuthentication" "$config_file"; then
            echo "Found other commented PasswordAuthentication lines in $config_file"
            sudo cp "$config_file" "${config_file}${backup_suffix}" 2>/dev/null || true
            # Uncomment and ensure it's set to no
            sudo sed -i 's/^#.*PasswordAuthentication.*/PasswordAuthentication no/' "$config_file"
            echo "Fixed all commented PasswordAuthentication lines in $config_file"
        fi
        
        # Verify the final state
        if grep -q "^PasswordAuthentication.*no" "$config_file"; then
            echo "✓ PasswordAuthentication is properly set to 'no' in $config_file"
        else
            echo "⚠ Adding PasswordAuthentication no to $config_file"
            echo "PasswordAuthentication no" | sudo tee -a "$config_file"
        fi
    fi
}

# (1) Add your SSH public key (replace below with your real public key)
PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIECb7zMSVVrnab22nImDBtaWcUqdy0saE9O78f1iBB+S phxcnx@gmail.com"
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

# (3) Restart SSH service
sudo systemctl restart ssh

echo "SSH key setup complete. Password authentication disabled."
echo "All SSH configuration files have been checked and updated."