#!/bin/bash

set -e

# =============================================================================
# CONFIGURATION - Edit these variables as needed
# =============================================================================

# Add your SSH public key here (replace with your actual public key)
PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIECb7zMSVVrnab22nImDBtaWcUqdy0saE9O78f1iBB+S phxcnx@gmail.com"

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
            ["Port"]="2222"
        )
        
        # Process each authentication setting
        for setting in "${!auth_settings[@]}"; do
            local desired_value="${auth_settings[$setting]}"
            
            # Check for commented lines with yes values
            if grep -q "^#.*${setting}.*yes" "$config_file"; then
                if [ "$backup_created" = false ]; then
                    sudo cp "$config_file" "${config_file}${backup_suffix}"
                    backup_created=true
                fi
                echo "Found commented ${setting} yes in $config_file"
                # Uncomment and change to desired value
                sudo sed -i "s/^#.*${setting}.*yes.*/${setting} ${desired_value}/" "$config_file"
                echo "Fixed commented ${setting} in $config_file"
            fi
            
            # Check for any other commented lines for this setting
            if grep -q "^#.*${setting}" "$config_file"; then
                if [ "$backup_created" = false ]; then
                    sudo cp "$config_file" "${config_file}${backup_suffix}" 2>/dev/null || true
                    backup_created=true
                fi
                echo "Found other commented ${setting} lines in $config_file"
                # Uncomment and ensure it's set to desired value
                sudo sed -i "s/^#.*${setting}.*/${setting} ${desired_value}/" "$config_file"
                echo "Fixed all commented ${setting} lines in $config_file"
            fi
            
            # Verify the final state and add if missing
            if grep -q "^${setting}.*${desired_value}" "$config_file"; then
                echo "✓ ${setting} is properly set to '${desired_value}' in $config_file"
            else
                echo "⚠ Adding ${setting} ${desired_value} to $config_file"
                echo "${setting} ${desired_value}" | sudo tee -a "$config_file"
            fi
        done
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

# (3) Restart SSH service
sudo systemctl restart ssh

echo "SSH key setup complete. Password authentication disabled."
echo "All SSH configuration files have been checked and updated."