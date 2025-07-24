#!/bin/bash

set -e

# (1) Add your SSH public key (replace below with your real public key)
PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIECb7zMSVVrnab22nImDBtaWcUqdy0saE9O78f1iBB+S phxcnx@gmail.com"
mkdir -p ~/.ssh
echo "$PUBKEY" >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys

# (2) Disable password authentication in all relevant configs
sudo sed -i.bak '/^PasswordAuthentication/s/yes/no/' /etc/ssh/sshd_config || echo "PasswordAuthentication no" | sudo tee -a /etc/ssh/sshd_config
# Also disable password auth in cloud-init config if it exists
if [ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]; then
    sudo sed -i.bak 's/^PasswordAuthentication yes/#PasswordAuthentication yes/' /etc/ssh/sshd_config.d/50-cloud-init.conf
fi

# (3) Restart SSH service
sudo systemctl restart ssh

echo "SSH key setup complete. Password authentication disabled."
