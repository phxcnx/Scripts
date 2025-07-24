#!/bin/bash

set -e

# (1) Add your SSH public key (replace below with your real public key)
PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIECb7zMSVVrnab22nImDBtaWcUqdy0saE9O78f1iBB+S phxcnx@gmail.com"
mkdir -p ~/.ssh
echo "$PUBKEY" >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys

# (2) Disable password authentication in all relevant configs
if [ -f /etc/ssh/sshd_config ]; then
    sudo sed -i.bak '/^PasswordAuthentication/s/yes/no/' /etc/ssh/sshd_config || echo "PasswordAuthentication no" | sudo tee -a /etc/ssh/sshd_config
else
    echo "Warning: /etc/ssh/sshd_config not found"
fi

if [ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]; then
    sudo sed -i.bak 's/^PasswordAuthentication yes/#PasswordAuthentication yes/' /etc/ssh/sshd_config.d/50-cloud-init.conf
else
    echo "Note: /etc/ssh/sshd_config.d/50-cloud-init.conf not found - skipping cloud-init config modification"
fi

# (3) Restart SSH service
if systemctl is-active --quiet ssh; then
    sudo systemctl restart ssh
elif systemctl is-active --quiet sshd; then
    sudo systemctl restart sshd
else
    echo "Warning: Neither ssh nor sshd service found"
fi

echo "SSH key setup complete. Password authentication disabled."
