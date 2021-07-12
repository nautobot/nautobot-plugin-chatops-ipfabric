#!/usr/bin/env bash

set -euo pipefail

# Hardcoded IP for the development server
TARGET_HOST_IP=159.65.241.133

chmod 600  /tmp/kitt-generic-ssh-key
eval "$(ssh-agent -s)"
openssl aes-256-cbc -K $encrypted_7d8846f60ae2_key -iv $encrypted_7d8846f60ae2_iv -in kitt-generic-ssh-key.enc -out /tmp/kitt-generic-ssh-key -d
echo "INFO: Connecting via SSH to ${TARGET_HOST_IP}"

# There are a lot of assumptions taken to simplify such as:
# - the folder /opt/chatbot-ipfabric is there and git is already cloned and has a deployment key to interact with git
# - poetry is installed

ssh -t -o StrictHostKeyChecking=no root@"${TARGET_HOST_IP}" -i  /tmp/kitt-generic-ssh-key << EOF
    cd /opt/chatbot-ipfabric
    git checkout develop
    git reset --hard origin/develop
    poetry install
    poetry run inv build && poetry run inv stop && poetry run inv start
EOF

echo "INFO: Server has been pulled latest develop branch and restarted the development environment"
