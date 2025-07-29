#!/bin/sh
set -e

PORT="${SSH_PORT:-2222}"

# Update server configuration
if [ -f /etc/ssh/sshd_config ]; then
    sed -i "s/^Port .*/Port ${PORT}/" /etc/ssh/sshd_config
fi

# Update client configuration if present
if [ -f /root/.ssh/config ]; then
    sed -i "s/^\s*Port .*/    Port ${PORT}/" /root/.ssh/config
    chmod 600 /root/.ssh/config
fi

exec /usr/sbin/sshd -D -e
