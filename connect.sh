#!/bin/bash

# Simple helper script to connect to a running container
# Usage: ./connect.sh {server|client}
# This wraps the docker exec command:
#   sudo docker exec -it ssh_{server|client} /bin/bash

set -e

if [ "$1" != "server" ] && [ "$1" != "client" ]; then
    echo "Usage: $0 {server|client}" >&2
    exit 1
fi

sudo docker exec -it ssh_$1 /bin/bash
