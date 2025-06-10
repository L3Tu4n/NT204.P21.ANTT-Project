#!/bin/bash
IP="$1"
WHITELIST="/opt/elastalert2/scripts/whitelist.txt"

if grep -Fxq "$IP" "$WHITELIST"; then
  echo "$IP is whitelisted, not blocking."
  exit 0
fi

ansible-playbook /opt/elastalert2/scripts/block_playbook.yml --extra-vars "ip=$IP"
