#!/usr/bin/env bash

GRUB_CFG="/etc/default/grub"

if [[ ! -f "$GRUB_CFG" ]]; then
	echo "Error: $GRUB_CFG does not exist."
	exit 1
fi
if grep -q "audit_backlog_limit" "$GRUB_CFG"; then
	echo "Found 'audit_backlog_limit=1' in $GRUB_CFG."
	exit 0
else
	echo "'audit_backlog_limit=1' not found in $GRUB_CFG."
	exit 1
fi
