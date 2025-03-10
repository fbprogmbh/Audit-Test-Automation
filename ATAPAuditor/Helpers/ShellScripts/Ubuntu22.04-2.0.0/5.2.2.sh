#!/usr/bin/env bash

# Simplified pattern
pattern="Defaults use_pty"

# Check if the pattern exists in /etc/sudoers
if grep -E "^\s*Defaults\s+use_pty" /etc/sudoers >/dev/null; then
	exit 0
else
	exit 1
fi
