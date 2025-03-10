#!/usr/bin/env bash

if ! command -v sshd &>/dev/null; then
	echo "sshd command could not be found"
	exit 0
fi

# Check using sshd -T output
actual_value=$(sshd -T | grep -Pi -- '^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))-cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se|chacha20-poly1305@openssh\.com)')

if [ -z "$actual_value" ]; then
	exit 0
else
	exit 1
fi
