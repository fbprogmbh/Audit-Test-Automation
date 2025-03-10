#!/usr/bin/env bash
if ! command -v sshd &>/dev/null; then
	echo "sshd command could not be found"
	exit 0
fi

# Check using sshd -T output
actual_value=$(sshd -T | grep -Pi -- 'macs\h+([^#\n\r]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)')

if [ -z "$actual_value" ]; then
	exit 0
else
	exit 1
fi
