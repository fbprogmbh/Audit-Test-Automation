#!/usr/bin/env bash

timeout=$(grep -roP "timestamp_timeout=\K[0-9]*" /etc/sudoers* | grep -v "/etc/sudoers.bak")

if [ -n "$timeout" ]; then
	timeout=$(echo "$timeout" | grep -oP "[0-9]+$")
fi

if [ -z "$timeout" ]; then
	timeout=$(sudo -V | grep -oP "(?<=Authentication timestamp timeout: )\d+")
fi

if [ -z "$timeout" ]; then
	timeout=0
fi

timeout=${timeout:-0}

if [ "$timeout" -le 15 ] && [ "$timeout" -gt 0 ]; then
	exit 0
else
	exit 1
fi
