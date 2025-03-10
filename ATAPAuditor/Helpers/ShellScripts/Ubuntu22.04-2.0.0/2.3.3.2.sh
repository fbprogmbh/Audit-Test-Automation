#!/usr/bin/env bash

if ! command -v chronyd &>/dev/null; then
	# chronyd is not installed
	exit 0
fi

if ps -ef | grep -v grep | grep -q "chronyd"; then
	if ps -ef | grep -v grep | grep "chronyd" | awk '{print $1}' | grep -q "^_chrony$"; then
		exit 0
	else
		exit 1
	fi
else
	exit 0
fi
