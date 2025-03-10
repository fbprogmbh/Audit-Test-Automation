#!/usr/bin/env bash

on_disk=$(awk '/^ *-w/ &&(/\/var\/log\/lastlog/  ||/\/var\/run\/faillock/) &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules)

if [[ -n "$on_disk" ]]; then
	exit 0
else
	echo "ERROR: Audit rules are NOT correctly set."
	exit 1
fi
