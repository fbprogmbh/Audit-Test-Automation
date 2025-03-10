#!/usr/bin/env bash

on_disk=$(awk '/^ *-a *always,exit/ &&/ -F *arch=b(32|64)/ &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) &&(/ -C *euid!=uid/||/ -C *uid!=euid/) &&/ -S *execve/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules)

if [[ -n "$on_disk" ]]; then
	exit 0
else
	echo "ERROR: Audit rules are NOT correctly set."
	exit 1
fi
