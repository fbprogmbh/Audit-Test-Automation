#!/usr/bin/env bash

UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)

if [ -n "${UID_MIN}" ]; then
	on_disk=$(awk "/^ *-a *always,exit/ &&/ -F *arch=b(32|64)/ &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) &&/ -F *auid>=${UID_MIN}/ &&(/ -F *exit=-EACCES/||/ -F *exit=-EPERM/) &&/ -S/ &&/creat/ &&/open/ &&/truncate/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules)

	if [[ -n "$on_disk" ]]; then
		exit 0
	else
		exit 1
	fi
else
	exit 1
fi
