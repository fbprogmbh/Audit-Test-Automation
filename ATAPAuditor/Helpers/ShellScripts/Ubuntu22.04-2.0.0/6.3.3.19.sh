#!/usr/bin/env bash

UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)

if [ -n "$UID_MIN" ]; then
	on_disk=$(awk '/^ *-a *always,exit/  &&/ -F *arch=b(32|64)/  &&(/ -F auid!=unset/||/ -F auid!=-1/||/ -F auid!=4294967295/)  &&/ -S/  &&(/init_module/  ||/finit_module/  ||/delete_module/  ||/create_module/  ||/query_module/)  &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules)

	if [[ -n "$on_disk" ]]; then
		exit 0
	else
		echo "ERROR: on_disk != loaded"
		exit 1
	fi
else
	echo "ERROR: Variable 'UID_MIN' is unset.\n"
	exit 1
fi
