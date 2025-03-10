#!/usr/bin/env bash

on_disk1=$(awk '/^ *-a *always,exit/ &&/ -F *arch=b(32|64)/ &&/ -S/ &&(/sethostname/ ||/setdomainname/) &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules)

on_disk2=$(awk '/^ *-w/ &&(/\/etc\/issue/ ||/\/etc\/issue.net/ ||/\/etc\/hosts/ ||/\/etc\/network/ ||/\/etc\/netplan/) &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules)

if [[ -n "$on_disk1" && -n "$on_disk2" ]]; then
	exit 0
else
	exit 1
fi
