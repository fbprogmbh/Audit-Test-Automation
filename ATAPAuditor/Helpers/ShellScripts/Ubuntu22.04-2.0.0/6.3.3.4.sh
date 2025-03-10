#!/usr/bin/env bash

on_disk1=$(awk '/^ *-a *always,exit/ &&/ -F *arch=b(32|64)/ &&/ -S/ &&(/adjtimex/ ||/settimeofday/ ||/clock_settime/ ) &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules)

on_disk2=$(awk '/^ *-w/ &&/\/etc\/localtime/ &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules)

if [[ -n "$on_disk1" && -n "$on_disk2" ]]; then
	exit 0
else
	exit 1
fi
