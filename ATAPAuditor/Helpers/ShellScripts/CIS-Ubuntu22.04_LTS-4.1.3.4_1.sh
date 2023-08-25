#!/usr/bin/env bash

{
    awk '/^ *-a *always,exit/ \
 &&/ -F *arch=b[2346]{2}/ \
 &&/ -S/ \
 &&(/adjtimex/ \
 ||/settimeofday/ \
 ||/clock_settime/ ) \
 &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules

    awk '/^ *-w/ \
 &&/\/etc\/localtime/ \
 &&/ +-p *wa/ \
 &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
}
