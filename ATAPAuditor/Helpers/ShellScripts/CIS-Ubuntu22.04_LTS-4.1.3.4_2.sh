#!/usr/bin/env bash

{
    auditctl -l | awk '/^ *-a *always,exit/ \
 &&/ -F *arch=b[2346]{2}/ \
 &&/ -S/ \
 &&(/adjtimex/ \
 ||/settimeofday/ \
 ||/clock_settime/ ) \
 &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'

    auditctl -l | awk '/^ *-w/ \
 &&/\/etc\/localtime/ \
 &&/ +-p *wa/ \
 &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
}
