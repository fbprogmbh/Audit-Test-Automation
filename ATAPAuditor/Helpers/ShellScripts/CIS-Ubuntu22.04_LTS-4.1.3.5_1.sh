#!/usr/bin/env bash

{
   awk '/^ *-a *always,exit/ \
&&/ -F *arch=b(32|64)/ \
&&/ -S/ \
&&(/sethostname/ \
 ||/setdomainname/) \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules

   awk '/^ *-w/ \
&&(/\/etc\/issue/ \
 ||/\/etc\/issue.net/ \
 ||/\/etc\/hosts/ \
 ||/\/etc\/network/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
}
