#!/usr/bin/env bash

{
  awk '/^ *-w/&&(/\/etc\/apparmor/ ||/\/etc\/apparmor.d/)&&/ +-p *wa/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
}
