#!/usr/bin/env bash

{
  awk '/^ *-w/ \
&&(/\/var\/run\/utmp/ \
 ||/\/var\/log\/wtmp/ \
 ||/\/var\/log\/btmp/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
}
