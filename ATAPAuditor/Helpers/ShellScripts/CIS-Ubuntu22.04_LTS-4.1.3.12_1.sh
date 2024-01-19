#!/usr/bin/env bash

{
  awk '/^ *-w/ \
&&(/\/var\/log\/lastlog/ \
 ||/\/var\/run\/faillock/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
}
