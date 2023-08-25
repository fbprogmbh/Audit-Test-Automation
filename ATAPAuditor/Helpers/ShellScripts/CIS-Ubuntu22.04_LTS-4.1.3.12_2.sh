#!/usr/bin/env bash
{
  auditctl -l | awk '/^ *-w/ \
&&(/\/var\/log\/lastlog/ \
 ||/\/var\/run\/faillock/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
}
