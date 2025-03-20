#!/usr/bin/env bash
{
  auditctl -l | awk '/^ *-w/ \
&&(/\/var\/run\/utmp/ \
 ||/\/var\/log\/wtmp/ \
 ||/\/var\/log\/btmp/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
}
