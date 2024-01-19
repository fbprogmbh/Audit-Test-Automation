#!/usr/bin/env bash

{
  auditctl -l | awk '/^ *-w/&&(/\/etc\/apparmor/ ||/\/etc\/apparmor.d/)&&/ +-p *wa/&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
}
