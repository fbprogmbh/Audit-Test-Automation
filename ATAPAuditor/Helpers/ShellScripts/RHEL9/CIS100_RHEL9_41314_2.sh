#!/usr/bin/env bash
{
     /usr/sbin/auditctl -l | awk '/^ *-w/ &&(/\/etc\/selinux/ ||/\/usr\/share\/selinux/) &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
}