#!/usr/bin/env bash
{
    auditctl -l | awk '/^ *-w/ &&(/\/etc\/selinux/ ||/\/usr\/share\/selinux/) &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
}