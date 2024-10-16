#!/bin/bash
awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow