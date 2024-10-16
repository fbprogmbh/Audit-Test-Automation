#!/bin/bash
awk -F: '($4 == "<shadow-gid>") { print }' /etc/passwd