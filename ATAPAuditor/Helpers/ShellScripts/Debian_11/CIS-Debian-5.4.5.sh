#!/usr/bin/env bash
{
    declare -A HASH_MAP=(["y"]="yescrypt" ["1"]="md5" ["2"]="blowfish"
        ["5"]="SHA256" ["6"]="SHA512" ["g"]="gost-yescrypt")
    CONFIGURED_HASH=$(sed -n "s/^\s*ENCRYPT_METHOD\s*\(.*\)\s*$/\1/p" /etc/login.defs )
    for MY_USER in $(sed -n "s/^\(.*\):\\$.*/\1/p" /etc/shadow); do
        CURRENT_HASH=$(sed -n "s/${MY_USER}:\\$\(.\).*/\1/p" /etc/shadow)
        if [[ "${HASH_MAP["${CURRENT_HASH}"]^^}" != "${CONFIGURED_HASH^^}" ]]; then
            echo "The password for '${MY_USER}' is using '${HASH_MAP["${CURRENT_HASH}"]}' instead of the configured '${CONFIGURED_HASH}'."
        fi
    done
}
