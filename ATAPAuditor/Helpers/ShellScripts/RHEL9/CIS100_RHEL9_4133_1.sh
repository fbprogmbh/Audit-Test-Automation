    #!/usr/bin/env bash
    {
        SUDO_LOG_FILE_ESCAPED=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//' -e 's/"//g' -e 's|/|\\/|g')
        [ -n "${SUDO_LOG_FILE_ESCAPED}" ] && awk "/^ *-w/ \ &&/"${SUDO_LOG_FILE_ESCAPED}"/ &&/ +-p *wa/ \ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules || printf "ERROR: Variable 'SUDO_LOG_FILE_ESCAPED' is unset.\n"
    }