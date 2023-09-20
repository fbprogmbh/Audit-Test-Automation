#!/usr/bin/env bash

{
    echo -e "\n- Start check - logfiles have appropriate permissions and ownership"
    output=""
    find /var/log -type f | (
        while read -r fname; do
            bname="$(basename "$fname")"
            case "$bname" in lastlog | lastlog.* | wtmp | wtmp.* | btmp | btmp.*)
                if ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,2,4,6][0,4]\h*$'; then
                    output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")\"\n"
                fi
                if ! stat -Lc "%U %G" "$fname" | grep -Pq -- '^\h*root\h+(utmp|root)\h*$'; then
                    output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")\"\n"
                fi
                ;;
            secure | auth.log)
                if ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,4]0\h*$'; then
                    output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")\"\n"
                fi
                if ! stat -Lc "%U %G" "$fname" | grep -Pq -- '^\h*(syslog|root)\h+(adm|root)\h*$'; then
                    output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")\"\n"
                fi
                ;;
            SSSD | sssd)
                if ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,2,4,6]0\h*$'; then
                    output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")\"\n"
                fi
                if ! stat -Lc "%U %G" "$fname" | grep -Piq -- '^\h*(SSSD|root)\h+(SSSD|root)\h*$'; then
                    output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")\"\n"
                fi
                ;;
            gdm | gdm3)
                if ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,2,4,6]0\h*$'; then
                    output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")\"\n"
                fi
                if ! stat -Lc "%U %G" "$fname" | grep -Pq -- '^\h*(root)\h+(gdm3?|root)\h*$'; then
                    output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")\"\n"
                fi
                ;;
            *.journal)
                if ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,4]0\h*$'; then
                    output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")\"\n"
                fi
                if ! stat -Lc "%U %G" "$fname" | grep -Pq -- '^\h*(root)\h+(systemd-journal|root)\h*$'; then
                    output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")\"\n"
                fi
                ;;
            *)
                if ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,4]0\h*$'; then
                    output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")\"\n"
                fi
                if ! stat -Lc "%U %G" "$fname" | grep -Pq -- '^\h*(syslog|root)\h+(adm|root)\h*$'; then
                    output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")\"\n"
                fi
                ;;
            esac
        done
        # If all files passed, then we pass
        if [ -z "$output" ]; then
            echo -e "\n- PASS\n- All files in \"/var/log/\" have appropriate permissions and ownership\n"
        else
            # print the reason why we are failing
            echo -e "\n- FAIL:\n$output"
        fi
        echo -e "- End check - logfiles have appropriate permissions and ownership\n"
    )
}
