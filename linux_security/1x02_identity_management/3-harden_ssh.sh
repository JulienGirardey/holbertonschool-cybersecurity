#!/bin/bash

file="$1"
# param[1]="PermitRootLogin"
# param[2]="PubkeyAuthentication"
# param[3]="PasswordAuthentication"

edit_sshd_config(){
  for PARAM in ${param[@]}
  do
    /usr/bin/sed -i '/^'"${PARAM}"'/d' ${file}
    /usr/bin/echo "All lines beginning with '${PARAM}' were deleted from ${file}."
  done
  /usr/bin/echo "PermitRootLogin no" >> ${file}
  /usr/bin/echo "'PermitRootLogin no' was added to ${file}."
  /usr/bin/echo "PubkeyAuthentication yes" >> ${file}
  /usr/bin/echo "'PubkeyAuthentication yes' was added to ${file}."
  /usr/bin/echo "PasswordAuthentication no" >> ${file}
  /usr/bin/echo "'PasswordAuthentication no' was added to ${file}."
}

reload_sshd(){
  /usr/bin/systemctl reload sshd.service
  /usr/bin/echo "Run '/usr/bin/systemctl reload sshd.service'...OK"
}

edit_sshd_config
sshd -t
reload_sshd
