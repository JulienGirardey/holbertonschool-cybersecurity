#!/bin/bash
#
# Description:
# This script sets certain parameters in /etc/ssh/sshd_config.
# It's not production ready and only used for training purposes.
#
# What should it do?
# * Check whether a /etc/ssh/sshd_config file exists
# * Create a backup of this file
# * Edit the file to set certain parameters
# * Reload the sshd configuration
# To enable debugging mode remove '#' from the following line
#set -x
# Variables

file="$1"
param[1]="PermitRootLogin "
param[2]="PubkeyAuthentication"
param[3]="PasswordAuthentication"

edit_sshd_config(){
  for PARAM in ${param[@]}
  do
    /usr/bin/sed -i '/^'"${PARAM}"'/d' ${file}
    /usr/bin/echo "All lines beginning with '${PARAM}' were deleted from ${file}."
  done
  /usr/bin/echo "${param[1]} no" >> ${file}
  /usr/bin/echo "'${param[1]} no' was added to ${file}."
  /usr/bin/echo "${param[2]} yes" >> ${file}
  /usr/bin/echo "'${param[2]} yes' was added to ${file}."
  /usr/bin/echo "${param[3]} no" >> ${file}
  /usr/bin/echo "'${param[3]} no' was added to ${file}."
}

reload_sshd(){
  /usr/bin/systemctl reload sshd.service
  /usr/bin/echo "Run '/usr/bin/systemctl reload sshd.service'...OK"
}

# main
while getopts .h. OPTION
do
  case $OPTION in
    h)
    usage
    exit;;
    ?)
    usage
    exit;;
  esac
done

if [ -z "${file}" ]
then

file="/etc/ssh/sshd_config"
fi
edit_sshd_config
reload_sshd
