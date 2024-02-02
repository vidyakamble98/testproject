#!/bin/bash
# -*- coding: utf-8 -*-
#set -x
########################################################################################################################
# Script: SASC_Unix_Audit_Users_Get-Local-User-Pass-expiry-Date
#
# Description: Ce script permet de recuperer les informations sur la date d'expiration des mots des users locaux
# Version: 1.1.0 (ou 1: modification majeure, 2: modification mineure, 3: correction de bug)
#
# Date de creation:20/02/2023
# Cree par: Lefrem N.
#
#
# Mise a jour:
#
# Pre-requis:                           Le serveur est de type Linux - Aix
#
# Inputs:                   -expire nbr days example: -expire 15
#
#
#
# Outputs:
#                           0 : le script s'est correctement d roul
#                           2 : OS not supported
#
########################################################################################################################

OS=$(uname | tr 'A-Z' 'a-z')
#HOST=$(uname -n)
#SERVER_NAME=$(hostname | awk -F. '{print $1}')

case $1 in
-expire)
    [ -z "$2" ] && echo "Please provide a number of days after '$1'" >&2 && exit 96
    ;;
*)
    echo "Please use '-expire' as a parameter" >&2 && exit 96
    ;;

esac

# Number of days before expiration
days="$2"


if [ "$OS" == "linux" ]; then
    USERS=$(cut -d: -f1 /etc/passwd)
    current_date=$(date +"%d-%m-%Y")

    for user in $USERS; do
        EXPIRY_DATE=$(chage -l "$user" 2>/dev/null | grep "Password expires" | awk '{print $4, $5, $6}')
        if [[ -n "$EXPIRY_DATE" && "$(echo "$EXPIRY_DATE" | tr '[:upper:]' '[:lower:]')" == *"password must be"* ]]; then
            echo "$user"
        elif [[ -n "$EXPIRY_DATE" && "$(echo "$EXPIRY_DATE" | tr '[:upper:]' '[:lower:]')" != *"never"* ]]; then
            expiration_date=$(date -d "$EXPIRY_DATE" +"%d-%m-%Y")
            days_until=$(( ( $(date -d "$EXPIRY_DATE" +"%s") - $(date +"%s") ) / 86400 ))
            
            if [ "$days_until" -le "$days" ]; then
                #echo "$SERVER_NAME,$user,$(date -d "$EXPIRY_DATE" +"%d/%m/%Y")"
                echo "$user"
            fi
        fi
    done

# elif [ "$OS" == "aix" ]; then
    # Parse AIX password expiration using the lsuser command
    # USERS=$(lsuser -a expires ALL)
    # current_epoch=$(perl -e 'use POSIX; print strftime("%s", localtime())')

    # for user in "${USERS[@]}"; do
    #     echo "$user"
    #     username=$(echo "$user" | cut -d ' ' -f 1)
    #     expires_field=$(echo "$user" | grep "expires=")

    #     time_since_last_update_in_epoch=$(lssec -f /etc/security/passwd -s $username -a lastupdate | cut -d= -f2)
    #     max_age=$(lsuser -f $username | grep maxage | cut -d= -f2)
    #     max_age_in_days=$(echo $((( max_age * 7 ))))
    #     max_age_in_epoch=$(echo $((( $max_age_in_days * 86400 ))) )
    #     time_until_expires_in_epoch=$(echo $((( $max_age_in_epoch + $time_since_last_update_in_epoch ))))
    #     time_of_expiration=$(perl -le 'print scalar localtime $ARGV[0]' ${time_until_expires_in_epoch})

    #     if [[ -n "$expires_field" ]]; then
    #         expires_date=$(echo "$expires_field" | awk -F'=' '{print $2}')

    #         if [[ "$expires_date" != "0" ]]; then
    #             days_until=$(( (expires_date - current_epoch) / 86400 ))
    #             echo -e "$username,$current_epoch,$expires_field,$expires_date,$days_until"

    #             if [ "$days_until" -eq "$days" ]; then
    #                 #echo -e "$SERVER_NAME,$username,$(perl -le 'use POSIX; print strftime("%d/%m/%Y", localtime($ARGV[0]))' "$expires_date")"
    #                 echo -e "$username"
    #             fi
    #         fi
    #     fi
    # done

else
    echo "Unsupported operating system: $OS" >&2
    exit 97
fi
