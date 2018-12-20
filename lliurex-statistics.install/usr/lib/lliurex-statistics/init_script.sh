#!/bin/bash

set_acls()
{
    if [ -w "${STATUS_FILE}" ]; then
        # fixed group 10003 for teachers into ldap
        setfacl -m g:10003:rw ${STATUS_FILE}
        setfacl -m g:adm:rw ${STATUS_FILE}
    fi
}
remove_locks()
{
    if [ -f "${LOCK_FILE}" ]; then
        log_success_msg "Removing lockfile ${LOCK_FILE}"
        rm -f ${LOCK_FILE}
    fi
}

set_acls
remove_locks