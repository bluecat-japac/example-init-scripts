#!/bin/bash
CREDENTIALS_VCENTER_JSON_PATH='configs/credential_conf.json'

VCENTER_USERNAME_STR=$(printf '%s\n' "$VCENTER_USERNAME" | sed -e 's/[\/&]/\\&/g')
sed -i -e "s/<vcenter_username>/${VCENTER_USERNAME}/g"  $CREDENTIALS_VCENTER_JSON_PATH

VCENTER_PASSWORD_STR=$(printf '%s\n' "$VCENTER_PASSWORD" | sed -e 's/[\/&]/\\&/g')
sed -i -e "s/<vcenter_password>/${VCENTER_PASSWORD}/g"  $CREDENTIALS_VCENTER_JSON_PATH

