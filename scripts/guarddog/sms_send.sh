#!/bin/bash
SUBJ="$1"
BODY_FILE="$2"
[ -z "$BODY_FILE" ] || [ ! -f "$BODY_FILE" ] && exit 0
/usr/bin/python3 /opt/tak-guarddog/sms_send.py "$SUBJ" "$BODY_FILE"
