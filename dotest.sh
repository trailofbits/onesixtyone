#!/bin/bash

pidof snmpd || { echo "snmpd not running?"; exit 1; }

result=$(./onesixtyone 127.0.0.1)

if [[ "$result" == *"public"* ]]; then
   echo "OK"
   exit 0
fi

echo "FAIL"
exit 1
