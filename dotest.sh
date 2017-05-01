#!/bin/bash

result=$(./onesixtyone 127.0.0.1)
if [[ "$result" == *"public"* ]]; then
   echo "OK"
   exit 0
fi
exit 1 
