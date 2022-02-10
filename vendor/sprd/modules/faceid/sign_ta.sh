#!/usr/bin/env bash

# $1 sign script
# $2 uuid
# $3 key
# $4 input source unsigned elf
# $5 output target signed elf

/usr/bin/python $1 --uuid $2 --key $3 --in $4 --out $5