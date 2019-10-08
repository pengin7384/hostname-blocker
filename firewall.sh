#!/bin/bash
rule_file="firewall.rules"
rules=()

while read line
do	
	rules+=$line
	rules+="|"
done < "$rule_file"

sudo insmod firewall.ko input="$rules"
