#!/bin/bash

# based off the following two scripts
# http://www.theunsupported.com/2012/07/block-malicious-ip-addresses/
# http://www.cyberciti.biz/tips/block-spamming-scanning-with-iptables.html

#
# Emerging Threats fwip rules.
#
# Raw IPs for the firewall block lists. These come from:
#
# Spam nets identified by Spamhaus (www.spamhaus.org)
# Top Attackers listed by DShield (www.dshield.org)
# Abuse.ch

# path to iptables
IPTABLES="/sbin/iptables";

# list of known spammers
URL="https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt";

# save local copy here
FILE="/tmp/emerging-Block-IPs.txt";

# iptables custom chain
CHAIN="CloudRambo";

# check to see if the chain already exists
$IPTABLES -L $CHAIN -n

# check to see if the chain already exists
if [ $? -eq 0 ]; then

    # flush the old rules
    $IPTABLES -F $CHAIN

    echo "Flushed old rules. Applying updated DROP list...."    

else

    # create a new chain set
    $IPTABLES -N $CHAIN

    # tie chain to input rules so it runs
    $IPTABLES -A INPUT -j $CHAIN

    # don't allow this traffic through
    $IPTABLES -A FORWARD -j $CHAIN

    echo "Chain not detected. Creating new chain and adding DROP list...."

fi;

# get a copy of the spam list
wget -qc $URL -O $FILE

# iterate through all known spamming hosts
for IP in $( cat $FILE | egrep -v '(^;|^#.*|^$)' | awk '{ print $1}' ); do

    # add the ip address log rule to the chain
    $IPTABLES -A $CHAIN -p 0 -s $IP -j LOG --log-prefix "[CloudRambo DROP]" -m limit --limit 3/min --limit-burst 10

    # add the ip address to the chain
    $IPTABLES -A $CHAIN -p 0 -s $IP -j DROP

    echo $IP

done

echo "Done!"

# remove the spam list
unlink $FILE
