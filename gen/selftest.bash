#!/usr/bin/bash

if [ $(whoami) != root ]; then
	echo "error: run as root"
	exit 1
fi

if [ $(uname) != Linux ]; then
	echo "error: run on Linux"
	exit 1
fi

veth_name=ipgen_test
txif=${veth_name}_tx
rxif=${veth_name}_rx

ip link add $txif type veth peer name $rxif

function cleanup
{
	ip link set down dev $txif
	ip link delete $txif
}
trap cleanup EXIT INT TERM

txmac=$(ip link show $txif |awk '/link/ {print $2;}')
rxmac=$(ip link show $txif |awk '/link/ {print $2;}')


testid=0
function testmsg
{
	local long=${2:-false}

	if $long; then
		echo -n "[$testid] Testing $1, take a while..."
	else
		echo -n "[$testid] Testing $1..."
	fi
	testid=$((testid + 1))
}

function endmsg
{

	echo "passed"
}

function run0
{

	./ipgen --nocurses $* -t 1 >/dev/null 2>./.error.log
	if [ $? != 0 ]; then
		echo "failed"
		cat ./.error.log
		rm -f ./.error.log
		exit 1
	fi
	endmsg
	rm -f ./.error.log
}

function run
{

	./ipgen --nocurses --fail-if-dropped -T $txif,$rxmac -R $rxif,$txmac $* \
	    -t 2 -p 1000 -s 46 >/dev/null 2>./.error.log
	if [ $? != 0 ]; then
		echo "Test failed: $*"
		cat ./.error.log
		rm -f ./.error.log
		exit 1
	fi
	endmsg
	rm -f ./.error.log
}

function run2544
{

	./ipgen --nocurses --rfc2544 --rfc2544-slowstart --rfc2544-pps-resolution 0.1 \
	    --rfc2544-trial-duration 1 --rfc2544-tolerable-error-rate 0.1 $* >/dev/null 2>./.error.log
	if [ $? != 0 ]; then
		echo "Test failed"
		cat ./.error.log
		rm -f ./.error.log
		exit 1
	fi
	endmsg
	rm -f ./.error.log
}

testmsg "packet generation benchmark (-X)"
run0 -X

testmsg "packet generation benchmark (-XX)"
run0 -XX

testmsg "packet generation benchmark (-XXX)"
run0 -XXX


testmsg "send/recv test"
run

testmsg "send/recv test (full-duplex)"
run -f

testmsg "send/recv test with IPv4"
run --saddr 10.0.0.1 --daddr 10.0.0.2

testmsg "send/recv test with IPv6"
run --saddr fc00::1 --daddr fc00::2

testmsg "send/recv test with IPv4 (TCP)"
run --saddr 10.0.0.1 --daddr 10.0.0.2 --tcp

testmsg "send/recv test with IPv6 (TCP)"
run --saddr fc00::1 --daddr fc00::2 --tcp

testmsg "send/recv test with IPv4 (TCP, fragment)"
run --saddr 10.0.0.1 --daddr 10.0.0.2 --tcp --fragment

testmsg "send/recv test with IPv6 (TCP, fragment)"
run --saddr fc00::1 --daddr fc00::2 --tcp --fragment

testmsg "send/recv test with IPv4 (range)"
run --saddr 10.0.0.1-10.0.0.10 --daddr 10.0.0.11-10.0.0.20

testmsg "send/recv test with IPv6 (range)"
run --saddr fc00::1-fc00::10 --daddr fc00::11-fc00::20

testmsg "send/recv test with IPv4 (allnet)"
run0 -T $txif,$rxmac,10.0.0.1/24 -R $rxif,$txmac,10.0.1.1/24 --allnet

testmsg "send/recv test with IPv6 (allnet)"
run0 -T $txif,$rxmac,fc00::1/112 -R $rxif,$txmac,fc00:1::1/112 --allnet


testmsg "RFC 2544 test with IPv4" true
run2544 -T $txif,$rxmac,10.0.0.1/24 -R $rxif,$txmac,10.0.1.1/24 --rfc2544-pktsize 46

testmsg "RFC 2544 test with IPv6" true
run2544 -T $txif,$rxmac,fc00::1/112 -R $rxif,$txmac,fc00:1::1/112 --rfc2544-pktsize 62


testmsg "send/recv test with VLAN"
run0 -V 10 -T $txif,$rxmac -R $rxif,$txmac

#testmsg "send/recv test via veth with PPPoE"
#run0 -P -T $txif,$rxmac -R $rxif,$txmac

