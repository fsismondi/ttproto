#!/usr/bin/env python3

#from typecheck3000 import typecheck, optional, either, iterable, tuple_of, list_of, dict_of, with_attr

"""


assert IPv6Address ("2001:DB8::1") == b' \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
assert IPv6Address ("fe80::212:34ff:fe56:7890") == b'\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x124\xff\xfeVx\x90'






if __name__ == "__main__":

	v1 = 4 # Message (int, 4)
	v2 = 5 # Message (UInt16, 5)

	Integer_0_to_10 = Range (int, 0, 10)

	assert v1 in Integer_0_to_10
	assert v1 not in Range (int, 0, 3)
	assert v1 in ValueList (int, [0, 4, 7])
	assert v1 not in ValueList (int, [0, 3])

	assert "arst" in Length (str, 4)
	assert "arst" not in Length (str, (5, 8))
	assert "arst" not in Length (str, [3, (5, 8)])

	ip = IPv6 (HopLimit = 5, SourceAddress = "fe80::0:0:42")
	ip2 = ip (TrafficClass = 54)

	assert ip     in IPv6 (HopLimit = 5)
	assert ip not in IPv6 (HopLimit = 1)
	assert ip not in IPv6 (HopLimit = 1) (HopLimit = 5)
	assert ip not in IPv6 (HopLimit = 5) (HopLimit = 1)

	udp = UDP (SourcePort = 1025, DestinationPort = 1025, Length = 102)

	ip_udp = pack (ip, udp, "pouet pouet")

	ip_udp_tp = pack (
		IPv6 (HopLimit = 5),
		UDP (SourcePort = 1025, DestinationPort = 1025),
		"pouet pouet"
	)

	ip_udp_tp2 = IPv6 (HopLimit = 5) / UDP (SourcePort = 1025, DestinationPort = 1025) / "pouet pouett"

	ereq = pack (
		IPv6 (SourceAddress = "fe80::ec2a:5eff:fe02:3ec", DestinationAddress = "ff02::1", FlowLabel=0xff00f, TrafficClass=255),
		ICMPv6EchoRequest (Identifier = 0x3a23, SequenceNumber = 1),
		"\0\1\2\3"
	)

	assert ip_udp.flatten() in ip_udp_tp
	assert ip_udp.flatten() not in ip_udp_tp2

	assert Integer_0_to_10.__name__ == "Integer_0_to_10"
	assert ip.__name__ == "ip"
	assert ip2.__name__ == "ip2"
	assert ip_udp.__name__ == "ip_udp"
	assert ip_udp_tp.__name__ == "ip_udp_tp"
	assert ip_udp_tp2.__name__ == "ip_udp_tp2"
	assert IPv6Address.__name__ == "IPv6Address"

	assert ip2[1] == 54
	assert ip2[-8] == 54
	assert ip2["TrafficClass"] == 54

	assert IPv6.__name__ == "IPv6"
	assert IPv6.get_root_variant().__name__ == "IPv6"
	assert UDP.__name__ == "UDP"
	assert ICMPv6.__name__ == "ICMPv6"
	assert ICMPv6Echo.__name__ == "ICMPv6Echo"
	assert ICMPv6EchoRequest.__name__ == "ICMPv6EchoRequest"

	# TODO: some tests on ip_udp_tp & ip_udp

	#print Integer_0_to_10
	#print v1
	#print v2
	#print ip
	#print Range (int, 0, 3)
	#print ValueList (int, [0, 4, 7])
	#print ValueList (int, [0, 3])
	#print Length (str, 4)
	#print Length (str, (5, 8))
	#print Length (str, [3, (5, 8)])
	#print IPv6Message (HopLimit = 5)
	#print IPv6Message (HopLimit = 1)
	#print IPv6Message (HopLimit = 1) (HopLimit = 5)
	#
	UInt8 (54)


	#ip_udp.display()
	#print
	#display (IPv6 (HopLimit = 1) (HopLimit = 5))
	#print
	#display (ereq)

	#result = ip_udp_tp.build_message()

	result = ereq.flatten().build_message()

	result[0].display()
	print (" ".join ([format (v, "02x") for v in result[1]]))
	#TODO: make decode_message accepte bytes
	decoded_ereq = IPv6.decode_message (BinarySlice (result[1]))
	decoded_ereq[0].display()

	Ethernet.decode_message (BinarySlice (b'33\xff463Vu-463\x86\xdd`\x00\x00\x00\x00\x18:\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff463\x87\x00\x8e\xe3\x00\x00\x00\x00\xfe\x80\x00\x00\x00\x00\x00\x00Tu-\xff\xfe463'))[0].display()

	val, bin = pack(
		Ethernet (SourceAddress = "00:01:02:03:04:05"),
		IPv6 (SourceAddress = "fe80::42", HopLimit=255),
		ICMPv6NeighborAdvertisement (Flags = 0x6000, TargetAddress = "fe80::42",
		Options = [ICMPv6TLLOption (LinkLayerAddress = "00:01:02:03:04:05")]),
	).flatten().build_message()
	val.display()
	print (bin)

# idees
# template parametre
#
#def DHCP_Req (source):
#	return pack (
#		L2Hdr (src = source.L2),
#		IPv6 (src = source.IP),
#		UDP (sport = 547, dport = 546).
#		DHCPv6Request (opt = [DHCPv6ClientId (id = source.id)])
#	)
#
#
#link1.send (
#	DHCP_Req (source = TN1) (
#		ipv6_source = "blahblah",
#		dhcpv6_opt_add = id
#	),
#
#	DHCP_Req (source = TN1) ({	# crade
#		IPv6: {"source": blahblah},
#		DHCPv6: {"opt_add": id}
#	})
#)
#
"""
