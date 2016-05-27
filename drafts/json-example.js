// ############### JSON examples for testes ###############
var data = [
	[
		{
			".type": "frame",
			".id": 1,
			".timestamp": 1451916263.048185,
			".error": null
		},
		{
			".type": "Ethernet",
			"DestinationAddress": "10:bd:18:e4:ea:80",
			"SourceAddress": "ac:bc:32:cd:f3:8b",
			"Type": "0x0800",
			"Trailer": "b''"
		},
		{
			".type": "IPv4",
			"Version": "4",
			"HeaderLength": "5",
			"TypeOfService": "0x00",
			"TotalLength": "47",
			"Identification": "0x84ff",
			"Reserved": "0",
			"DontFragment": "0",
			"MoreFragments": "0",
			"FragmentOffset": "0",
			"TimeToLive": "64",
			"Protocol": "17",
			"HeaderChecksum": "0x9f9f",
			"SourceAddress": "131.254.65.77",
			"DestinationAddress": "129.132.15.80",
			"Options": "b''"
		},
		{
			".type": "UDP",
			"SourcePort": "55546",
			"DestinationPort": "5683",
			"Length": "27",
			"Checksum": "0xbbd2"
		},
		{
			".type": "CoAP",
			"Version": "1",
			"Type": "1",
			"TokenLength": "2",
			"Code": "1",
			"MessageID": "0xc048",
			"Token": "b'b\\xda'",
			"Payload": "b''"
		},
		{
			".type": "CoAPOptionObserve",
			"Delta": "6",
			"Length": "0",
			"Value": "0"
		},
		{
			".type": "CoAPOptionUriPath",
			"Delta": "5",
			"Length": "9",
			"Value": "obs-large"
		},
		{
			".type": "CoAPOptionBlock2",
			"Delta": "12",
			"Length": "1",
			"Number": "0",
			"M": "0",
			"SizeExponent": "2"
		}
	],
	[
		{
			".type": "frame",
			".id": 2,
			".timestamp": 1451916263.069451,
			".error": null
		},
		{
			".type": "Ethernet",
			"DestinationAddress": "ac:bc:32:cd:f3:8b",
			"SourceAddress": "10:bd:18:e4:ea:80",
			"Type": "0x0800",
			"Trailer": "b''"
		},
		{
			".type": "IPv4",
			"Version": "4",
			"HeaderLength": "5",
			"TypeOfService": "0x00",
			"TotalLength": "104",
			"Identification": "0x0000",
			"Reserved": "0",
			"DontFragment": "1",
			"MoreFragments": "0",
			"FragmentOffset": "0",
			"TimeToLive": "50",
			"Protocol": "17",
			"HeaderChecksum": "0xf265",
			"SourceAddress": "129.132.15.80",
			"DestinationAddress": "131.254.65.77",
			"Options": "b''"
		},
		{
			".type": "UDP",
			"SourcePort": "5683",
			"DestinationPort": "55546",
			"Length": "84",
			"Checksum": "0xe057"
		},
		{
			".type": "CoAP",
			"Version": "1",
			"Type": "1",
			"TokenLength": "2",
			"Code": "69",
			"MessageID": "0xae29",
			"Token": "b'b\\xda'",
			"Payload": "b'----------------------------------------------------------------'"
		},
		{
			".type": "CoAPOptionContentFormat",
			"Delta": "12",
			"Length": "0",
			"Value": "0"
		},
		{
			".type": "CoAPOptionMaxAge",
			"Delta": "2",
			"Length": "1",
			"Value": "5"
		},
		{
			".type": "CoAPOptionBlock2",
			"Delta": "9",
			"Length": "1",
			"Number": "0",
			"M": "1",
			"SizeExponent": "2"
		}
	],
	[
		{
			".type": "frame",
			".id": 3,
			".timestamp": 1451916269.460468,
			".error": null
		},
		{
			".type": "Ethernet",
			"DestinationAddress": "10:bd:18:e4:ea:80",
			"SourceAddress": "ac:bc:32:cd:f3:8b",
			"Type": "0x0800",
			"Trailer": "b''"
		},
		{
			".type": "IPv4",
			"Version": "4",
			"HeaderLength": "5",
			"TypeOfService": "0x00",
			"TotalLength": "47",
			"Identification": "0xbf89",
			"Reserved": "0",
			"DontFragment": "0",
			"MoreFragments": "0",
			"FragmentOffset": "0",
			"TimeToLive": "64",
			"Protocol": "17",
			"HeaderChecksum": "0x6515",
			"SourceAddress": "131.254.65.77",
			"DestinationAddress": "129.132.15.80",
			"Options": "b''"
		},
		{
			".type": "UDP",
			"SourcePort": "56412",
			"DestinationPort": "5683",
			"Length": "27",
			"Checksum": "0xab59"
		},
		{
			".type": "CoAP",
			"Version": "1",
			"Type": "1",
			"TokenLength": "2",
			"Code": "1",
			"MessageID": "0xcd5f",
			"Token": "b'b\\xda'",
			"Payload": "b''"
		},
		{
			".type": "CoAPOptionObserve",
			"Delta": "6",
			"Length": "0",
			"Value": "0"
		},
		{
			".type": "CoAPOptionUriPath",
			"Delta": "5",
			"Length": "9",
			"Value": "obs-large"
		},
		{
			".type": "CoAPOptionBlock2",
			"Delta": "12",
			"Length": "1",
			"Number": "0",
			"M": "0",
			"SizeExponent": "2"
		}
	],
	[
		{
			".type": "frame",
			".id": 4,
			".timestamp": 1451916269.484576,
			".error": null
		},
		{
			".type": "Ethernet",
			"DestinationAddress": "ac:bc:32:cd:f3:8b",
			"SourceAddress": "10:bd:18:e4:ea:80",
			"Type": "0x0800",
			"Trailer": "b''"
		},
		{
			".type": "IPv4",
			"Version": "4",
			"HeaderLength": "5",
			"TypeOfService": "0x00",
			"TotalLength": "108",
			"Identification": "0x0000",
			"Reserved": "0",
			"DontFragment": "1",
			"MoreFragments": "0",
			"FragmentOffset": "0",
			"TimeToLive": "50",
			"Protocol": "17",
			"HeaderChecksum": "0xf261",
			"SourceAddress": "129.132.15.80",
			"DestinationAddress": "131.254.65.77",
			"Options": "b''"
		},
		{
			".type": "UDP",
			"SourcePort": "5683",
			"DestinationPort": "56412",
			"Length": "88",
			"Checksum": "0xdb6a"
		},
		{
			".type": "CoAP",
			"Version": "1",
			"Type": "1",
			"TokenLength": "2",
			"Code": "69",
			"MessageID": "0xae2a",
			"Token": "b'b\\xda'",
			"Payload": "b'----------------------------------------------------------------'"
		},
		{
			".type": "CoAPOptionObserve",
			"Delta": "6",
			"Length": "3",
			"Value": "1572458"
		},
		{
			".type": "CoAPOptionContentFormat",
			"Delta": "6",
			"Length": "0",
			"Value": "0"
		},
		{
			".type": "CoAPOptionMaxAge",
			"Delta": "2",
			"Length": "1",
			"Value": "5"
		},
		{
			".type": "CoAPOptionBlock2",
			"Delta": "9",
			"Length": "1",
			"Number": "0",
			"M": "1",
			"SizeExponent": "2"
		}
	],
	[
		{
			".type": "frame",
			".id": 5,
			".timestamp": 1451916269.492087,
			".error": null
		},
		{
			".type": "Ethernet",
			"DestinationAddress": "10:bd:18:e4:ea:80",
			"SourceAddress": "ac:bc:32:cd:f3:8b",
			"Type": "0x0800",
			"Trailer": "b''"
		},
		{
			".type": "IPv4",
			"Version": "4",
			"HeaderLength": "5",
			"TypeOfService": "0x00",
			"TotalLength": "46",
			"Identification": "0x1f51",
			"Reserved": "0",
			"DontFragment": "0",
			"MoreFragments": "0",
			"FragmentOffset": "0",
			"TimeToLive": "64",
			"Protocol": "17",
			"HeaderChecksum": "0x054f",
			"SourceAddress": "131.254.65.77",
			"DestinationAddress": "129.132.15.80",
			"Options": "b''"
		},
		{
			".type": "UDP",
			"SourcePort": "56412",
			"DestinationPort": "5683",
			"Length": "26",
			"Checksum": "0x6194"
		},
		{
			".type": "CoAP",
			"Version": "1",
			"Type": "1",
			"TokenLength": "2",
			"Code": "1",
			"MessageID": "0xcd60",
			"Token": "b'b\\xda'",
			"Payload": "b''"
		},
		{
			".type": "CoAPOptionUriPath",
			"Delta": "11",
			"Length": "9",
			"Value": "obs-large"
		},
		{
			".type": "CoAPOptionBlock2",
			"Delta": "12",
			"Length": "1",
			"Number": "1",
			"M": "0",
			"SizeExponent": "2"
		}
	],
	[
		{
			".type": "frame",
			".id": 6,
			".timestamp": 1451916269.512997,
			".error": null
		},
		{
			".type": "Ethernet",
			"DestinationAddress": "ac:bc:32:cd:f3:8b",
			"SourceAddress": "10:bd:18:e4:ea:80",
			"Type": "0x0800",
			"Trailer": "b''"
		},
		{
			".type": "IPv4",
			"Version": "4",
			"HeaderLength": "5",
			"TypeOfService": "0x00",
			"TotalLength": "104",
			"Identification": "0x0000",
			"Reserved": "0",
			"DontFragment": "1",
			"MoreFragments": "0",
			"FragmentOffset": "0",
			"TimeToLive": "50",
			"Protocol": "17",
			"HeaderChecksum": "0xf265",
			"SourceAddress": "129.132.15.80",
			"DestinationAddress": "131.254.65.77",
			"Options": "b''"
		},
		{
			".type": "UDP",
			"SourcePort": "5683",
			"DestinationPort": "56412",
			"Length": "84",
			"Checksum": "0x6a96"
		},
		{
			".type": "CoAP",
			"Version": "1",
			"Type": "1",
			"TokenLength": "2",
			"Code": "69",
			"MessageID": "0xae2b",
			"Token": "b'b\\xda'",
			"Payload": "b'\\n15:04:27												\\n------------------------------'"
		},
		{
			".type": "CoAPOptionContentFormat",
			"Delta": "12",
			"Length": "0",
			"Value": "0"
		},
		{
			".type": "CoAPOptionMaxAge",
			"Delta": "2",
			"Length": "1",
			"Value": "5"
		},
		{
			".type": "CoAPOptionBlock2",
			"Delta": "9",
			"Length": "1",
			"Number": "1",
			"M": "1",
			"SizeExponent": "2"
		}
	],
	[
		{
			".type": "frame",
			".id": 7,
			".timestamp": 1451916273.544183,
			".error": null
		},
		{
			".type": "Ethernet",
			"DestinationAddress": "ac:bc:32:cd:f3:8b",
			"SourceAddress": "10:bd:18:e4:ea:80",
			"Type": "0x0800",
			"Trailer": "b''"
		},
		{
			".type": "IPv4",
			"Version": "4",
			"HeaderLength": "5",
			"TypeOfService": "0x00",
			"TotalLength": "108",
			"Identification": "0x0000",
			"Reserved": "0",
			"DontFragment": "1",
			"MoreFragments": "0",
			"FragmentOffset": "0",
			"TimeToLive": "50",
			"Protocol": "17",
			"HeaderChecksum": "0xf261",
			"SourceAddress": "129.132.15.80",
			"DestinationAddress": "131.254.65.77",
			"Options": "b''"
		},
		{
			".type": "UDP",
			"SourcePort": "5683",
			"DestinationPort": "56412",
			"Length": "88",
			"Checksum": "0xeb67"
		},
		{
			".type": "CoAP",
			"Version": "1",
			"Type": "0",
			"TokenLength": "2",
			"Code": "69",
			"MessageID": "0xae2c",
			"Token": "b'b\\xda'",
			"Payload": "b'----------------------------------------------------------------'"
		},
		{
			".type": "CoAPOptionObserve",
			"Delta": "6",
			"Length": "3",
			"Value": "1572459"
		},
		{
			".type": "CoAPOptionContentFormat",
			"Delta": "6",
			"Length": "0",
			"Value": "0"
		},
		{
			".type": "CoAPOptionMaxAge",
			"Delta": "2",
			"Length": "1",
			"Value": "5"
		},
		{
			".type": "CoAPOptionBlock2",
			"Delta": "9",
			"Length": "1",
			"Number": "0",
			"M": "1",
			"SizeExponent": "2"
		}
	],
	[
		{
			".type": "frame",
			".id": 8,
			".timestamp": 1451916273.546963,
			".error": null
		},
		{
			".type": "Ethernet",
			"DestinationAddress": "10:bd:18:e4:ea:80",
			"SourceAddress": "ac:bc:32:cd:f3:8b",
			"Type": "0x0800",
			"Trailer": "b''"
		},
		{
			".type": "IPv4",
			"Version": "4",
			"HeaderLength": "5",
			"TypeOfService": "0x00",
			"TotalLength": "32",
			"Identification": "0x30f8",
			"Reserved": "0",
			"DontFragment": "0",
			"MoreFragments": "0",
			"FragmentOffset": "0",
			"TimeToLive": "64",
			"Protocol": "17",
			"HeaderChecksum": "0xf3b5",
			"SourceAddress": "131.254.65.77",
			"DestinationAddress": "129.132.15.80",
			"Options": "b''"
		},
		{
			".type": "UDP",
			"SourcePort": "56412",
			"DestinationPort": "5683",
			"Length": "12",
			"Checksum": "0xa8f9"
		},
		{
			".type": "CoAP",
			"Version": "1",
			"Type": "2",
			"TokenLength": "0",
			"Code": "0",
			"MessageID": "0xae2c",
			"Token": "b''",
			"Payload": "b''"
		}
	],
	[
		{
			".type": "frame",
			".id": 9,
			".timestamp": 1451916273.577881,
			".error": null
		},
		{
			".type": "Ethernet",
			"DestinationAddress": "10:bd:18:e4:ea:80",
			"SourceAddress": "ac:bc:32:cd:f3:8b",
			"Type": "0x0800",
			"Trailer": "b''"
		},
		{
			".type": "IPv4",
			"Version": "4",
			"HeaderLength": "5",
			"TypeOfService": "0x00",
			"TotalLength": "46",
			"Identification": "0xf262",
			"Reserved": "0",
			"DontFragment": "0",
			"MoreFragments": "0",
			"FragmentOffset": "0",
			"TimeToLive": "64",
			"Protocol": "17",
			"HeaderChecksum": "0x323d",
			"SourceAddress": "131.254.65.77",
			"DestinationAddress": "129.132.15.80",
			"Options": "b''"
		},
		{
			".type": "UDP",
			"SourcePort": "56412",
			"DestinationPort": "5683",
			"Length": "26",
			"Checksum": "0x6193"
		},
		{
			".type": "CoAP",
			"Version": "1",
			"Type": "1",
			"TokenLength": "2",
			"Code": "1",
			"MessageID": "0xcd61",
			"Token": "b'b\\xda'",
			"Payload": "b''"
		},
		{
			".type": "CoAPOptionUriPath",
			"Delta": "11",
			"Length": "9",
			"Value": "obs-large"
		},
		{
			".type": "CoAPOptionBlock2",
			"Delta": "12",
			"Length": "1",
			"Number": "1",
			"M": "0",
			"SizeExponent": "2"
		}
	],
	[
		{
			".type": "frame",
			".id": 10,
			".timestamp": 1451916273.5992,
			".error": null
		},
		{
			".type": "Ethernet",
			"DestinationAddress": "ac:bc:32:cd:f3:8b",
			"SourceAddress": "10:bd:18:e4:ea:80",
			"Type": "0x0800",
			"Trailer": "b''"
		},
		{
			".type": "IPv4",
			"Version": "4",
			"HeaderLength": "5",
			"TypeOfService": "0x00",
			"TotalLength": "104",
			"Identification": "0x0000",
			"Reserved": "0",
			"DontFragment": "1",
			"MoreFragments": "0",
			"FragmentOffset": "0",
			"TimeToLive": "50",
			"Protocol": "17",
			"HeaderChecksum": "0xf265",
			"SourceAddress": "129.132.15.80",
			"DestinationAddress": "131.254.65.77",
			"Options": "b''"
		},
		{
			".type": "UDP",
			"SourcePort": "5683",
			"DestinationPort": "56412",
			"Length": "84",
			"Checksum": "0x6f93"
		},
		{
			".type": "CoAP",
			"Version": "1",
			"Type": "1",
			"TokenLength": "2",
			"Code": "69",
			"MessageID": "0xae2d",
			"Token": "b'b\\xda'",
			"Payload": "b'\\n15:04:32												\\n------------------------------'"
		},
		{
			".type": "CoAPOptionContentFormat",
			"Delta": "12",
			"Length": "0",
			"Value": "0"
		},
		{
			".type": "CoAPOptionMaxAge",
			"Delta": "2",
			"Length": "1",
			"Value": "5"
		},
		{
			".type": "CoAPOptionBlock2",
			"Delta": "9",
			"Length": "1",
			"Number": "1",
			"M": "1",
			"SizeExponent": "2"
		}
	],
	[
		{
			".type": "frame",
			".id": 11,
			".timestamp": 1451916278.562071,
			".error": null
		},
		{
			".type": "Ethernet",
			"DestinationAddress": "ac:bc:32:cd:f3:8b",
			"SourceAddress": "10:bd:18:e4:ea:80",
			"Type": "0x0800",
			"Trailer": "b''"
		},
		{
			".type": "IPv4",
			"Version": "4",
			"HeaderLength": "5",
			"TypeOfService": "0x00",
			"TotalLength": "108",
			"Identification": "0x0000",
			"Reserved": "0",
			"DontFragment": "1",
			"MoreFragments": "0",
			"FragmentOffset": "0",
			"TimeToLive": "50",
			"Protocol": "17",
			"HeaderChecksum": "0xf261",
			"SourceAddress": "129.132.15.80",
			"DestinationAddress": "131.254.65.77",
			"Options": "b''"
		},
		{
			".type": "UDP",
			"SourcePort": "5683",
			"DestinationPort": "56412",
			"Length": "88",
			"Checksum": "0xeb64"
		},
		{
			".type": "CoAP",
			"Version": "1",
			"Type": "0",
			"TokenLength": "2",
			"Code": "69",
			"MessageID": "0xae2e",
			"Token": "b'b\\xda'",
			"Payload": "b'----------------------------------------------------------------'"
		},
		{
			".type": "CoAPOptionObserve",
			"Delta": "6",
			"Length": "3",
			"Value": "1572460"
		},
		{
			".type": "CoAPOptionContentFormat",
			"Delta": "6",
			"Length": "0",
			"Value": "0"
		},
		{
			".type": "CoAPOptionMaxAge",
			"Delta": "2",
			"Length": "1",
			"Value": "5"
		},
		{
			".type": "CoAPOptionBlock2",
			"Delta": "9",
			"Length": "1",
			"Number": "0",
			"M": "1",
			"SizeExponent": "2"
		}
	],
	[
		{
			".type": "frame",
			".id": 12,
			".timestamp": 1451916278.566861,
			".error": null
		},
		{
			".type": "Ethernet",
			"DestinationAddress": "10:bd:18:e4:ea:80",
			"SourceAddress": "ac:bc:32:cd:f3:8b",
			"Type": "0x0800",
			"Trailer": "b''"
		},
		{
			".type": "IPv4",
			"Version": "4",
			"HeaderLength": "5",
			"TypeOfService": "0x00",
			"TotalLength": "32",
			"Identification": "0xe93b",
			"Reserved": "0",
			"DontFragment": "0",
			"MoreFragments": "0",
			"FragmentOffset": "0",
			"TimeToLive": "64",
			"Protocol": "17",
			"HeaderChecksum": "0x3b72",
			"SourceAddress": "131.254.65.77",
			"DestinationAddress": "129.132.15.80",
			"Options": "b''"
		},
		{
			".type": "UDP",
			"SourcePort": "56412",
			"DestinationPort": "5683",
			"Length": "12",
			"Checksum": "0xa8f7"
		},
		{
			".type": "CoAP",
			"Version": "1",
			"Type": "2",
			"TokenLength": "0",
			"Code": "0",
			"MessageID": "0xae2e",
			"Token": "b''",
			"Payload": "b''"
		}
	],
	[
		{
			".type": "frame",
			".id": 13,
			".timestamp": 1451916278.597632,
			".error": null
		},
		{
			".type": "Ethernet",
			"DestinationAddress": "10:bd:18:e4:ea:80",
			"SourceAddress": "ac:bc:32:cd:f3:8b",
			"Type": "0x0800",
			"Trailer": "b''"
		},
		{
			".type": "IPv4",
			"Version": "4",
			"HeaderLength": "5",
			"TypeOfService": "0x00",
			"TotalLength": "46",
			"Identification": "0xb4f6",
			"Reserved": "0",
			"DontFragment": "0",
			"MoreFragments": "0",
			"FragmentOffset": "0",
			"TimeToLive": "64",
			"Protocol": "17",
			"HeaderChecksum": "0x6fa9",
			"SourceAddress": "131.254.65.77",
			"DestinationAddress": "129.132.15.80",
			"Options": "b''"
		},
		{
			".type": "UDP",
			"SourcePort": "56412",
			"DestinationPort": "5683",
			"Length": "26",
			"Checksum": "0x6192"
		},
		{
			".type": "CoAP",
			"Version": "1",
			"Type": "1",
			"TokenLength": "2",
			"Code": "1",
			"MessageID": "0xcd62",
			"Token": "b'b\\xda'",
			"Payload": "b''"
		},
		{
			".type": "CoAPOptionUriPath",
			"Delta": "11",
			"Length": "9",
			"Value": "obs-large"
		},
		{
			".type": "CoAPOptionBlock2",
			"Delta": "12",
			"Length": "1",
			"Number": "1",
			"M": "0",
			"SizeExponent": "2"
		}
	],
	[
		{
			".type": "frame",
			".id": 14,
			".timestamp": 1451916278.618835,
			".error": null
		},
		{
			".type": "Ethernet",
			"DestinationAddress": "ac:bc:32:cd:f3:8b",
			"SourceAddress": "10:bd:18:e4:ea:80",
			"Type": "0x0800",
			"Trailer": "b''"
		},
		{
			".type": "IPv4",
			"Version": "4",
			"HeaderLength": "5",
			"TypeOfService": "0x00",
			"TotalLength": "104",
			"Identification": "0x0000",
			"Reserved": "0",
			"DontFragment": "1",
			"MoreFragments": "0",
			"FragmentOffset": "0",
			"TimeToLive": "50",
			"Protocol": "17",
			"HeaderChecksum": "0xf265",
			"SourceAddress": "129.132.15.80",
			"DestinationAddress": "131.254.65.77",
			"Options": "b''"
		},
		{
			".type": "UDP",
			"SourcePort": "5683",
			"DestinationPort": "56412",
			"Length": "84",
			"Checksum": "0x6a91"
		},
		{
			".type": "CoAP",
			"Version": "1",
			"Type": "1",
			"TokenLength": "2",
			"Code": "69",
			"MessageID": "0xae2f",
			"Token": "b'b\\xda'",
			"Payload": "b'\\n15:04:37												\\n------------------------------'"
		},
		{
			".type": "CoAPOptionContentFormat",
			"Delta": "12",
			"Length": "0",
			"Value": "0"
		},
		{
			".type": "CoAPOptionMaxAge",
			"Delta": "2",
			"Length": "1",
			"Value": "5"
		},
		{
			".type": "CoAPOptionBlock2",
			"Delta": "9",
			"Length": "1",
			"Number": "1",
			"M": "1",
			"SizeExponent": "2"
		}
	],
	[
		{
			".type": "frame",
			".id": 15,
			".timestamp": 1451916281.957667,
			".error": null
		},
		{
			".type": "Ethernet",
			"DestinationAddress": "10:bd:18:e4:ea:80",
			"SourceAddress": "ac:bc:32:cd:f3:8b",
			"Type": "0x0800",
			"Trailer": "b''"
		},
		{
			".type": "IPv4",
			"Version": "4",
			"HeaderLength": "5",
			"TypeOfService": "0x00",
			"TotalLength": "46",
			"Identification": "0x523f",
			"Reserved": "0",
			"DontFragment": "0",
			"MoreFragments": "0",
			"FragmentOffset": "0",
			"TimeToLive": "64",
			"Protocol": "17",
			"HeaderChecksum": "0xd260",
			"SourceAddress": "131.254.65.77",
			"DestinationAddress": "129.132.15.80",
			"Options": "b''"
		},
		{
			".type": "UDP",
			"SourcePort": "56412",
			"DestinationPort": "5683",
			"Length": "26",
			"Checksum": "0x31a3"
		},
		{
			".type": "CoAP",
			"Version": "1",
			"Type": "0",
			"TokenLength": "2",
			"Code": "1",
			"MessageID": "0xcd63",
			"Token": "b'b\\xda'",
			"Payload": "b''"
		},
		{
			".type": "CoAPOptionObserve",
			"Delta": "6",
			"Length": "1",
			"Value": "1"
		},
		{
			".type": "CoAPOptionUriPath",
			"Delta": "5",
			"Length": "9",
			"Value": "obs-large"
		}
	],
	[
		{
			".type": "frame",
			".id": 16,
			".timestamp": 1451916281.981763,
			".error": null
		},
		{
			".type": "Ethernet",
			"DestinationAddress": "ac:bc:32:cd:f3:8b",
			"SourceAddress": "10:bd:18:e4:ea:80",
			"Type": "0x0800",
			"Trailer": "b''"
		},
		{
			".type": "IPv4",
			"Version": "4",
			"HeaderLength": "5",
			"TypeOfService": "0x00",
			"TotalLength": "104",
			"Identification": "0x0000",
			"Reserved": "0",
			"DontFragment": "1",
			"MoreFragments": "0",
			"FragmentOffset": "0",
			"TimeToLive": "50",
			"Protocol": "17",
			"HeaderChecksum": "0xf265",
			"SourceAddress": "129.132.15.80",
			"DestinationAddress": "131.254.65.77",
			"Options": "b''"
		},
		{
			".type": "UDP",
			"SourcePort": "5683",
			"DestinationPort": "56412",
			"Length": "84",
			"Checksum": "0xadbb"
		},
		{
			".type": "CoAP",
			"Version": "1",
			"Type": "2",
			"TokenLength": "2",
			"Code": "69",
			"MessageID": "0xcd63",
			"Token": "b'b\\xda'",
			"Payload": "b'----------------------------------------------------------------'"
		},
		{
			".type": "CoAPOptionContentFormat",
			"Delta": "12",
			"Length": "0",
			"Value": "0"
		},
		{
			".type": "CoAPOptionMaxAge",
			"Delta": "2",
			"Length": "1",
			"Value": "5"
		},
		{
			".type": "CoAPOptionBlock2",
			"Delta": "9",
			"Length": "1",
			"Number": "0",
			"M": "1",
			"SizeExponent": "2"
		}
	]
];