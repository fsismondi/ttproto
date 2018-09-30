TTProto ( Testing Tool Prototype)
-----------------------------------

ttproto is an experimental tool for implementing testing tools, for conformance and interoperability testing.
It was first implemented to explore new features and concepts for the TTCN-3 standard, but we also used it to implement a passive interoperability test suite we provided for the CoAP interoperability event held in Paris in March 2012.

ttproto is now being used for the purpose of developing testing tools (for interoperability and conformance testing) for the [f-interop european project](http://www.f-interop.eu/)
This tool is implemented in python3 and its design was influenced mainly by TTCN-3 (abstract model, templates, snapshots, behavior trees, communication ports, logging) and by Scapy (syntax, flexibility, customizability)
Its purpose is to facilitate rapid prototyping and experimentation (rather than production use). We chose to maximize its modularity and readability rather than performances and real-time considerations.

# Using TTProto from CLI

```
>>> python3 -m ttproto --help
usage: ttproto <command> [<args>]

TTProto CLI accepts the following commands:
    dissect         Dissects network traces (.pcap file).
    analyze         Analyses network traces (.pcap file).
    service_amqp    Launches TTProto as a HTTP service (WIP).
    service_http    Launches TTProto as an AMQP service.
```


Also, you can get help for each subcomand:

```
>>> python3 -m ttproto dissect --help
usage:  ttproto dissect file [<options>]

Dissection usage examples:
    dissect ./tests/test_dumps/6lowpan_hc/TD_6LOWPAN_HC_01.pcap
    dissect ./tests/test_dumps/6lowpan_hc/TD_6LOWPAN_HC_01.pcap -o /tmp/dissection.json
    dissect ./tests/test_dumps/6lowpan_hc/TD_6LOWPAN_HC_01.pcap -p sixlowpan
    dissect ./tests/test_dumps/6lowpan_hc/TD_6LOWPAN_HC_01.pcap -p icmpv6
    dissect ./tests/test_dumps/6lowpan_hc/TD_6LOWPAN_HC_01.pcap -p icmpv6echorequest
```

## Example:

```
python3 -m ttproto dissect ./tests/test_dumps/6lowpan_hc/TD_6LOWPAN_HC_01.pcap

INFO tat|ttproto_api [MainThread] Dissecting PCAP file ./tests/test_dumps/6lowpan_hc/TD_6LOWPAN_HC_01.pcap
INFO tat|ttproto_api [MainThread] PCAP dissected
INFO tat|main [MainThread] ###[ Ieee802154 ]###
  FrameType=                1 (Data Frame)
  SecurityEnabled=          0
  FramePending=             0
  AcknowlegeRequest=        1
  IntraPan=                 1
  Reserved=                 0
  DestinationAddressingMode= 3 (extended)
  FrameVersion=             0 (IEEE 802.15.4-2003)
  SourceAddressingMode=     3 (extended)
  SequenceNumber=           45
  DestinationPanId=         0xabcd
  DestinationAddress=       00:12:74:00:14:6e:f1:21
  SourcePanId=              (omit)
  SourceAddress=            00:12:74:00:14:65:d8:db
  Payload=
###[ SixLowpanIPHC ]###
    Dispatch=               0b011
    TF=                     0b11 (Elided)
    NH=                     0 (Inline)
    HLIM=                   0b10 (Compressed hop limit = 64)
    CID=                    0 (No additional context)
    SAC=                    0 (Stateless)
    SAM=                    0b01 (64 bits)
    M=                      0 (Not Multicast)
    DAC=                    0 (Stateless)
    DAM=                    0b11 (0 bits  (multicast: 8))
    SCI=                    (omit)
    DCI=                    (omit)
    InlineECN=              (omit)
    InlineDSCP=             (omit)
    InlineTFPad=            (omit)
    InlineFL=               (omit)
    InlineNH=               58
    InlineHLIM=             (omit)
    InlineSourceAddress=    76:00:14:ff:fe:65:d8:db
    InlineDestinationAddress= (omit)
    CompressedNextHeader=   (omit)
    Payload=
###[ IPv6 ]###
      Version=              6
      TrafficClass=         0x00
      FlowLabel=            0x00000
      PayloadLength=        64
      NextHeader=           58 (ICMP for IPv6)
      HopLimit=             64
      SourceAddress=        fe80::7600:14ff:fe65:d8db
      DestinationAddress=   fe80::212:7400:146e:f121
      Payload=
###[ ICMPv6EchoRequest ]###
        Type=               128 (Echo Request)
        Code=               0
        Checksum=           0x9f55
        Identifier=         0x5328
        SequenceNumber=     43
        Payload=
###[ BytesValue ]###
          Value=            b'\x99\xa1\xa0W\x00\x00\x00\x00\xaf*\n\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567'
  FCS=
Encoded as:
    61 cc 2d cd ab 21 f1 6e  14 00 74 12 00 db d8 65
    14 00 74 12 00 7a 13 3a  76 00 14 ff fe 65 d8 db
    80 00 9f 55 53 28 00 2b  99 a1 a0 57 00 00 00 00
    af 2a 0a 00 00 00 00 00  10 11 12 13 14 15 16 17
    18 19 1a 1b 1c 1d 1e 1f  20 21 22 23 24 25 26 27
    28 29 2a 2b 2c 2d 2e 2f  30 31 32 33 34 35 36 37

(...)
```

# Using TTProto core API

Here some examples on how to the TTproto API used for pcap analysis:

Using the ttproto console:
```
    python3 -i console.py
```

For running a dissection of a PCAP file:
```
    >>> capture = Capture('tests/test_dumps/coap_core/TD_COAP_CORE_01_PASS.pcap')
    >>> dissection = capture.get_dissection()
    >>> print(json.dumps(dissection, indent=4))

    [
        {
            "_type": "frame",
            "id": 1,
            "timestamp": 1464858393.547275,
            "error": null,
            "protocol_stack": [
                {
                    "_type": "protocol",
                    "_protocol": "NullLoopback",
                    "AddressFamily": "2",
                    "ProtocolFamily": "0"
                },
                {
                    "_type": "protocol",
                    "_protocol": "IPv4",
                    "Version": "4",
                    (...)
                    "SourceAddress": "127.0.0.1",
                    "DestinationAddress": "127.0.0.1",
                    "Options": "b''"
                },
                {
                    (...)
                },
                {
                    "_type": "protocol",
                    "_protocol": "CoAP",
                    "Version": "1",
                    "Type": "0",
                    "TokenLength": "2",
                    "Code": "1",
                    "MessageID": "0xaa01",
                    "Token": "b'b\\xda'",
                    "Options": [
                        {
                            "Option": "CoAPOptionUriPath",
                            "Delta": "11",
                            "Length": "4",
                            "Value": "test"
                        },
                        {
                            "Option": "CoAPOptionBlock2",
                            "Delta": "12",
                            "Length": "1",
                            "Number": "0",
                            "M": "0",
                            "SizeExponent": "2"
                        }
                    ],
                    "Payload": "b''"
                }
            ]
        },
        {
            (...)
        }
    ]
```

For running an analysis of a PCAP, interop testcase post-mortem analysis, for (e.g) TD_COAP_CORE_01:

```
    >>> analyzer = Analyzer('tat_coap')
    >>> analysis_result = analyzer.analyse('tests/test_dumps/coap_core/TD_COAP_CORE_01_PASS.pcap','TD_COAP_CORE_01')
    >>> print(json.dumps(analysis_result, indent=4))
    [
        "TD_COAP_CORE_01",
        "pass",
        [],
        "<Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON 43521] GET /test>\n  [ pass ] <Frame   1: (...)",
        [
            [
                "pass",
                "<Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON 43521] GET /test> Match: CoAP(type=0, code=1)"
            ],
            [
                "pass",
                "<Frame   1: [127.0.0.1 -> 127.0.0.1] CoAP [CON 43521] GET /test> Match: CoAP(type=0, code=1)"
            ],
            [
                "pass",
                "<Frame   2: [127.0.0.1 -> 127.0.0.1] CoAP [ACK 43521] 2.05 Content > Match: CoAP(code=69, mid=0xaa01, tok=b'b\\xda', pl=Not(b''))"
            ],
            [
                "pass",
                "<Frame   2: [127.0.0.1 -> 127.0.0.1] CoAP [ACK 43521] 2.05 Content > Match: CoAP(opt=Opt(CoAPOptionContentFormat()))"
            ]
        ],
        []
    ]
```

# see more

- on the detailed feature set of the library check: [ttproto features](https://www.irisa.fr/tipi/wiki/doku.php/testing_tool_prototype:features)
- on how to write a testcase for CoAP or any other protocol see [CONTRIBUTING.rst document](https://gitlab.f-interop.eu/fsismondi/ttproto/blob/master/CONTRIBUTING.rst)
- on the source code [gitlab repo](https://gitlab.f-interop.eu/fsismondi/ttproto)


# The git repository contains the following testing tools:

## TAT_COAP - Test Analysis Tool

Passive test analysis tool for testing CoAP interoperability between 2 IUTs.
It uses the generic TAT structure (interfaces to extend in a simple way the tool to other protocols).

### HTTP based interface

The HTTP API consists of HTTP RPC-style methods:

- GET /api/v1/analyzer_getTestCases
- GET /api/v1/analyzer_getTestcaseImplementation
- POST /api/v1/analyzer_testCaseAnalyze
- GET /api/v1/analyzer_getFrames
- POST /api/v1/dissector_dissectFile (TOKEN must be provided)
- GET  /api/v1/dissector_getFrames (TOKEN must be provided)
- GET /api/v1/dissector_getFramesSummary

for details/params refer to the tat_coap/webserver.py file

### AMQP interface

TAT_COAP also implements an AMQP interface. See doc for API endpoints and configuration of AMQP connection.

## TS_COAP - Analysis a posteriori PCAP analyser (stable)
Passive test analysis tool for testing interoperability between 2 IUTs. This tool provides just one feature which is analysing network camptures, which can be accesses though a python based webserver.

### HTTP based interface
run CoAP TAT as a webserver at [127.0.0.1:2080](127.0.0.1:2080)
```
cd ttproto
python3 -m ttproto.ts_coap
```
open web-browser at 127.0.0.1:2080 and upload your PCAP file to be analyzed!

## TS_6LoWPAN_ND - Conformance Testing Tool (WIP)
Conformance testing tool for testing 6LoWPAN ND


# Running unit tests

python3 -m pytest tests/  --ignore=tests/test_webserver/tests.py  --ignore=tests/test_tat/test_webserver.py
