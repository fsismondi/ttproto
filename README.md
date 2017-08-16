# TTProto ( Testing Tool Prototype)
-------------------------

ttproto is an experimental tool for implementing testing tools, for conformance and interoperability testing.
It was first implemented to explore new features and concepts for the TTCN-3 standard, but we also used it to implement a passive interoperability test suite we provided for the CoAP interoperability event held in Paris in March 2012.
ttproto is now being used for the purpose of developing testing tools (for interoperability and conformance testing) for the [f-interop european project](http://www.f-interop.eu/)
This tool is implemented in python3 and its design was influenced mainly by TTCN-3 (abstract model, templates, snapshots, behavior trees, communication ports, logging) and by Scapy (syntax, flexibility, customizability)
Its purpose is to facilitate rapid prototyping and experimentation (rather than production use). We chose to maximize its modularity and readability rather than performances and real-time considerations.

# Examples of use of TTProto core API
-------------------------------------
Here some examples on how to the TTproto API used for pcap analysis:

Using the ttproto console:
```
    python3 -i console.py
```

For running a dissection of a PCAP file:
```
    >>> dis = Dissector('tests/test_dumps/analysis/coap_core/TD_COAP_CORE_01_PASS.pcap')
    >>> dissection = dis.dissect()
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
'''

For running an analysis of a PCAP (interop testcase post-mortem analysis):

'''
    >>> analyzer = Analyzer('tat_coap')
    >>> analysis_result = analyzer.analyse('tests/test_dumps/analysis/coap_core/TD_COAP_CORE_01_PASS.pcap','TD_COAP_CORE_01')
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
'''

# The git repository contains the following testing tools:
----------------------------------------------------------

## TAT_COAP - Test Analysis Tool

Passive test analysis tool for testing CoAP interoperability between 2 IUTs.
It uses the generic TAT structure (interfaces to extend in a simple way the tool to other protocols).

### HTTP based interface

run CoAP TAT as a webserver at [127.0.0.1:2080](127.0.0.1:2080).
```
cd ttproto
python3 -m ttproto.tat_coap
```

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

TAT_COAP also implements an AMQP interface. See tat_coap/amqp_interface.py for API endpoints and configuration of AMQP connection.

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


# Running tests

python3 -m pytest tests/  --ignore=tests/test_webserver/tests.py  --ignore=tests/test_tat_coap/test_webserver.py
