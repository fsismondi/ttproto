# TTProto ( Testing Tool Prototype)
-------------------------

ttproto is an experimental tool for implementing testing tools, for conformance and interoperability testing.
It was first implemented to explore new features and concepts for the TTCN-3 standard, but we also used it to implement a passive interoperability test suite we provided for the CoAP interoperability event held in Paris in March 2012.
ttproto is now being used for the purpose of developing testing tools (for interoperability and conformance testing) for the [f-interop european project](http://www.f-interop.eu/)
This tool is implemented in python3 and its design was influenced mainly by TTCN-3 (abstract model, templates, snapshots, behavior trees, communication ports, logging) and by Scapy (syntax, flexibility, customizability)
Its purpose is to facilitate rapid prototyping and experimentation (rather than production use). We chose to maximize its modularity and readability rather than performances and real-time considerations.

# The git repository contains the following testing tools:
-----------------------------------

## TAT_COAP - Test Analysis Tool

Passive test analysis tool for testing CoAP interoperability between 2 IUTs.
It uses the generic TAT structure (interfaces to extend in a simple way the tool to other protocols).

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

TAT_COAP also implements an AMQP interface. See tat_coap/amqp_interface.py for API endpoints and configuration of AMQP connection.

## TS_COAP - Analysis a posteriori PCAP analyser (stable)
Passive test analysis tool for testing interoperability between 2 IUTs. This tool provides just one feature which is analysing network camptures, which can be accesses though a python based webserver.

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
