Testing Tool Prototype
======================
ttproto is an experimental tool for implementing testing tools, for conformance and interoperability testing.

It was first implemented to explore new features and concepts for the TTCN-3 standard, but we also used it to implement a passive interoperability test suite we provided for the CoAP interoperability event held in Paris in March 2012.

ttproto is now being used for the purpose of developping testing tools (for interoperability and conformance testing) for the [f-interop european project](http://www.f-interop.eu/)

This tool is implemented in python3 and its design was influenced mainly by TTCN-3 (abstract model, templates, snapshots, behaviour trees, communication ports, logging) and by Scapy (syntax, flexibility, customisability)

Its purpose is to facilitate rapid prototyping rather than experimentations (rather than production use). We choosed to maximise its modularity and readability rather than performances and real-time considerations.


The git repository contains the following testing tools:
--------------------------------------------------------

TS_COAP - Test Analysis Tool
----------------------------
Test analysis tool for testing interoperability between 2 IUTs

# run CoAP TAT as a webserver at [127.0.0.1:2080](127.0.0.1:2080)
cd ttproto
python3 -m ttproto.ts_coap

# TODO how to use REST API for finterop

TS_6LoWPAN_ND - Conformance Testing Tool
----------------------------
Conformance testing tool for testing 6LoWPAN ND

# TODO write down steps for executing a tests
