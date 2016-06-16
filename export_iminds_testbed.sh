#!/usr/bin/env bash
git archive --format=tar --prefix=ttproto/ master | gzip >ttproto.tar.gz
scp -r -i /Users/fsismondi/F-Interop/20160500_fed4fire-CoAP-remote-PoC/iMindsTestBed.privateKey ttproto.tar.gz fsismond@193.190.127.249:/groups/wall2-ilabt-iminds-be/f-interop-coap/ttproto.tar.gz
