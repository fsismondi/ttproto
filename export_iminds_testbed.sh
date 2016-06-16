#!/usr/bin/env bash
PROJ=$(basename `git rev-parse --show-toplevel`)
git archive --format=tar --prefix="$PROJ/" master | gzip >"$PROJ.tar.gz"
scp -r -i /Users/fsismondi/F-Interop/20160500_fed4fire-CoAP-remote-PoC/iMindsTestBed.privateKey "$PROJ.tar.gz" fsismond@193.190.127.249:/groups/wall2-ilabt-iminds-be/f-interop-coap/
ssh -i /Users/fsismondi/F-Interop/20160500_fed4fire-CoAP-remote-PoC/iMindsTestBed.privateKey fsismond@coord.iter01.wall2-ilabt-iminds-be.wall2.ilabt.iminds.be "cd /groups/wall2-ilabt-iminds-be/f-interop-coap; tar -zxvf "$PROJ.tar.gz""
