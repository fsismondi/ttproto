#!/bin/sh

# Build the .rst files
sphinx-apidoc -e -f -l -o sphinx-doc-src ttproto

# FIXME: Sphinx building system seems to run the code
# 		 And those files has some waiting mecanism in them
#		 so they block the whole build

# Change extension of the launcher files
mv sphinx-doc-src/ttproto.ts_6lowpan_nd.console.rst sphinx-doc-src/ttproto.ts_6lowpan_nd.console.rst.old
mv sphinx-doc-src/ttproto.ts_6lowpan_nd.run_implem.rst sphinx-doc-src/ttproto.ts_6lowpan_nd.run_implem.rst.old

# Clear old .old files that will block the renaming of the new ones
# rm sphinx-doc-src/ttproto.ts_6lowpan_nd.test*.rst.old

# Same for test files that are executed too
# rename 's/\.rst$/\.rst\.old/' sphinx-doc-src/ttproto.ts_6lowpan_nd.test*.rst

# Build html documentations
sphinx-build -q -w log/sphinx-build.log -b html sphinx-doc-src sphinx-doc

# Build latex documentations
# sphinx-build -q -w log/sphinx-build.log -b latex sphinx-doc-src sphinx-doc