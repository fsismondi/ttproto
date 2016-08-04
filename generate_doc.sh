#!/bin/sh

# Build the .rst files
sphinx-apidoc -e -f -l -o sphinx-doc-src ttproto

# WARNING: The following script will run module codes if there are some
#          and this can lead to errors or even to the blocking of the
#          documentation generation.
#          You can put the files to exclude into the exclude_patterns
#          variable in sphinx-doc-src/conf.py file to avoid this.

# Build html documentations (-b latex to generate latex doc)
sphinx-build -q -w log/sphinx-build.log -b html sphinx-doc-src doc

# Put the index.html document to be opened into browser
if [ ! -f doc/index.html ]; then
    ln -L doc/ttproto.html doc/index.html
fi
