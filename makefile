# Makefile

# Parameters
LOG_DIR = ./log
DOC_DIR = ./doc
TMP_DIR = ./tmp
REPORTS_DIR = ./reports
SPHINX_DOC_SRC = ./sphinx-doc-src
DIAG_DIR = $(DOC_DIR)/diagrams

# Launch the unitary test suite
unit-tests:
	python3 -m tests.launcher

# Build the documentation of the project
documentation:

	# Build the .rst files
	sphinx-apidoc -e -f -l -o sphinx-doc-src ttproto

	# WARNING: The following script will run module codes if there are some
	#          and this can lead to errors or even to the blocking of the
	#          documentation generation.
	#          You can put the files to exclude into the exclude_patterns
	#          variable in sphinx-doc-src/conf.py file to avoid this.

	# Build html documentations (-b latex to generate latex doc)
	sphinx-build -q -w $(LOG_DIR)/sphinx-build.log -b html sphinx-doc-src $(DOC_DIR)

	# Put the index.html document to be opened into browser
	if [ ! -f $(DOC_DIR)/index.html ]; then
	    ln -L $(DOC_DIR)/ttproto.html $(DOC_DIR)/index.html
	fi

# Build the UML diagrams of the project as .dia files
diagrams:
	for file in $$(find . -name "*.py"); do autodia -i $$file -l python -H -o "$(DIAG_DIR)/$${file%.py}.dia"; done;

# Clean the working directory
clean:
	rm -rf $(DIAG_DIR)
	rm -rf $(TMP_DIR)/*
	rm -rf $(REPORTS_DIR)/*
	rm -rf $(DOC_DIR)/_*
	rm -rf $(DOC_DIR)/.*
	rm $(SPHINX_DOC_SRC)/*.rst
	rm $(DOC_DIR)/*
	for file in $$(find . -name "*.pyc"); do rm $$file; done;
