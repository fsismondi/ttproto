# -*- coding:utf-8 -*-
import os
import errno
import logging

__version__ = '0.1.11'

PACKAGE_DIR = os.path.dirname(os.path.realpath(__file__))
# Directories
DATADIR = os.path.join(PACKAGE_DIR, "data")
TMPDIR = os.path.join(PACKAGE_DIR, "tmp")
LOGDIR = os.path.join(PACKAGE_DIR, "log")

LOG_LEVEL = logging.INFO
LOG_FORMAT = '%(levelname)s %(name)s [%(threadName)s] %(message)s'
logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)

# lower versbosity of pika's logs
logging.getLogger('pika').setLevel(logging.WARNING)

logging.info("ttproto base dir : %s " % PACKAGE_DIR)

for d in TMPDIR, DATADIR, LOGDIR:
    logging.info("Creating %s directory." % d)
    try:
        os.makedirs(d)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
