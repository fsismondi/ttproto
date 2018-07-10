# -*- coding:utf-8 -*-
import os
import errno
import logging

__version__ = '0.1.4'

# Directories
DATADIR = "data"
TMPDIR = "tmp"
LOGDIR = "log"

LOG_LEVEL = logging.INFO
LOG_FORMAT = '%(levelname)s %(name)s [%(threadName)s] %(message)s'
logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)

# lower versbosity of pika's logs
logging.getLogger('pika').setLevel(logging.WARNING)

for d in TMPDIR, DATADIR, LOGDIR:
    try:
        os.makedirs(d)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
