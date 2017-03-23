# -*- coding:utf-8 -*-
import os, errno

__version__ = '0.1.1'  

# Directories
DATADIR = "data"
TMPDIR = "tmp"
LOGDIR = "log"

for d in TMPDIR, DATADIR, LOGDIR:
    try:
        os.makedirs(d)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise