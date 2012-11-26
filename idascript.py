# Python module for IDAPython scripts run via idascript.
#
# Copied from the original idascript utility, with minor changes:
#    http://www.hexblog.com/?p=128
#
# Craig Heffner
# 14-November-2012
# http://www.tacnetsol.com
# http://www.devttys0.com
#
# Jurriaan Bremer (pep8, corrected the temp file path thingy)
# http://jbremer.org/

import idc
import os
import os.path
import sys


class ToFileStdOut(object):
    def __init__(self, outfile):
        self.outfile = open(outfile, 'w')

    def write(self, text):
        self.outfile.write(text)

    def flush(self):
        self.outfile.flush()

    def isatty(self):
        return False

    def __del__(self):
        self.outfile.close()

# Redirect stdout and stderr to the output file
path = os.path.join(os.getenv('TEMP'), 'idaout.txt')
sys.stdout = sys.stderr = ToFileStdOut(path)

# Make the normal sys.argv and sys.exit function properly
sys.argv = idc.ARGV
sys.exit = idc.Exit
