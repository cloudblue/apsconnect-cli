import sys


def mute_stdoutputs():
    sys.stdout = None
    sys.stderr = None
