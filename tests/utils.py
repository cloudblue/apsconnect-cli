import sys

if sys.version_info >= (3,):
    from unittest.mock import MagicMock
else:
    from mock import MagicMock


def create_fn_raising_error(msg):
    def _failing_fn(*args, **kwargs):
        raise Exception(msg)

    return _failing_fn


def create_replica(name):
    replica = MagicMock()
    replica.metadata = MagicMock()
    replica.metadata.name = name
    return replica


def create_pod(name):
    pod = MagicMock()
    pod.metadata = MagicMock()
    pod.metadata.name = name
    return pod


def mute_stdoutputs():
    sys.stdout = None
    sys.stderr = None
