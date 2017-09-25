import pytest
from ceph_volume.devices.lvm import api

class Capture(object):

    def __init__(self, *a, **kw):
        self.a = a
        self.kw = kw
        self.calls = []

    def __call__(self, *a, **kw):
        self.calls.append({'args': a, 'kwargs': kw})


@pytest.fixture
def capture():
    return Capture()


@pytest.fixture
def volumes(monkeypatch):
    monkeypatch.setattr('ceph_volume.process.call', lambda x: ('', '', 0))
    volumes = api.Volumes()
    volumes._purge()
    return volumes


@pytest.fixture
def volume_groups(monkeypatch):
    monkeypatch.setattr('ceph_volume.process.call', lambda x: ('', '', 0))
    vgs = api.VolumeGroups()
    vgs._purge()
    return vgs


@pytest.fixture
def is_root(monkeypatch):
    """
    Patch ``os.getuid()`` so that ceph-volume's decorators that ensure a user
    is root (or is sudoing to superuser) can continue as-is
    """
    monkeypatch.setattr('os.getuid', lambda: 0)
