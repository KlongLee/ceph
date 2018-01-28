import os
import pytest
from ceph_volume.api import lvm as lvm_api
from ceph_volume import conf


class Capture(object):

    def __init__(self, *a, **kw):
        self.a = a
        self.kw = kw
        self.calls = []

    def __call__(self, *a, **kw):
        self.calls.append({'args': a, 'kwargs': kw})


class Factory(object):

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


@pytest.fixture
def factory():
    return Factory


@pytest.fixture
def capture():
    return Capture()


@pytest.fixture
def fake_run(monkeypatch):
    fake_run = Capture()
    monkeypatch.setattr('ceph_volume.process.run', fake_run)
    return fake_run


@pytest.fixture
def fake_call(monkeypatch):
    fake_call = Capture()
    monkeypatch.setattr('ceph_volume.process.call', fake_call)
    return fake_call


@pytest.fixture
def conf_ceph(monkeypatch):
    """
    Monkeypatches ceph_volume.conf.ceph, which is meant to parse/read
    a ceph.conf. The patching is naive, it allows one to set return values for
    specific method calls.
    """
    def apply(**kw):
        stub = Factory(**kw)
        monkeypatch.setattr(conf, 'ceph', stub)
        return stub
    return apply


@pytest.fixture
def volumes(monkeypatch):
    monkeypatch.setattr('ceph_volume.process.call', lambda x: ('', '', 0))
    volumes = lvm_api.Volumes()
    volumes._purge()
    return volumes


@pytest.fixture
def volume_groups(monkeypatch):
    monkeypatch.setattr('ceph_volume.process.call', lambda x: ('', '', 0))
    vgs = lvm_api.VolumeGroups()
    vgs._purge()
    return vgs


@pytest.fixture
def is_root(monkeypatch):
    """
    Patch ``os.getuid()`` so that ceph-volume's decorators that ensure a user
    is root (or is sudoing to superuser) can continue as-is
    """
    monkeypatch.setattr('os.getuid', lambda: 0)


@pytest.fixture
def tmpfile(tmpdir):
    """
    Create a temporary file, optionally filling it with contents, returns an
    absolute path to the file when called
    """
    def generate_file(name='file', contents=''):
        path = os.path.join(str(tmpdir), name)
        with open(path, 'w') as fp:
            fp.write(contents)
        return path
    return generate_file
