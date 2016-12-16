#!/bin/sh -ex

CEPH_REF=${CEPH_REF:-master}
wget -q https://raw.githubusercontent.com/SUSE/ceph/$CEPH_REF/src/test/pybind/test_notify.py
#wget -O test_notify.py "https://git.ceph.com/?p=ceph.git;a=blob_plain;hb=$CEPH_REF;f=src/test/librbd/test_notify.py"

python test_notify.py slave
exit 0
