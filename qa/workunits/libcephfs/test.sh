#!/bin/sh -e

ceph_test_libcephfs
ceph_test_libcephfs_access
ceph_test_libcephfs_reclaim
ceph_test_libcephfs_lazyio

exit 0
