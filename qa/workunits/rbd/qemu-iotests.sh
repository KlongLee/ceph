#!/bin/sh -ex

# Run qemu-iotests against rbd. These are block-level tests that go
# through qemu but do not involve running a full vm. Note that these
# require the admin ceph user, as there's no way to pass the ceph user
# to qemu-iotests currently.

# This will only work with particular qemu versions, like 1.0. Later
# versions of qemu include qemu-iotests directly in the qemu
# repository.
codevers=`lsb_release -sc`
iotests=qemu-iotests
testlist='001 002 003 004 005 008 009 010 011 021 025'

# See if we need to use the iotests suites in qemu (newer version).
# Right now, trusty is the only version that uses this.
for chkcode in "trusty"
do
    if [ "$chkcode" = "$codevers" ]
    then
        iotests=qemu/tests/qemu-iotests
    fi
done

if [ "$iotests" = "qemu/tests/qemu-iotests" ]
then
    git clone git://apt-mirror.front.sepia.ceph.com/qemu.git
    # use v2.2.0-rc3 (last released version that handles all the tests
    cd qemu
    git checkout 2528043f1f299e0e88cb026f1ca7c40bbb4e1f80
    cd ..
    testlist=$testlist' 032 033 055 077'
else
    git clone git://ceph.com/git/qemu-iotests.git
fi

cd "$iotests"

mkdir bin
# qemu-iotests expects a binary called just 'qemu' to be available
ln -s `which qemu-system-x86_64` bin/qemu

# this is normally generated by configure, but has nothing but a python
# binary definition, which we don't care about.  for some reason it is
# not present on trusty.
touch common.env

# TEST_DIR is the pool for rbd
TEST_DIR=rbd PATH="$PATH:$PWD/bin" ./check -rbd $testlist

if [ "$iotests" = "qemu/tests/qemu-iotests" ]
then
    cd ../../..
else
    cd ..
fi

dname=`echo $iotests | cut -d "/" -f1`
rm -rf $dname

