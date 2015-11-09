#!/bin/bash -ex

TMPDIR=/tmp/rbd_test_admin_socket$$
mkdir $TMPDIR
trap "rm -fr $TMPDIR" 0

. $(dirname $0)/../ceph-helpers.sh

function expect_false()
{
    set -x
    if "$@"; then return 1; else return 0; fi
}

function rbd_watch_out_file()
{
    echo ${TMPDIR}/rbd_watch_$1.out
}

function rbd_watch_pid_file()
{
    echo ${TMPDIR}/rbd_watch_$1.pid
}

function rbd_watch_fifo()
{
    echo ${TMPDIR}/rbd_watch_$1.fifo
}

function rbd_watch_asok()
{
    echo ${TMPDIR}/rbd_watch_$1.asok
}

function rbd_get_perfcounter()
{
    local image=$1
    local counter=$2

    ceph --admin-daemon $(rbd_watch_asok ${image}) perf dump |
	sed -ne 's/^.*"'${counter}'": \([0-9]*\).*$/\1/p'
}

function rbd_check_perfcounter()
{
    local image=$1
    local counter=$2
    local expected_val=$3
    local val=

    val=$(rbd_get_perfcounter ${image} ${counter})

    test "${val}" -eq "${expected_val}"
}

function rbd_watch_start()
{
    local image=$1

    mkfifo $(rbd_watch_fifo ${image})
    (cat $(rbd_watch_fifo ${image}) |
	    rbd watch ${image} > $(rbd_watch_out_file ${image}) 2>&1)&

    # find pid of the started rbd watch process
    local pid
    for i in `seq 10`; do
	pid=$(ps auxww | awk "/[r]bd watch ${image}/ {print \$2}")
	test -n "${pid}" && break
	sleep 0.1
    done
    test -n "${pid}"
    echo ${pid} > $(rbd_watch_pid_file ${image})

    # find watcher admin socket
    local asok=$(ceph-conf admin_socket | sed -E "s/[0-9]+/${pid}/")
    test -n "${asok}"
    for i in `seq 10`; do
	test -S "${asok}" && break
	sleep 0.1
    done
    test -S "${asok}"
    ln -s "${asok}" $(rbd_watch_asok ${image})

    # configure debug level
    ceph --admin-daemon "${asok}" config set debug_rbd 20

    # check that watcher is registered
    rbd status ${image} | expect_false grep "Watchers: none"
}

function rbd_watch_end()
{
    local image=$1
    local regexp=$2

    # send 'enter' to watch to exit
    echo > $(rbd_watch_fifo ${image})
    # just in case it is not terminated
    kill $(cat $(rbd_watch_pid_file ${image})) || :

    # output rbd watch out file for easier troubleshooting
    cat $(rbd_watch_out_file ${image})

    # cleanup
    rm -f $(rbd_watch_fifo ${image}) $(rbd_watch_pid_file ${image}) \
       $(rbd_watch_out_file ${image}) $(rbd_watch_asok ${image})
}

wait_for_clean

image=testimg$$
ceph_admin="ceph --admin-daemon $(rbd_watch_asok ${image})"

rbd create --size 128 ${image}

# check rbd cache commands are present in help output
rbd_watch_start ${image}
${ceph_admin} help | fgrep "rbd cache flush ${image}"
${ceph_admin} help | fgrep "rbd cache invalidate ${image}"
rbd_watch_end ${image}

# test rbd cache commands with disabled and enabled cache
for conf_rbd_cache in false true; do

    rbd image-meta set ${image} conf_rbd_cache ${conf_rbd_cache}

    rbd_watch_start ${image}

    rbd_check_perfcounter ${image} flush 0
    ${ceph_admin} rbd cache flush ${image}
    # 'flush' counter should increase regardless if cache is enabled
    rbd_check_perfcounter ${image} flush 1

    rbd_check_perfcounter ${image} invalidate_cache 0
    ${ceph_admin} rbd cache invalidate ${image}
    # 'invalidate_cache' counter should increase regardless if cache is enabled
    rbd_check_perfcounter ${image} invalidate_cache 1

    rbd_watch_end ${image}
done

rbd rm ${image}
