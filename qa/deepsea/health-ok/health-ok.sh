#!/bin/bash
#
# DeepSea integration test "suites/basic/health-ok.sh"
#
# This script runs DeepSea stages 0-3 (or 0-4, depending on options) to deploy
# a Ceph cluster (with various options to control the cluster configuration).
# After the last stage completes, the script checks for HEALTH_OK.
#
# The script makes no assumptions beyond those listed in README.
#
# After HEALTH_OK is reached, the script also runs various sanity tests
# depending on the options provided.
#
# On success (HEALTH_OK is reached, sanity tests pass), the script returns 0.
# On failure, for whatever reason, the script returns non-zero.
#
# The script produces verbose output on stdout, which can be captured for later
# forensic analysis.
#

set -e
set +x

SCRIPTNAME=$(basename ${0})
BASEDIR=$(readlink -f "$(dirname ${0})")
test -d $BASEDIR
[[ $BASEDIR =~ \/health-ok$ ]]

source $BASEDIR/common/common.sh

function usage {
    set +x
    echo "$SCRIPTNAME - script for testing HEALTH_OK deployment"
    echo "for use in SUSE Enterprise Storage testing"
    echo
    echo "Usage:"
    echo "  $SCRIPTNAME [-h,--help] [--cli] [--client-nodes=X]"
    echo "  [--mds] [--min-nodes=X] [--nfs-ganesha] [--no-update]"
    echo "  [--openstack] [--profile=X] [--rbd] [--rgw] [--ssl]"
    echo "  [--tuned=X]"
    echo
    echo "Options:"
    echo "    --cli           Use DeepSea CLI"
    echo "    --client-nodes  Number of client (non-cluster) nodes"
    echo "    --help          Display this usage message"
    echo "    --mds           Deploy MDS"
    echo "    --min-nodes     Minimum number of nodes"
    echo "    --nfs-ganesha   Deploy NFS-Ganesha"
    echo "    --no-update     Use no-update-no-reboot Stage 0 alt default"
    echo "    --openstack     Pre-create pools for OpenStack functests"
    echo "    --profile       Storage/OSD profile (see below)"
    echo "    --rbd           Modify ceph.conf for rbd integration testing"
    echo "    --rgw           Deploy RGW"
    echo "    --ssl           Deploy RGW with SSL"
    echo "    --start-stage   Run stages from (defaults to 0)"
    echo "    --teuthology    Provide this option when running via teuthology"
    echo "    --tuned=on/off  Deploy tuned in Stage 3 (default: off)"
    echo
    echo "Supported storage/OSD profiles:"
    echo "    default         Whatever is generated by Stage 1 (bluestore)"
    echo "    dmcrypt         All encrypted OSDs"
    echo "    filestore       All filestore OSDs"
    echo "    random          A randomly chosen profile (teuthology/OVH only)"
    echo "    <OTHER>         Any other value will be assumed to be the name"
    echo "                    of an OSD profile in qa/osd-config/ovh"
    exit 1
}

assert_enhanced_getopt

TEMP=$(getopt -o h \
--long "cli,client-nodes:,help,igw,mds,min-nodes:,nfs-ganesha,no-update,openstack,profile:,rbd,rgw,ssl,start-stage:,teuthology,tuned:" \
-n 'health-ok.sh' -- "$@")

if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

# Note the quotes around TEMP': they are essential!
eval set -- "$TEMP"

# process command-line options
CLI=""
CLIENT_NODES=0
STORAGE_PROFILE="default"
CUSTOM_STORAGE_PROFILE=""
MDS=""
MIN_NODES=1
OPENSTACK=""
NFS_GANESHA=""
NO_UPDATE=""
RBD=""
RGW=""
SSL=""
START_STAGE="0"
TEUTHOLOGY=""
TUNED="off"
while true ; do
    case "$1" in
        --cli) CLI="$1" ; shift ;;
        --client-nodes) shift ; CLIENT_NODES=$1 ; shift ;;
        -h|--help) usage ;;    # does not return
        --mds) MDS="$1" ; shift ;;
        --min-nodes) shift ; MIN_NODES=$1 ; shift ;;
        --nfs-ganesha) NFS_GANESHA="$1" ; shift ;;
        --no-update) NO_UPDATE="$1" ; shift ;;
        --openstack) OPENSTACK="$1" ; shift ;;
        --profile) shift ; STORAGE_PROFILE=$1 ; shift ;;
        --rbd) RBD="$1" ; shift ;;
        --rgw) RGW="$1" ; shift ;;
        --ssl) SSL="$1" ; shift ;;
	--start-stage) shift ; START_STAGE=$1 ; shift ;;
	--teuthology) TEUTHOLOGY="$1" ; shift ;;
        --tuned) shift ; TUNED=$1 ; shift ;;
        --) shift ; break ;;
        *) echo "Internal error" ; exit 1 ;;
    esac
done
if [ "$NFS_GANESHA" ] ; then
    if [ -z "$MDS" -a -z "$RGW" ] ; then
        echo "NFS-Ganesha requires either mds or rgw role, but neither was specified. Bailing out!"
        exit 1
    fi
fi
TUNED=${TUNED,,}
case "$TUNED" in
    on) ;;
    off) TUNED='' ;;
    *) echo "Bad value ->$TUNED<- passed with --tuned. Bailing out!" ; exit 1 ;;
esac
echo "WWWW"
echo "health-ok.sh running with the following configuration:"
test -n "$CLI" && echo "- CLI"
echo "- CLIENT_NODES ->$CLIENT_NODES<-"
echo "- MIN_NODES ->$MIN_NODES<-"
test -n "$MDS" && echo "- MDS"
test -n "$NFS_GANESHA" && echo "- NFS-Ganesha"
test -n "$OPENSTACK" && echo "- OpenStack test pools will be pre-created"
echo "- PROFILE ->$STORAGE_PROFILE<-"
test -n "$RBD" && echo "- RBD"
test -n "$RGW" && echo "- RGW"
test -n "$SSL" && echo "- SSL"
echo "- Start Stage ->$START_STAGE<-"
test -n "$TEUTHOLOGY" && echo "- TEUTHOLOGY"
echo -n "- TUNED: "
test -n "$TUNED" && echo "ON"
test -z "$TUNED" && echo "OFF"
echo -n "Stage 0 update: "
test -n "$NO_UPDATE" && echo "disabled" || echo "enabled"
set -x

# deploy phase
deploy_ceph

# verification phase
ceph_health_test
test "$STORAGE_NODES" = "$(number_of_hosts_in_ceph_osd_tree)"
#salt -I roles:storage osd.report 2>/dev/null

# test phase
REPEAT_STAGE_0=""
ceph_log_grep_enoent_eaccess
test_systemd_ceph_osd_target_wants
#rados_write_test
#ceph_version_test
if [ -n "$RGW" ] ; then
    rgw_curl_test
    test -n "$SSL" && validate_rgw_cert_perm
    rgw_user_and_bucket_list
    rgw_validate_system_user
    rgw_validate_demo_users
fi
test -n "$MDS" -a "$CLIENT_NODES" -ge 1 && cephfs_mount_and_sanity_test
if [ "$NFS_GANESHA" ] ; then
    for v in "" "3" "4" ; do
        echo "Testing NFS-Ganesha with NFS version ->$v<-"
        if [ "$RGW" -a "$v" = "3" ] ; then
            echo "Not testing RGW FSAL on NFSv3"
            continue
        else
            nfs_ganesha_mount "$v"
        fi
        if [ "$MDS" ] ; then
            nfs_ganesha_write_test cephfs "$v"
        fi
        if [ "$RGW" ] ; then
            if [ "$v" = "3" ] ; then
                echo "Not testing RGW FSAL on NFSv3"
            else
                rgw_curl_test
                rgw_user_and_bucket_list
                rgw_validate_demo_users
                nfs_ganesha_write_test rgw "$v"
            fi
        fi
        nfs_ganesha_umount
        sleep 10
    done
    REPEAT_STAGE_0="yes, please"
fi
test "$REPEAT_STAGE_0" && run_stage_0 "$CLI" # exercise ceph.restart orchestration

echo "YYYY"
echo "health-ok test result: PASS"
