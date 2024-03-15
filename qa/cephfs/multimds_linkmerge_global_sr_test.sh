MNT=/mnt
CEPH=bin/ceph
RADOS=bin/rados
FS=a
DIR1_MDS_OBJ=""
DIR2_MDS_OBJ=""
DIR3_MDS_OBJ=""
DIR4_MDS_OBJ=""
DIR1_SUBDIR1_MDS_OBJ=""
DIR2_SUBDIR2_MDS_OBJ=""
DIR3_SUBDIR3_MDS_OBJ=""
DIR1_SUBDIR1_FILE1_DATA_OBJ=""
DIR4_FILE1_DATA_OBJ=""

function flush_mds_journal () {
  echo "flush mds.0 journal"
  $CEPH tell mds.0 flush journal > /dev/null 2>&1
  echo "flush mds.1 journal"
  $CEPH tell mds.1 flush journal > /dev/null 2>&1
  echo "flush mds.2 journal"
  $CEPH tell mds.2 flush journal > /dev/null 2>&1
}

function get_data_object () {
  $RADOS -p cephfs.a.meta getomapval $1 $2 /tmp/a
  pinode=$(bin/ceph-dencoder type 'inode_t<std::allocator>' skip 25 import /tmp/a decode dump_json | jq '.ino')
  hex_pinode=$(printf "%x" $pinode)
  dataobject=$(echo $hex_pinode.00000000)
  echo "$dataobject"
}

function fuse_mount () {
  echo "--------------------------------------------------------------------------------------------------"
  echo "Fuse mount at $MNT"
  sudo umount -f $MNT
  sudo umount -f $MNT
  sleep 3
  sudo bin/ceph-fuse -c ./ceph.conf $MNT 2>/dev/null
}

function clean_data () {
  echo "--------------------------------------------------------------------------------------------------"
  echo "clean data ..."
  echo "remove snapshot ..."
  rmdir $MNT/dir1/.snap/*
  rmdir $MNT/dir2/.snap/*
  rmdir $MNT/dir3/.snap/*
  rmdir $MNT/dir4/.snap/*
  echo "rm -rf $MNT"
  rm -rf $MNT/*
  flush_mds_journal
  sleep 3
}

function set_max_mds () {
  echo "set max_mds to $1"
  $CEPH fs set $FS max_mds $1
  flush_mds_journal
  echo "Wait 10 secs for other mds to become active"
  sleep 10
}

function create_dirs_and_pin () {
  echo "mkdir /dir1"
  mkdir $MNT/dir1
  flush_mds_journal
  declare -g DIR1_MDS_OBJ=$($RADOS -p cephfs.a.meta ls | grep -E "([0-9]|[a-f]){11}.")
  echo "DIR1_MDS_OBJ: $DIR1_MDS_OBJ"

  echo "mkdir /dir2"
  mkdir $MNT/dir2
  flush_mds_journal
  declare -g DIR2_MDS_OBJ=$($RADOS -p cephfs.a.meta ls | grep -E "([0-9]|[a-f]){11}." | grep -v "${DIR1_MDS_OBJ}")
  echo "DIR2_MDS_OBJ: $DIR2_MDS_OBJ"

  echo "mkdir /dir3"
  mkdir $MNT/dir3
  flush_mds_journal
  declare -g DIR3_MDS_OBJ=$($RADOS -p cephfs.a.meta ls | grep -E "([0-9]|[a-f]){11}." | grep -v "${DIR1_MDS_OBJ}" | grep -v "${DIR2_MDS_OBJ}")
  echo "DIR3_MDS_OBJ: $DIR3_MDS_OBJ"

  rank0=$($CEPH fs get $FS 2>/dev/null | grep "mds\." | grep "{0" | awk '{print $1}')
  echo "static pin /dir1 to rank 0 - $rank0"
  setfattr -n ceph.dir.pin -v 0 $MNT/dir1
  rank1=$($CEPH fs get $FS 2>/dev/null | grep "mds\." | grep "{1" | awk '{print $1}')
  echo "static pin /dir2 to rank 1 - $rank1"
  setfattr -n ceph.dir.pin -v 1 $MNT/dir2
  rank2=$($CEPH fs get $FS 2>/dev/null | grep "mds\." | grep "{2" | awk '{print $1}')
  echo "static pin /dir3 to rank 2 - $rank2"
  setfattr -n ceph.dir.pin -v 2 $MNT/dir3
}

function create_sample_files () {
  echo "create /dir1/init_migration1"
  echo "data init_migration1" > $MNT/dir1/init_migration1

  echo "create /dir2/init_migration1"
  echo "data init_migration2" > $MNT/dir2/init_migration2

  echo "create /dir3/init_migration1"
  echo "data init_migration2" > $MNT/dir3/init_migration3

  echo "Wait 30 seconds for subtree migration"
  sleep 30

  echo "create /dir1/sub_dir1"
  mkdir $MNT/dir1/sub_dir1
  flush_mds_journal
  declare -g DIR1_SUBDIR1_MDS_OBJ=$($RADOS -p cephfs.a.meta ls | grep -E "([0-9]|[a-f]){11}." | grep -v "${DIR1_MDS_OBJ}" | grep -v "${DIR2_MDS_OBJ}" | grep -v "${DIR3_MDS_OBJ}")
  echo "DIR1_SUBDIR1_MDS_OBJ: $DIR1_SUBDIR1_MDS_OBJ"

  echo "create /dir2/sub_dir2"
  mkdir $MNT/dir2/sub_dir2
  flush_mds_journal
  declare -g DIR2_SUBDIR2_MDS_OBJ=$($RADOS -p cephfs.a.meta ls | grep -E "([0-9]|[a-f]){11}." | grep -v "${DIR1_MDS_OBJ}" | grep -v "${DIR2_MDS_OBJ}" | grep -v "${DIR3_MDS_OBJ}" | grep -v "${DIR1_SUBDIR1_MDS_OBJ}")
  echo "DIR2_SUBDIR2_MDS_OBJ: $DIR2_SUBDIR2_MDS_OBJ"

  echo "create /dir3/sub_dir3"
  mkdir $MNT/dir3/sub_dir3
  flush_mds_journal
  declare -g DIR3_SUBDIR3_MDS_OBJ=$($RADOS -p cephfs.a.meta ls | grep -E "([0-9]|[a-f]){11}." | grep -v "${DIR1_MDS_OBJ}" | grep -v "${DIR2_MDS_OBJ}" | grep -v "${DIR3_MDS_OBJ}" | grep -v "${DIR1_SUBDIR1_MDS_OBJ}" | grep -v "${DIR2_SUBDIR2_MDS_OBJ}")
  echo "DIR3_SUBDIR3_MDS_OBJ: $DIR3_SUBDIR3_MDS_OBJ"

  echo "create /dir1/sub_dir1/dir1_file1"
  echo "Initial data for dir1_snap0 dir1_snap1 " > $MNT/dir1/sub_dir1/dir1_file1
  flush_mds_journal
  DIR1_SUBDIR1_FILE1_DATA_OBJ=$(get_data_object $DIR1_SUBDIR1_MDS_OBJ "dir1_file1_head")
  echo "DIR1_SUBDIR1_FILE1_DATA_OBJ: $DIR1_SUBDIR1_FILE1_DATA_OBJ"

  echo "ln /dir1/sub_dir1/dir1_file1 /dir2/sub_dir2/dir2_hl_file1"
  ln $MNT/dir1/sub_dir1/dir1_file1 $MNT/dir2/sub_dir2/dir2_hl_file1
  flush_mds_journal
}

function setup_test_bed () {
  fuse_mount
  clean_data
  create_dirs_and_pin
  create_sample_files
}

if [ "$1" == "repeat" ]; then
  echo "Cleanup and repeating the test"
else
  echo "Setup ..."
  set_max_mds 3
fi

setup_test_bed

#capture size of primary file for validation
dir1_file1_size_for_dir1_snap0=$(stat -c "%s" $MNT/dir1/sub_dir1/dir1_file1)

#create snaps
mkdir $MNT/dir1/.snap/dir1_snap0
mkdir $MNT/dir2/.snap/dir1_snap1

#List rados snaps - observe no snaps at rados yet
snap_count=$($RADOS -p cephfs.a.data listsnaps $DIR1_SUBDIR1_FILE1_DATA_OBJ --format=json-pretty | jq -r '.clones[].snapshots[].id' | jq -s 'length')
if [ "$snap_count" -ne 0 ]; then
  echo "FAIL - snapshots should be empty before write"
  exit
fi

#COW - Write data - rados takes snapshot on next write
echo "data for dir2_snap0 " >> $MNT/dir1/sub_dir1/dir1_file1

#List rados snaps - observe snaps
snap_count=$($RADOS -p cephfs.a.data listsnaps $DIR1_SUBDIR1_FILE1_DATA_OBJ --format=json-pretty | jq -r '.clones[].snapshots[].id' | jq -s 'length')
if [ "$snap_count" -ne 2 ]; then
  echo "FAIL - object snapshots should have been taken after write"
  exit
fi

#Remove primary file and wait for re-integration
rm -f $MNT/dir1/sub_dir1/dir1_file1
flush_mds_journal
echo "Waiting 15 secs reintegration"
sleep 15

#capture size of new primary file for validation
dir2_hl_file1_size_for_dir2_snap0=$(stat -c "%s" $MNT/dir2/sub_dir2/dir2_hl_file1)

#Take snaps on dir2 - secondary hardlink file is present (became primary)
mkdir $MNT/dir2/.snap/dir2_snap0

#truncate hardlink file - observe previous snapshots
truncate -s 0 $MNT/dir2/sub_dir2/dir2_hl_file1
flush_mds_journal

#List rados snaps - observe snaps
snap_count=$($RADOS -p cephfs.a.data listsnaps $DIR1_SUBDIR1_FILE1_DATA_OBJ --format=json-pretty | jq -r '.clones[].snapshots[].id' | jq -s 'length')
if [ "$snap_count" -ne 3 ]; then
  echo "FAIL - snapshot on new primary file should be accounted - total snpashot should be 3"
  exit
fi

#Validate privous snapshots
snapped_dir1_file1_size_for_dir1_snap0=$(stat -c "%s" $MNT/dir1/.snap/dir1_snap0/sub_dir1/dir1_file1)
if [ "$dir1_file1_size_for_dir1_snap0" -ne "$snapped_dir1_file1_size_for_dir1_snap0" ];then
  echo "FAIL - file content should match in snapshot for /dir1/sub_dir1/dir1_file1"
  exit
fi

#Validate privous snapshots
snapped_dir2_hl_file1_size_for_dir2_snap0=$(stat -c "%s" $MNT/dir2/.snap/dir2_snap0/sub_dir2/dir2_hl_file1)
if [ "$dir2_hl_file1_size_for_dir2_snap0" -ne "$snapped_dir2_hl_file1_size_for_dir2_snap0" ];then
  echo "FAIL - file content should match in snapshot for /dir2/sub_dir2/dir2_hl_file1"
  exit
fi

echo "SUCCESS"
