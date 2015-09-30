#! /bin/bash

TESTDATA="testdata.$$"

function wait_for_health() {
    echo -n "Wait for health_ok..."
    tries=0
    while ./ceph health 2> /dev/null |  grep -v 'HEALTH_OK' > /dev/null
    do
	tries=`expr $tries + 1`
        if [ $tries = "30" ];
	then
            echo "Time exceeded to go to health"
            exit 1
	fi
        sleep 5
    done
    echo "DONE"
}

# A single osd
rm -rf out dev
MDS=0 MON=1 OSD=1 ./vstart.sh -l -d  -n -o "osd_pool_default_size=1"
wait_for_health

# Create a pool with a single pg
./ceph osd pool create test 1 1

dd if=/dev/urandom of=$TESTDATA bs=1032 count=1
for i in `seq 1 5`
do
    ./rados -p test put obj${i} $TESTDATA
done

# obj1 create snap 1
# manually obj1 remove head
# obj5  snap  6 4 2 1
# manually obj5 create snap 7
# manually obj5 remove 2
# manually obj5 remove 1
# obj3 snaps 3 1
# obj2 snap 4
# remove obj2
# manually remove snap 4
# obj4 remove obj4

SNAP=1
./rados -p test mksnap snap${SNAP}
dd if=/dev/urandom of=$TESTDATA bs=256 count=${SNAP}
./rados -p test put obj1 $TESTDATA
./rados -p test put obj5 $TESTDATA
./rados -p test put obj3 $TESTDATA

SNAP=2
./rados -p test mksnap snap${SNAP}
dd if=/dev/urandom of=$TESTDATA bs=256 count=${SNAP}
./rados -p test put obj5 $TESTDATA

SNAP=3
./rados -p test mksnap snap${SNAP}
dd if=/dev/urandom of=$TESTDATA bs=256 count=${SNAP}
./rados -p test put obj3 $TESTDATA

SNAP=4
./rados -p test mksnap snap${SNAP}
dd if=/dev/urandom of=$TESTDATA bs=256 count=${SNAP}
./rados -p test put obj5 $TESTDATA
./rados -p test put obj2 $TESTDATA

SNAP=5
./rados -p test mksnap snap${SNAP}
SNAP=6
./rados -p test mksnap snap${SNAP}
dd if=/dev/urandom of=$TESTDATA bs=256 count=${SNAP}
./rados -p test put obj5 $TESTDATA

SNAP=7
./rados -p test mksnap snap${SNAP}

./rados -p test rm obj4
./rados -p test rm obj2

killall ceph-osd
sleep 5

JSON="$(./ceph-objectstore-tool --data-path dev/osd0 --journal-path dev/osd0.journal --op list obj1 | grep \"snapid\":-2)"
./ceph-objectstore-tool --data-path dev/osd0 --journal-path dev/osd0.journal "$JSON" remove

JSON="$(./ceph-objectstore-tool --data-path dev/osd0 --journal-path dev/osd0.journal --op list obj5 | grep \"snapid\":2)"
./ceph-objectstore-tool --data-path dev/osd0 --journal-path dev/osd0.journal "$JSON" remove

JSON="$(./ceph-objectstore-tool --data-path dev/osd0 --journal-path dev/osd0.journal --op list obj5 | grep \"snapid\":1)"
OBJ5SAVE="$JSON"
./ceph-objectstore-tool --data-path dev/osd0 --journal-path dev/osd0.journal "$JSON" remove

JSON="$(./ceph-objectstore-tool --data-path dev/osd0 --journal-path dev/osd0.journal --op list obj5 | grep \"snapid\":4)"
dd if=/dev/urandom of=$TESTDATA bs=256 count=18
./ceph-objectstore-tool --data-path dev/osd0 --journal-path dev/osd0.journal "$JSON" set-bytes $TESTDATA

JSON="$(./ceph-objectstore-tool --data-path dev/osd0 --journal-path dev/osd0.journal --op list obj3 | grep \"snapid\":-2)"
dd if=/dev/urandom of=$TESTDATA bs=256 count=15
./ceph-objectstore-tool --data-path dev/osd0 --journal-path dev/osd0.journal "$JSON" set-bytes $TESTDATA

JSON="$(./ceph-objectstore-tool --data-path dev/osd0 --journal-path dev/osd0.journal --op list obj4 | grep \"snapid\":7)"
./ceph-objectstore-tool --data-path dev/osd0 --journal-path dev/osd0.journal "$JSON" remove

JSON="$(./ceph-objectstore-tool --data-path dev/osd0 --journal-path dev/osd0.journal --op list obj2 | grep \"snapid\":-1)"
./ceph-objectstore-tool --data-path dev/osd0 --journal-path dev/osd0.journal "$JSON" rm-attr snapset

# Create a clone which isn't in snapset and doesn't have object info
JSON="$(echo "$OBJ5SAVE" | sed s/snapid\":1/snapid\":7/)"
dd if=/dev/urandom of=$TESTDATA bs=256 count=7
./ceph-objectstore-tool --data-path dev/osd0 --journal-path dev/osd0.journal "$JSON" set-bytes $TESTDATA

rm -f $TESTDATA

#MDS=0 MON=1 OSD=1 ./vstart.sh -l -d  -o "osd_pool_default_size=1"
./ceph-osd -i 0 -c ceph.conf
wait_for_health

sleep 5
./ceph pg scrub 1.0
timeout 30 ./ceph -w

./stop.sh

ERRORS=0

declare -a err_strings
err_strings[0]="log_channel[(]cluster[)] log [[]ERR[]] : scrub 1.0 1/6cf8deff/obj1/1 is an unexpected clone"
err_strings[1]="log_channel[(]cluster[)] log [[]ERR[]] : scrub 1.0 1/666934a3/obj5/7 no '_' attr"
err_strings[2]="log_channel[(]cluster[)] log [[]ERR[]] : scrub 1.0 1/666934a3/obj5/7 is an unexpected clone"
err_strings[3]="log_channel[(]cluster[)] log [[]ERR[]] : scrub 1.0 1/666934a3/obj5/head expected clone 1/666934a3/obj5/2"
err_strings[4]="log_channel[(]cluster[)] log [[]ERR[]] : scrub 1.0 1/666934a3/obj5/head expected clone 1/666934a3/obj5/1"
err_strings[5]="log_channel[(]cluster[)] log [[]INF[]] : scrub 1.0 1/666934a3/obj5/head missing clones"
err_strings[6]="log_channel[(]cluster[)] log [[]ERR[]] : scrub 1.0 1/3f1ee208/obj2/snapdir no 'snapset' attr"
err_strings[7]="log_channel[(]cluster[)] log [[]ERR[]] : scrub 1.0 1/3f1ee208/obj2/7 is an unexpected clone"
err_strings[8]="log_channel[(]cluster[)] log [[]ERR[]] : scrub 1.0 1/3f1ee208/obj2/4 is an unexpected clone"
err_strings[9]="log_channel[(]cluster[)] log [[]ERR[]] : scrub 1.0 1/a8759770/obj4/snapdir expected clone 1/a8759770/obj4/7"
err_strings[10]="log_channel[(]cluster[)] log [[]INF[]] : scrub 1.0 1/a8759770/obj4/snapdir missing clones"
err_strings[11]="log_channel[(]cluster[)] log [[]ERR[]] : 1.0 scrub 12 errors"
err_strings[12]="log_channel[(]cluster[)] log [[]ERR[]] : scrub 1.0 1/666934a3/obj5/4 on disk size [(]4608[)] does not match object info size [(]512[)] adjusted for ondisk to [(]512[)]"
err_strings[13]="log_channel[(]cluster[)] log [[]ERR[]] : scrub 1.0 1/61f68bb1/obj3/head on disk size [(]3840[)] does not match object info size [(]768[)] adjusted for ondisk to [(]768[)]"

for i in `seq 0 ${#err_strings[@]}`
do
    if ! grep "${err_strings[$i]}" out/osd.0.log > /dev/null;
    then
	echo "Missing log message '${err_strings[$i]}'"
        ERRORS=$(expr $ERRORS + 1)
    fi
done

if [ $ERRORS != "0" ];
then
    echo "TEST FAILED WITH $ERRORS ERRORS"
    exit 1
fi

echo "TEST PASSED"
exit 0
