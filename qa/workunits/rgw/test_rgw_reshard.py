#!/usr/bin/python3

import errno
import logging as log
import time
import json
import os
from common import exec_cmd, boto_connect, create_user
import re

from pprint import pprint

"""
Rgw manual and dynamic resharding  testing against a running instance
"""
# The test cases in this file have been annotated for inventory.
# To extract the inventory (in csv format) use the command:
#
#   grep '^ *# TESTCASE' | sed 's/^ *# TESTCASE //'
#
#

""" Constants """
USER = 'tester'
DISPLAY_NAME = 'Testing'
ACCESS_KEY = 'NX5QOQKC6BH2IDN8HC7A'
SECRET_KEY = 'LnEsqNNqZIpkzauboDcLXLcYaWwLQ3Kop0zAnKIn'
BUCKET_NAME = 'a-bucket'
VER_BUCKET_NAME = 'myver'
INDEX_POOL = 'default.rgw.buckets.index'

class BucketStats:
    def __init__(self, bucket_name, bucket_id, num_objs=0, size_kb=0, num_shards=0):
        self.bucket_name = bucket_name
        self.bucket_id = bucket_id
        self.num_objs = num_objs
        self.size_kb = size_kb
        self.num_shards = num_shards if num_shards > 0 else 1

    def get_num_shards(self):
        self.num_shards = get_bucket_num_shards(self.bucket_name, self.bucket_id)


def get_bucket_stats(bucket_name):
    """
    function to get bucket stats
    """
    cmd = exec_cmd("radosgw-admin bucket stats --bucket {}".format(bucket_name))
    json_op = json.loads(cmd)
    #print(json.dumps(json_op, indent = 4, sort_keys=True))
    bucket_id = json_op['id']
    num_shards = json_op['num_shards']
    if len(json_op['usage']) > 0:
        num_objects = json_op['usage']['rgw.main']['num_objects']
        size_kb = json_op['usage']['rgw.main']['size_kb']
    else:
        num_objects = 0
        size_kb = 0
    log.debug(" \nBUCKET_STATS: \nbucket: {} id: {} num_objects: {} size_kb: {} num_shards: {}\n".format(bucket_name, bucket_id,
              num_objects, size_kb, num_shards))
    return BucketStats(bucket_name, bucket_id, num_objects, size_kb, num_shards)


def get_bucket_num_shards(bucket_name, bucket_id):
    """
    function to get bucket num shards
    """
    metadata = 'bucket.instance:' + bucket_name + ':' + bucket_id
    cmd = exec_cmd('radosgw-admin metadata get {}'.format(metadata))
    json_op = json.loads(cmd)
    num_shards = json_op['data']['bucket_info']['num_shards']
    return num_shards

def run_bucket_reshard_cmd(bucket_name, num_shards, **kwargs):
    cmd = 'radosgw-admin bucket reshard --bucket {} --num-shards {}'.format(bucket_name, num_shards)
    cmd += ' --rgw-reshard-bucket-lock-duration 30' # reduce to minimum
    if 'error_at' in kwargs:
        cmd += ' --inject-error-at {}'.format(kwargs.pop('error_at'))
    elif 'abort_at' in kwargs:
        cmd += ' --inject-abort-at {}'.format(kwargs.pop('abort_at'))
    return exec_cmd(cmd, **kwargs)

def test_bucket_reshard(conn, name, **fault):
    bucket = conn.create_bucket(Bucket=name)
    objs = []
    try:
        # create objs
        for i in range(0, 20):
            objs += [bucket.put_object(Key='key' + str(i), Body=b"some_data")]

        old_shard_count = get_bucket_stats(name).num_shards
        num_shards_expected = old_shard_count + 1

        # try reshard with fault injection
        _, ret = run_bucket_reshard_cmd(name, num_shards_expected, check_retcode=False, **fault)
        assert(ret != 0 and ret != errno.EBUSY)

        # check shard count
        cur_shard_count = get_bucket_stats(name).num_shards
        assert(cur_shard_count == old_shard_count)

        # verify that the bucket is writeable by deleting an object
        objs.pop().delete()

        # retry reshard without fault injection. if radosgw-admin aborted,
        # we'll have to retry until the reshard lock expires
        while True:
            _, ret = run_bucket_reshard_cmd(name, num_shards_expected, check_retcode=False)
            if ret == errno.EBUSY:
                log.info('waiting 30 seconds for reshard lock to expire...')
                time.sleep(30)
                continue
            assert(ret == 0)
            break

        # recheck shard count
        final_shard_count = get_bucket_stats(name).num_shards
        assert(final_shard_count == num_shards_expected)
    finally:
        # cleanup on resharded bucket must succeed
        bucket.delete_objects(Delete={'Objects':[{'Key':o.key} for o in objs]})
        bucket.delete()


def main():
    """
    execute manual and dynamic resharding commands
    """
    create_user(USER, DISPLAY_NAME, ACCESS_KEY, SECRET_KEY)
    
    connection = boto_connect(ACCESS_KEY, SECRET_KEY)

    # create a bucket
    bucket = connection.create_bucket(Bucket=BUCKET_NAME)
    ver_bucket = connection.create_bucket(Bucket=VER_BUCKET_NAME)
    connection.BucketVersioning('ver_bucket')

    bucket_acl = connection.BucketAcl(BUCKET_NAME).load()
    ver_bucket_acl = connection.BucketAcl(VER_BUCKET_NAME).load()

    # TESTCASE 'reshard-add','reshard','add','add bucket to resharding queue','succeeds'
    log.debug('TEST: reshard add\n')

    num_shards_expected = get_bucket_stats(BUCKET_NAME).num_shards + 1
    cmd = exec_cmd('radosgw-admin reshard add --bucket {} --num-shards {}'.format(BUCKET_NAME, num_shards_expected))
    cmd = exec_cmd('radosgw-admin reshard list')
    json_op = json.loads(cmd)
    log.debug('bucket name {}'.format(json_op[0]['bucket_name']))
    assert json_op[0]['bucket_name'] == BUCKET_NAME
    assert json_op[0]['tentative_new_num_shards'] == num_shards_expected

    # TESTCASE 'reshard-process','reshard','','process bucket resharding','succeeds'
    log.debug('TEST: reshard process\n')
    cmd = exec_cmd('radosgw-admin reshard process')
    time.sleep(5)
    # check bucket shards num
    bucket_stats1 = get_bucket_stats(BUCKET_NAME)
    if bucket_stats1.num_shards != num_shards_expected:
        log.error("Resharding failed on bucket {}. Expected number of shards are not created\n".format(BUCKET_NAME))

    # TESTCASE 'reshard-add','reshard','add','add non empty bucket to resharding queue','succeeds'
    log.debug('TEST: reshard add non empty bucket\n')
    # create objs
    num_objs = 8
    for i in range(0, num_objs):
        connection.Object(BUCKET_NAME, ('key'+str(i))).put(Body=b"some_data")

    num_shards_expected = get_bucket_stats(BUCKET_NAME).num_shards + 1
    cmd = exec_cmd('radosgw-admin reshard add --bucket {} --num-shards {}'.format(BUCKET_NAME, num_shards_expected))
    cmd = exec_cmd('radosgw-admin reshard list')
    json_op = json.loads(cmd)
    assert json_op[0]['bucket_name'] == BUCKET_NAME
    assert json_op[0]['tentative_new_num_shards'] == num_shards_expected

    # TESTCASE 'reshard process ,'reshard','process','reshard non empty bucket','succeeds'
    log.debug('TEST: reshard process non empty bucket\n')
    cmd = exec_cmd('radosgw-admin reshard process')
    # check bucket shards num
    bucket_stats1 = get_bucket_stats(BUCKET_NAME)
    if bucket_stats1.num_shards != num_shards_expected:
        log.error("Resharding failed on bucket {}. Expected number of shards are not created\n".format(BUCKET_NAME))

    # TESTCASE 'manual bucket resharding','inject error','fail','check bucket accessibility', 'retry reshard'
    log.debug('TEST: reshard bucket with EIO injected at do_reshard\n')
    test_bucket_reshard(connection, 'error-at-do-reshard', error_at='do_reshard')
    log.debug('TEST: reshard bucket with abort at do_reshard\n')
    test_bucket_reshard(connection, 'abort-at-do-reshard', abort_at='do_reshard')

    # TESTCASE 'versioning reshard-','bucket', reshard','versioning reshard','succeeds'
    log.debug(' test: reshard versioned bucket')
    num_shards_expected = get_bucket_stats(VER_BUCKET_NAME).num_shards + 1
    cmd = exec_cmd('radosgw-admin bucket reshard --bucket {} --num-shards {}'.format(VER_BUCKET_NAME,
                                                                                 num_shards_expected))
    # check bucket shards num
    ver_bucket_stats = get_bucket_stats(VER_BUCKET_NAME)
    assert ver_bucket_stats.num_shards == num_shards_expected

    # TESTCASE 'check acl'
    new_bucket_acl = connection.BucketAcl(BUCKET_NAME).load()
    assert new_bucket_acl == bucket_acl
    new_ver_bucket_acl = connection.BucketAcl(VER_BUCKET_NAME).load()
    assert new_ver_bucket_acl == ver_bucket_acl

    # TESTCASE 'check reshard removes olh entries with empty name'
    log.debug(' test: reshard removes olh entries with empty name')
    bucket1.objects.all().delete()

    # get name of shard 0 object, add a bogus olh entry with empty name
    bucket_shard0 = '.dir.%s.0' % get_bucket_stats(BUCKET_NAME1).bucket_id
    if 'CEPH_ROOT' in os.environ:
      k = '%s/qa/workunits/rgw/olh_noname_key' % os.environ['CEPH_ROOT']
      v = '%s/qa/workunits/rgw/olh_noname_val' % os.environ['CEPH_ROOT']
    else:
      k = 'olh_noname_key'
      v = 'olh_noname_val'
    exec_cmd('rados -p %s setomapval %s --omap-key-file %s < %s' % (INDEX_POOL, bucket_shard0, k, v))

    # check that bi list has one entry with empty name
    cmd = exec_cmd('radosgw-admin bi list --bucket %s' % BUCKET_NAME1)
    json_op = json.loads(cmd.decode('utf-8', 'ignore')) # ignore utf-8 can't decode 0x80
    assert len(json_op) == 1
    assert json_op[0]['entry']['key']['name'] == ''

    # reshard to prune the bogus olh
    cmd = exec_cmd('radosgw-admin bucket reshard --bucket %s --num-shards %s --yes-i-really-mean-it' % (BUCKET_NAME1, 1))

    # get new name of shard 0 object, check that bi list has zero entries
    bucket_shard0 = '.dir.%s.0' % get_bucket_stats(BUCKET_NAME1).bucket_id
    cmd = exec_cmd('radosgw-admin bi list --bucket %s' % BUCKET_NAME1)
    json_op = json.loads(cmd)
    assert len(json_op) == 0

    # Clean up
    log.debug("Deleting bucket {}".format(BUCKET_NAME))
    bucket.objects.all().delete()
    bucket.delete()
    log.debug("Deleting bucket {}".format(VER_BUCKET_NAME))
    ver_bucket.delete()


main()
log.info("Completed resharding tests")
