"""
Rgw admin testing against a running instance
"""
# The test cases in this file have been annotated for inventory.
# To extract the inventory (in csv format) use the command:
#
#   grep '^ *# TESTCASE' | sed 's/^ *# TESTCASE //'
#
# to run this standalone (on one zone):
#	python tasks/radosgw_admin.py HOSTNAME
#

import copy
import json
import logging
import time
import datetime
import Queue
import bunch

import sys

from cStringIO import StringIO

import boto.exception
import boto.s3.connection
import boto.s3.acl
from boto.utils import RequestHook

import httplib2

import util.rgw as rgw_utils

from util.rgw import rgwadmin, get_user_summary, get_user_successful_ops

log = logging.getLogger(__name__)

def usage_acc_findentry2(entries, user, add=True):
    for e in entries:
        if e['user'] == user:
            return e
    if not add:
            return None
    e = {'user': user, 'buckets': []}
    entries.append(e)
    return e
def usage_acc_findsum2(summaries, user, add=True):
    for e in summaries:
        if e['user'] == user:
            return e
    if not add:
        return None
    e = {'user': user, 'categories': [],
        'total': {'bytes_received': 0,
            'bytes_sent': 0, 'ops': 0, 'successful_ops': 0 }}
    summaries.append(e)
    return e
def usage_acc_update2(x, out, b_in, err):
    x['bytes_sent'] += b_in
    x['bytes_received'] += out
    x['ops'] += 1
    if not err:
        x['successful_ops'] += 1
def usage_acc_validate_fields(r, x, x2, what):
    q=[]
    for field in ['bytes_sent', 'bytes_received', 'ops', 'successful_ops']:
        try:
            if x2[field] < x[field]:
                q.append("field %s: %d < %d" % (field, x2[field], x[field]))
        except Exception as ex:
            r.append( "missing/bad field " + field + " in " + what + " " + str(ex))
            return
    if len(q) > 0:
        r.append("incomplete counts in " + what + ": " + ", ".join(q))
class usage_acc:
    def __init__(self):
        self.results = {'entries': [], 'summary': []}
    def findentry(self, user):
        return usage_acc_findentry2(self.results['entries'], user)
    def findsum(self, user):
        return usage_acc_findsum2(self.results['summary'], user)
    def e2b(self, e, bucket, add=True):
        for b in e['buckets']:
            if b['bucket'] == bucket:
                return b
        if not add:
                return None
        b = {'bucket': bucket, 'categories': []}
        e['buckets'].append(b)
        return b
    def c2x(self, c, cat, add=True):
        for x in c:
            if x['category'] == cat:
                return x
        if not add:
                return None
        x = {'bytes_received': 0, 'category': cat,
            'bytes_sent': 0, 'ops': 0, 'successful_ops': 0 }
        c.append(x)
        return x
    def update(self, c, cat, user, out, b_in, err):
        x = self.c2x(c, cat)
        usage_acc_update2(x, out, b_in, err)
        if not err and cat == 'create_bucket' and not x.has_key('owner'):
            x['owner'] = user
    def make_entry(self, cat, bucket, user, out, b_in, err):
        if cat == 'create_bucket' and err:
                return
        e = self.findentry(user)
        b = self.e2b(e, bucket)
        self.update(b['categories'], cat, user, out, b_in, err)
        s = self.findsum(user)
        x = self.c2x(s['categories'], cat)
        usage_acc_update2(x, out, b_in, err)
        x = s['total']
        usage_acc_update2(x, out, b_in, err)
    def generate_make_entry(self):
        return lambda cat,bucket,user,out,b_in,err: self.make_entry(cat, bucket, user, out, b_in, err)
    def get_usage(self):
        return self.results
    def compare_results(self, results):
        if not results.has_key('entries') or not results.has_key('summary'):
            return ['Missing entries or summary']
        r = []
        for e in self.results['entries']:
            try:
                e2 = usage_acc_findentry2(results['entries'], e['user'], False)
            except Exception as ex:
                r.append("malformed entry looking for user "
		    + e['user'] + " " + str(ex))
                break
            if e2 == None:
                r.append("missing entry for user " + e['user'])
                continue
            for b in e['buckets']:
                c = b['categories']
                if b['bucket'] == 'nosuchbucket':
                    print "got here"
                try:
                    b2 = self.e2b(e2, b['bucket'], False)
                    if b2 != None:
                            c2 = b2['categories']
                except Exception as ex:
                    r.append("malformed entry looking for bucket "
			+ b['bucket'] + " in user " + e['user'] + " " + str(ex))
                    break
                if b2 == None:
                    r.append("can't find bucket " + b['bucket']
			+ " in user " + e['user'])
                    continue
                for x in c:
                    try:
                        x2 = self.c2x(c2, x['category'], False)
                    except Exception as ex:
                        r.append("malformed entry looking for "
			    + x['category'] + " in bucket " + b['bucket']
			    + " user " + e['user'] + " " + str(ex))
                        break
                    usage_acc_validate_fields(r, x, x2, "entry: category "
			+ x['category'] + " bucket " + b['bucket']
			+ " in user " + e['user'])
        for s in self.results['summary']:
            c = s['categories']
            try:
                s2 = usage_acc_findsum2(results['summary'], s['user'], False)
            except Exception as ex:
                r.append("malformed summary looking for user " + e['user']
		    + " " + str(ex))
                break
            if s2 == None:
                r.append("missing summary for user " + e['user'] + " " + str(ex))
                continue
            try:
                c2 = s2['categories']
            except Exception as ex:
                r.append("malformed summary missing categories for user "
		    + e['user'] + " " + str(ex))
                break
            for x in c:
                try:
                    x2 = self.c2x(c2, x['category'], False)
                except Exception as ex:
                    r.append("malformed summary looking for "
			+ x['category'] + " user " + e['user'] + " " + str(ex))
                    break
                usage_acc_validate_fields(r, x, x2, "summary: category "
		    + x['category'] + " in user " + e['user'])
            x = s['total']
            try:
                x2 = s2['total']
            except Exception as ex:
                r.append("malformed summary looking for totals for user "
		    + e['user'] + " " + str(ex))
                break
            usage_acc_validate_fields(r, x, x2, "summary: totals for user" + e['user'])
        return r

def ignore_this_entry(cat, bucket, user, out, b_in, err):
    pass
class requestlog_queue():
    def __init__(self, add):
        self.q = Queue.Queue(1000)
        self.adder = add
    def handle_request_data(self, request, response, error=False):
        now = datetime.datetime.now()
	if error:
	    pass
	elif response.status < 200 or response.status >= 400:
	    error = True
        self.q.put(bunch.Bunch({'t': now, 'o': request, 'i': response, 'e': error}))
    def clear(self):
        with self.q.mutex:
            self.q.queue.clear()
    def log_and_clear(self, cat, bucket, user, add_entry = None):
        while not self.q.empty():
            j = self.q.get()
	    bytes_out = 0
            if 'Content-Length' in j.o.headers:
		bytes_out = int(j.o.headers['Content-Length'])
            bytes_in = 0
            if 'content-length' in j.i.msg.dict:
		bytes_in = int(j.i.msg.dict['content-length'])
            log.info('RL: %s %s %s bytes_out=%d bytes_in=%d failed=%r'
		% (cat, bucket, user, bytes_out, bytes_in, j.e))
	    if add_entry == None:
		add_entry = self.adder
	    add_entry(cat, bucket, user, bytes_out, bytes_in, j.e)

def create_presigned_url(conn, method, bucket_name, key_name, expiration):
    return conn.generate_url(expires_in=expiration,
        method=method,
        bucket=bucket_name,
        key=key_name,
        query_auth=True,
    )

def send_raw_http_request(conn, method, bucket_name, key_name, follow_redirects = False):
    url = create_presigned_url(conn, method, bucket_name, key_name, 3600)
    print url
    h = httplib2.Http()
    h.follow_redirects = follow_redirects
    return h.request(url, method)


def get_acl(key):
    """
    Helper function to get the xml acl from a key, ensuring that the xml
    version tag is removed from the acl response
    """
    raw_acl = key.get_xml_acl()

    def remove_version(string):
        return string.split(
            '<?xml version="1.0" encoding="UTF-8"?>'
        )[-1]

    def remove_newlines(string):
        return string.strip('\n')

    return remove_version(
        remove_newlines(raw_acl)
    )

def task(ctx, config):
    """
    Test radosgw-admin functionality against a running rgw instance.
    """
    global log

    # regions and config found from rgw task
    assert ctx.rgw.regions is not None, \
        "radosgw_admin task needs region(s) declared from the rgw task"
    regions = ctx.rgw.regions
    log.debug('regions are: %r', regions)

    assert ctx.rgw.config, \
        "radosgw_admin task needs a config passed from the rgw task"
    config = ctx.rgw.config
    log.debug('config is: %r', config)

    clients_from_config = config.keys()

    # choose first client as default
    client = clients_from_config[0]

    multi_region_run = rgw_utils.multi_region_enabled(ctx)
    if multi_region_run:
        client = rgw_utils.get_config_master_client(ctx, config, regions)

    log.debug('multi_region_run is: %r', multi_region_run)
    log.debug('master_client is: %r', client)

    # once the client is chosen, pull the host name and  assigned port out of
    # the role_endpoints that were assigned by the rgw task
    (remote_host, remote_port) = ctx.rgw.role_endpoints[client]

    realm = ctx.rgw.realm
    log.debug('radosgw-admin: realm %r', realm)

    ##
    user1='foo'
    user2='fud'
    subuser1='foo:foo1'
    subuser2='foo:foo2'
    display_name1='Foo'
    display_name2='Fud'
    email='foo@foo.com'
    email2='bar@bar.com'
    access_key='9te6NH5mcdcq0Tc5i8i1'
    secret_key='Ny4IOauQoL18Gp2zM7lC1vLmoawgqcYP/YGcWfXu'
    access_key2='p5YnriCv1nAtykxBrupQ'
    secret_key2='Q8Tk6Q/27hfbFSYdSkPtUqhqx1GgzvpXa4WARozh'
    swift_secret1='gpS2G9RREMrnbqlp29PP2D36kgPR1tm72n5fPYfL'
    swift_secret2='ri2VJQcKSYATOY6uaDUX7pxgkW+W1YmC6OCxPHwy'

    bucket_name='myfoo'
    bucket_name2='mybar'

    # connect to rgw
    connection = boto.s3.connection.S3Connection(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        is_secure=False,
        port=remote_port,
        host=remote_host,
        calling_format=boto.s3.connection.OrdinaryCallingFormat(),
        )
    connection2 = boto.s3.connection.S3Connection(
        aws_access_key_id=access_key2,
        aws_secret_access_key=secret_key2,
        is_secure=False,
        port=remote_port,
        host=remote_host,
        calling_format=boto.s3.connection.OrdinaryCallingFormat(),
        )

    acc = usage_acc()
    rl = requestlog_queue(acc.generate_make_entry())
    connection.set_request_hook(rl)
    connection2.set_request_hook(rl)

    # legend (test cases can be easily grep-ed out)
    # TESTCASE 'testname','object','method','operation','assertion'

    # TESTCASE 'usage-show0' 'usage' 'show' 'all usage' 'succeeds'
    (err, summary0) = rgwadmin(ctx, client, ['usage', 'show'], check_status=True)

    # TESTCASE 'info-nosuch','user','info','non-existent user','fails'
    (err, out) = rgwadmin(ctx, client, ['user', 'info', '--uid', user1])
    assert err

    # TESTCASE 'create-ok','user','create','w/all valid info','succeeds'
    (err, out) = rgwadmin(ctx, client, [
            'user', 'create',
            '--uid', user1,
            '--display-name', display_name1,
            '--email', email,
            '--access-key', access_key,
            '--secret', secret_key,
            '--max-buckets', '4'
            ],
            check_status=True)

    # TESTCASE 'duplicate email','user','create','existing user email','fails'
    (err, out) = rgwadmin(ctx, client, [
            'user', 'create',
            '--uid', user2,
            '--display-name', display_name2,
            '--email', email,
            ])
    assert err

    # TESTCASE 'info-existing','user','info','existing user','returns correct info'
    (err, out) = rgwadmin(ctx, client, ['user', 'info', '--uid', user1], check_status=True)
    assert out['user_id'] == user1
    assert out['email'] == email
    assert out['display_name'] == display_name1
    assert len(out['keys']) == 1
    assert out['keys'][0]['access_key'] == access_key
    assert out['keys'][0]['secret_key'] == secret_key
    assert not out['suspended']

    # this whole block should only be run if regions have been configured
    if multi_region_run:
        rgw_utils.radosgw_agent_sync_all(ctx)
        # post-sync, validate that user1 exists on the sync destination host
        for agent_client, c_config in ctx.radosgw_agent.config.iteritems():
            dest_client = c_config['dest']
            (err, out) = rgwadmin(ctx, dest_client, ['metadata', 'list', 'user'])
            (err, out) = rgwadmin(ctx, dest_client, ['user', 'info', '--uid', user1], check_status=True)
            assert out['user_id'] == user1
            assert out['email'] == email
            assert out['display_name'] == display_name1
            assert len(out['keys']) == 1
            assert out['keys'][0]['access_key'] == access_key
            assert out['keys'][0]['secret_key'] == secret_key
            assert not out['suspended']

        # compare the metadata between different regions, make sure it matches
        log.debug('compare the metadata between different regions, make sure it matches')
        for agent_client, c_config in ctx.radosgw_agent.config.iteritems():
            source_client = c_config['src']
            dest_client = c_config['dest']
            (err1, out1) = rgwadmin(ctx, source_client,
                ['metadata', 'get', 'user:{uid}'.format(uid=user1)], check_status=True)
            (err2, out2) = rgwadmin(ctx, dest_client,
                ['metadata', 'get', 'user:{uid}'.format(uid=user1)], check_status=True)
            assert out1 == out2

        # suspend a user on the master, then check the status on the destination
        log.debug('suspend a user on the master, then check the status on the destination')
        for agent_client, c_config in ctx.radosgw_agent.config.iteritems():
            source_client = c_config['src']
            dest_client = c_config['dest']
            (err, out) = rgwadmin(ctx, source_client, ['user', 'suspend', '--uid', user1])
            rgw_utils.radosgw_agent_sync_all(ctx)
            (err, out) = rgwadmin(ctx, dest_client, ['user', 'info', '--uid', user1], check_status=True)
            assert out['suspended']

        # delete a user on the master, then check that it's gone on the destination
        log.debug('delete a user on the master, then check that it\'s gone on the destination')
        for agent_client, c_config in ctx.radosgw_agent.config.iteritems():
            source_client = c_config['src']
            dest_client = c_config['dest']
            (err, out) = rgwadmin(ctx, source_client, ['user', 'rm', '--uid', user1], check_status=True)
            rgw_utils.radosgw_agent_sync_all(ctx)
            (err, out) = rgwadmin(ctx, source_client, ['user', 'info', '--uid', user1])
            assert out is None
            (err, out) = rgwadmin(ctx, dest_client, ['user', 'info', '--uid', user1])
            assert out is None

            # then recreate it so later tests pass
            (err, out) = rgwadmin(ctx, client, [
                'user', 'create',
                '--uid', user1,
                '--display-name', display_name1,
                '--email', email,
                '--access-key', access_key,
                '--secret', secret_key,
                '--max-buckets', '4'
                ],
                check_status=True)

        # now do the multi-region bucket tests
        log.debug('now do the multi-region bucket tests')

        # Create a second user for the following tests
        log.debug('Create a second user for the following tests')
        (err, out) = rgwadmin(ctx, client, [
            'user', 'create',
            '--uid', user2,
            '--display-name', display_name2,
            '--email', email2,
            '--access-key', access_key2,
            '--secret', secret_key2,
            '--max-buckets', '4'
            ],
            check_status=True)
        (err, out) = rgwadmin(ctx, client, ['user', 'info', '--uid', user2], check_status=True)
        assert out is not None

        # create a bucket and do a sync
        log.debug('create a bucket and do a sync')
        bucket = connection.create_bucket(bucket_name2)
        rgw_utils.radosgw_agent_sync_all(ctx)

        # compare the metadata for the bucket between different regions, make sure it matches
        log.debug('compare the metadata for the bucket between different regions, make sure it matches')
        for agent_client, c_config in ctx.radosgw_agent.config.iteritems():
            source_client = c_config['src']
            dest_client = c_config['dest']
            (err1, out1) = rgwadmin(ctx, source_client,
                ['metadata', 'get', 'bucket:{bucket_name}'.format(bucket_name=bucket_name2)],
                check_status=True)
            (err2, out2) = rgwadmin(ctx, dest_client,
                ['metadata', 'get', 'bucket:{bucket_name}'.format(bucket_name=bucket_name2)],
                check_status=True)
            log.debug('metadata 1 %r', out1)
            log.debug('metadata 2 %r', out2)
            assert out1 == out2

            # get the bucket.instance info and compare that
            src_bucket_id = out1['data']['bucket']['bucket_id']
            dest_bucket_id = out2['data']['bucket']['bucket_id']
            (err1, out1) = rgwadmin(ctx, source_client, ['metadata', 'get',
                'bucket.instance:{bucket_name}:{bucket_instance}'.format(
                bucket_name=bucket_name2,bucket_instance=src_bucket_id)],
                check_status=True)
            (err2, out2) = rgwadmin(ctx, dest_client, ['metadata', 'get',
                'bucket.instance:{bucket_name}:{bucket_instance}'.format(
                bucket_name=bucket_name2,bucket_instance=dest_bucket_id)],
                check_status=True)
            assert out1 == out2

        same_region = 0
        for agent_client, c_config in ctx.radosgw_agent.config.iteritems():
            source_client = c_config['src']
            dest_client = c_config['dest']

            source_region = rgw_utils.region_for_client(ctx, source_client)
            dest_region = rgw_utils.region_for_client(ctx, dest_client)

            # 301 is only returned for requests to something in a different region
            if source_region == dest_region:
                log.debug('301 is only returned for requests to something in a different region')
                same_region += 1
                continue

            # Attempt to create a new connection with user1 to the destination RGW
            log.debug('Attempt to create a new connection with user1 to the destination RGW')
            # and use that to attempt a delete (that should fail)

            (dest_remote_host, dest_remote_port) = ctx.rgw.role_endpoints[dest_client]
            connection_dest = boto.s3.connection.S3Connection(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                is_secure=False,
                port=dest_remote_port,
                host=dest_remote_host,
                calling_format=boto.s3.connection.OrdinaryCallingFormat(),
                )

            # this should fail
            r, content = send_raw_http_request(connection_dest, 'DELETE', bucket_name2, '', follow_redirects = False)
            assert r.status == 301

            # now delete the bucket on the source RGW and do another sync
            log.debug('now delete the bucket on the source RGW and do another sync')
            bucket.delete()
            rgw_utils.radosgw_agent_sync_all(ctx)

        if same_region == len(ctx.radosgw_agent.config):
            bucket.delete()
            rgw_utils.radosgw_agent_sync_all(ctx)

        # make sure that the bucket no longer exists in either region
        log.debug('make sure that the bucket no longer exists in either region')
        for agent_client, c_config in ctx.radosgw_agent.config.iteritems():
            source_client = c_config['src']
            dest_client = c_config['dest']
            (err1, out1) = rgwadmin(ctx, source_client, ['metadata', 'get',
                'bucket:{bucket_name}'.format(bucket_name=bucket_name2)])
            (err2, out2) = rgwadmin(ctx, dest_client, ['metadata', 'get',
                'bucket:{bucket_name}'.format(bucket_name=bucket_name2)])
            # Both of the previous calls should have errors due to requesting
            # metadata for non-existent buckets
            assert err1
            assert err2

        # create a bucket and then sync it
        log.debug('create a bucket and then sync it')
        bucket = connection.create_bucket(bucket_name2)
        rgw_utils.radosgw_agent_sync_all(ctx)

        # compare the metadata for the bucket between different regions, make sure it matches
        log.debug('compare the metadata for the bucket between different regions, make sure it matches')
        for agent_client, c_config in ctx.radosgw_agent.config.iteritems():
            source_client = c_config['src']
            dest_client = c_config['dest']
            (err1, out1) = rgwadmin(ctx, source_client,
                ['metadata', 'get', 'bucket:{bucket_name}'.format(bucket_name=bucket_name2)],
                check_status=True)
            (err2, out2) = rgwadmin(ctx, dest_client,
                ['metadata', 'get', 'bucket:{bucket_name}'.format(bucket_name=bucket_name2)],
                check_status=True)
            assert out1 == out2

        # Now delete the bucket and recreate it with a different user
        log.debug('Now delete the bucket and recreate it with a different user')
        # within the same window of time and then sync.
        bucket.delete()
        bucket = connection2.create_bucket(bucket_name2)
        rgw_utils.radosgw_agent_sync_all(ctx)

        # compare the metadata for the bucket between different regions, make sure it matches
        log.debug('compare the metadata for the bucket between different regions, make sure it matches')
        # user2 should own the bucket in both regions
        for agent_client, c_config in ctx.radosgw_agent.config.iteritems():
            source_client = c_config['src']
            dest_client = c_config['dest']
            (err1, out1) = rgwadmin(ctx, source_client,
                ['metadata', 'get', 'bucket:{bucket_name}'.format(bucket_name=bucket_name2)],
                check_status=True)
            (err2, out2) = rgwadmin(ctx, dest_client,
                ['metadata', 'get', 'bucket:{bucket_name}'.format(bucket_name=bucket_name2)],
                check_status=True)
            assert out1 == out2
            assert out1['data']['owner'] == user2
            assert out1['data']['owner'] != user1

        # now we're going to use this bucket to test meta-data update propagation
        log.debug('now we\'re going to use this bucket to test meta-data update propagation')
        for agent_client, c_config in ctx.radosgw_agent.config.iteritems():
            source_client = c_config['src']
            dest_client = c_config['dest']

            # get the metadata so we can tweak it
            log.debug('get the metadata so we can tweak it')
            (err, orig_data) = rgwadmin(ctx, source_client,
                ['metadata', 'get', 'bucket:{bucket_name}'.format(bucket_name=bucket_name2)],
                check_status=True)

            # manually edit mtime for this bucket to be 300 seconds in the past
            log.debug('manually edit mtime for this bucket to be 300 seconds in the past')
            new_data = copy.deepcopy(orig_data)
            mtime = datetime.datetime.strptime(orig_data['mtime'], "%Y-%m-%d %H:%M:%S.%fZ") - datetime.timedelta(300)
            new_data['mtime'] =  unicode(mtime.strftime("%Y-%m-%d %H:%M:%S.%fZ"))
            log.debug("new mtime ", mtime)
            assert new_data != orig_data
            (err, out) = rgwadmin(ctx, source_client,
                ['metadata', 'put', 'bucket:{bucket_name}'.format(bucket_name=bucket_name2)],
                stdin=StringIO(json.dumps(new_data)),
                check_status=True)

            # get the metadata and make sure that the 'put' worked
            log.debug('get the metadata and make sure that the \'put\' worked')
            (err, out) = rgwadmin(ctx, source_client,
                ['metadata', 'get', 'bucket:{bucket_name}'.format(bucket_name=bucket_name2)],
                check_status=True)
            assert out == new_data

            # sync to propagate the new metadata
            log.debug('sync to propagate the new metadata')
            rgw_utils.radosgw_agent_sync_all(ctx)

            # get the metadata from the dest and compare it to what we just set
            log.debug('get the metadata from the dest and compare it to what we just set')
            # and what the source region has.
            (err1, out1) = rgwadmin(ctx, source_client,
                ['metadata', 'get', 'bucket:{bucket_name}'.format(bucket_name=bucket_name2)],
                check_status=True)
            (err2, out2) = rgwadmin(ctx, dest_client,
                ['metadata', 'get', 'bucket:{bucket_name}'.format(bucket_name=bucket_name2)],
                check_status=True)
            # yeah for the transitive property
            assert out1 == out2
            assert out1 == new_data

        # now we delete the bucket
        log.debug('now we delete the bucket')
        bucket.delete()

        log.debug('sync to propagate the deleted bucket')
        rgw_utils.radosgw_agent_sync_all(ctx)

        # Delete user2 as later tests do not expect it to exist.
        # Verify that it is gone on both regions
        for agent_client, c_config in ctx.radosgw_agent.config.iteritems():
            source_client = c_config['src']
            dest_client = c_config['dest']
            (err, out) = rgwadmin(ctx, source_client,
                ['user', 'rm', '--uid', user2], check_status=True)
            rgw_utils.radosgw_agent_sync_all(ctx)
            # The two 'user info' calls should fail and not return any data
            # since we just deleted this user.
            (err, out) = rgwadmin(ctx, source_client, ['user', 'info', '--uid', user2])
            assert out is None
            (err, out) = rgwadmin(ctx, dest_client, ['user', 'info', '--uid', user2])
            assert out is None

        # Test data sync

        # First create a bucket for data sync test purpose
        bucket = connection.create_bucket(bucket_name + 'data')

        # Create a tiny file and check if in sync
        for agent_client, c_config in ctx.radosgw_agent.config.iteritems():
            if c_config.get('metadata-only'):
                continue

            for full in (True, False):
                source_client = c_config['src']
                dest_client = c_config['dest']
                k = boto.s3.key.Key(bucket)
                k.key = 'tiny_file'
                k.set_contents_from_string("123456789")
                safety_window = rgw_utils.radosgw_data_log_window(ctx, source_client)
                time.sleep(safety_window)
                rgw_utils.radosgw_agent_sync_all(ctx, data=True, full=full)
                (dest_host, dest_port) = ctx.rgw.role_endpoints[dest_client]
                dest_connection = boto.s3.connection.S3Connection(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    is_secure=False,
                    port=dest_port,
                    host=dest_host,
                    calling_format=boto.s3.connection.OrdinaryCallingFormat(),
                )
                dest_k = dest_connection.get_bucket(bucket_name + 'data').get_key('tiny_file')
                assert k.get_contents_as_string() == dest_k.get_contents_as_string()

                # check that deleting it removes it from the dest zone
                k.delete()
                time.sleep(safety_window)
                # full sync doesn't handle deleted objects yet
                rgw_utils.radosgw_agent_sync_all(ctx, data=True, full=False)

                dest_bucket = dest_connection.get_bucket(bucket_name + 'data')
                dest_k = dest_bucket.get_key('tiny_file')
                assert dest_k == None, 'object not deleted from destination zone'

        # finally we delete the bucket
        bucket.delete()

        bucket = connection.create_bucket(bucket_name + 'data2')
        for agent_client, c_config in ctx.radosgw_agent.config.iteritems():
            if c_config.get('metadata-only'):
                continue

            for full in (True, False):
                source_client = c_config['src']
                dest_client = c_config['dest']
                (dest_host, dest_port) = ctx.rgw.role_endpoints[dest_client]
                dest_connection = boto.s3.connection.S3Connection(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    is_secure=False,
                    port=dest_port,
                    host=dest_host,
                    calling_format=boto.s3.connection.OrdinaryCallingFormat(),
                )
                for i in range(20):
                    k = boto.s3.key.Key(bucket)
                    k.key = 'tiny_file_' + str(i)
                    k.set_contents_from_string(str(i) * 100)

                safety_window = rgw_utils.radosgw_data_log_window(ctx, source_client)
                time.sleep(safety_window)
                rgw_utils.radosgw_agent_sync_all(ctx, data=True, full=full)

                for i in range(20):
                    dest_k = dest_connection.get_bucket(bucket_name + 'data2').get_key('tiny_file_' + str(i))
                    assert (str(i) * 100) == dest_k.get_contents_as_string()
                    k = boto.s3.key.Key(bucket)
                    k.key = 'tiny_file_' + str(i)
                    k.delete()

                # check that deleting removes the objects from the dest zone
                time.sleep(safety_window)
                # full sync doesn't delete deleted objects yet
                rgw_utils.radosgw_agent_sync_all(ctx, data=True, full=False)

                for i in range(20):
                    dest_bucket = dest_connection.get_bucket(bucket_name + 'data2')
                    dest_k = dest_bucket.get_key('tiny_file_' + str(i))
                    assert dest_k == None, 'object %d not deleted from destination zone' % i
        bucket.delete()

    # end of 'if multi_region_run:'

    rl.log_and_clear("(after-multi-region-run)", '-', '-', ignore_this_entry)

    # TESTCASE 'suspend-ok','user','suspend','active user','succeeds'
    (err, out) = rgwadmin(ctx, client, ['user', 'suspend', '--uid', user1],
        check_status=True)

    # TESTCASE 'suspend-suspended','user','suspend','suspended user','succeeds w/advisory'
    (err, out) = rgwadmin(ctx, client, ['user', 'info', '--uid', user1], check_status=True)
    assert out['suspended']

    # TESTCASE 're-enable','user','enable','suspended user','succeeds'
    (err, out) = rgwadmin(ctx, client, ['user', 'enable', '--uid', user1], check_status=True)

    # TESTCASE 'info-re-enabled','user','info','re-enabled user','no longer suspended'
    (err, out) = rgwadmin(ctx, client, ['user', 'info', '--uid', user1], check_status=True)
    assert not out['suspended']

    # TESTCASE 'add-keys','key','create','w/valid info','succeeds'
    (err, out) = rgwadmin(ctx, client, [
            'key', 'create', '--uid', user1,
            '--access-key', access_key2, '--secret', secret_key2,
            ], check_status=True)

    # TESTCASE 'info-new-key','user','info','after key addition','returns all keys'
    (err, out) = rgwadmin(ctx, client, ['user', 'info', '--uid', user1],
        check_status=True)
    assert len(out['keys']) == 2
    assert out['keys'][0]['access_key'] == access_key2 or out['keys'][1]['access_key'] == access_key2
    assert out['keys'][0]['secret_key'] == secret_key2 or out['keys'][1]['secret_key'] == secret_key2

    # TESTCASE 'rm-key','key','rm','newly added key','succeeds, key is removed'
    (err, out) = rgwadmin(ctx, client, [
            'key', 'rm', '--uid', user1,
            '--access-key', access_key2,
            ], check_status=True)
    assert len(out['keys']) == 1
    assert out['keys'][0]['access_key'] == access_key
    assert out['keys'][0]['secret_key'] == secret_key

    # TESTCASE 'add-swift-key','key','create','swift key','succeeds'
    subuser_access = 'full'
    subuser_perm = 'full-control'

    (err, out) = rgwadmin(ctx, client, [
            'subuser', 'create', '--subuser', subuser1,
            '--access', subuser_access
            ], check_status=True)

    # TESTCASE 'add-swift-key','key','create','swift key','succeeds'
    (err, out) = rgwadmin(ctx, client, [
            'subuser', 'modify', '--subuser', subuser1,
            '--secret', swift_secret1,
            '--key-type', 'swift',
            ], check_status=True)

    # TESTCASE 'subuser-perm-mask', 'subuser', 'info', 'test subuser perm mask durability', 'succeeds'
    (err, out) = rgwadmin(ctx, client, ['user', 'info', '--uid', user1])

    assert out['subusers'][0]['permissions'] == subuser_perm

    # TESTCASE 'info-swift-key','user','info','after key addition','returns all keys'
    (err, out) = rgwadmin(ctx, client, ['user', 'info', '--uid', user1], check_status=True)
    assert len(out['swift_keys']) == 1
    assert out['swift_keys'][0]['user'] == subuser1
    assert out['swift_keys'][0]['secret_key'] == swift_secret1

    # TESTCASE 'add-swift-subuser','key','create','swift sub-user key','succeeds'
    (err, out) = rgwadmin(ctx, client, [
            'subuser', 'create', '--subuser', subuser2,
            '--secret', swift_secret2,
            '--key-type', 'swift',
            ], check_status=True)

    # TESTCASE 'info-swift-subuser','user','info','after key addition','returns all sub-users/keys'
    (err, out) = rgwadmin(ctx, client, ['user', 'info', '--uid', user1], check_status=True)
    assert len(out['swift_keys']) == 2
    assert out['swift_keys'][0]['user'] == subuser2 or out['swift_keys'][1]['user'] == subuser2
    assert out['swift_keys'][0]['secret_key'] == swift_secret2 or out['swift_keys'][1]['secret_key'] == swift_secret2

    # TESTCASE 'rm-swift-key1','key','rm','subuser','succeeds, one key is removed'
    (err, out) = rgwadmin(ctx, client, [
            'key', 'rm', '--subuser', subuser1,
            '--key-type', 'swift',
            ], check_status=True)
    assert len(out['swift_keys']) == 1

    # TESTCASE 'rm-subuser','subuser','rm','subuser','success, subuser is removed'
    (err, out) = rgwadmin(ctx, client, [
            'subuser', 'rm', '--subuser', subuser1,
            ], check_status=True)
    assert len(out['subusers']) == 1

    # TESTCASE 'rm-subuser-with-keys','subuser','rm','subuser','succeeds, second subser and key is removed'
    (err, out) = rgwadmin(ctx, client, [
            'subuser', 'rm', '--subuser', subuser2,
            '--key-type', 'swift', '--purge-keys',
            ], check_status=True)
    assert len(out['swift_keys']) == 0
    assert len(out['subusers']) == 0

    # TESTCASE 'bucket-stats','bucket','stats','no session/buckets','succeeds, empty list'
    (err, out) = rgwadmin(ctx, client, ['bucket', 'stats', '--uid', user1],
        check_status=True)
    assert len(out) == 0

    if multi_region_run:
        rgw_utils.radosgw_agent_sync_all(ctx)

    # TESTCASE 'bucket-stats2','bucket','stats','no buckets','succeeds, empty list'
    (err, out) = rgwadmin(ctx, client, ['bucket', 'list', '--uid', user1], check_status=True)
    assert len(out) == 0

    # create a first bucket
    bucket = connection.create_bucket(bucket_name)

    rl.log_and_clear("create_bucket", bucket_name, user1)

    # TESTCASE 'bucket-list','bucket','list','one bucket','succeeds, expected list'
    (err, out) = rgwadmin(ctx, client, ['bucket', 'list', '--uid', user1], check_status=True)
    assert len(out) == 1
    assert out[0] == bucket_name

    bucket_list = connection.get_all_buckets()
    assert len(bucket_list) == 1
    assert bucket_list[0].name == bucket_name

    rl.log_and_clear("list_buckets", '', user1)

    # TESTCASE 'bucket-list-all','bucket','list','all buckets','succeeds, expected list'
    (err, out) = rgwadmin(ctx, client, ['bucket', 'list'], check_status=True)
    assert len(out) >= 1
    assert bucket_name in out;

    # TESTCASE 'max-bucket-limit,'bucket','create','4 buckets','5th bucket fails due to max buckets == 4'
    bucket2 = connection.create_bucket(bucket_name + '2')
    rl.log_and_clear("create_bucket", bucket_name + '2', user1)
    bucket3 = connection.create_bucket(bucket_name + '3')
    rl.log_and_clear("create_bucket", bucket_name + '3', user1)
    bucket4 = connection.create_bucket(bucket_name + '4')
    rl.log_and_clear("create_bucket", bucket_name + '4', user1)
    # the 5th should fail.
    failed = False
    try:
        connection.create_bucket(bucket_name + '5')
    except Exception:
        failed = True
    assert failed
    rl.log_and_clear("create_bucket", bucket_name + '5', user1)

    # delete the buckets
    bucket2.delete()
    rl.log_and_clear("delete_bucket", bucket_name + '2', user1)
    bucket3.delete()
    rl.log_and_clear("delete_bucket", bucket_name + '3', user1)
    bucket4.delete()
    rl.log_and_clear("delete_bucket", bucket_name + '4', user1)

    # TESTCASE 'bucket-stats3','bucket','stats','new empty bucket','succeeds, empty list'
    (err, out) = rgwadmin(ctx, client, [
            'bucket', 'stats', '--bucket', bucket_name], check_status=True)
    assert out['owner'] == user1
    bucket_id = out['id']

    # TESTCASE 'bucket-stats4','bucket','stats','new empty bucket','succeeds, expected bucket ID'
    (err, out) = rgwadmin(ctx, client, ['bucket', 'stats', '--uid', user1], check_status=True)
    assert len(out) == 1
    assert out[0]['id'] == bucket_id    # does it return the same ID twice in a row?

    # use some space
    key = boto.s3.key.Key(bucket)
    key.set_contents_from_string('one')
    rl.log_and_clear("put_obj", bucket_name, user1)

    # TESTCASE 'bucket-stats5','bucket','stats','after creating key','succeeds, lists one non-empty object'
    (err, out) = rgwadmin(ctx, client, [
            'bucket', 'stats', '--bucket', bucket_name], check_status=True)
    assert out['id'] == bucket_id
    assert out['usage']['rgw.main']['num_objects'] == 1
    assert out['usage']['rgw.main']['size_kb'] > 0

    # reclaim it
    key.delete()
    rl.log_and_clear("delete_obj", bucket_name, user1)

    # TESTCASE 'bucket unlink', 'bucket', 'unlink', 'unlink bucket from user', 'fails', 'access denied error'
    (err, out) = rgwadmin(ctx, client,
        ['bucket', 'unlink', '--uid', user1, '--bucket', bucket_name],
        check_status=True)

    # create a second user to link the bucket to
    (err, out) = rgwadmin(ctx, client, [
            'user', 'create',
            '--uid', user2,
            '--display-name', display_name2,
            '--access-key', access_key2,
            '--secret', secret_key2,
            '--max-buckets', '1',
            ],
            check_status=True)

    # try creating an object with the first user before the bucket is relinked
    denied = False
    key = boto.s3.key.Key(bucket)

    try:
        key.set_contents_from_string('two')
    except boto.exception.S3ResponseError:
        denied = True

    assert not denied
    rl.log_and_clear("put_obj", bucket_name, user1)

    # delete the object
    key.delete()
    rl.log_and_clear("delete_obj", bucket_name, user1)

    # link the bucket to another user
    (err, out) = rgwadmin(ctx, client, ['metadata', 'get', 'bucket:{n}'.format(n=bucket_name)],
        check_status=True)

    bucket_data = out['data']
    assert bucket_data['bucket']['name'] == bucket_name

    bucket_id = bucket_data['bucket']['bucket_id']

    # link the bucket to another user
    (err, out) = rgwadmin(ctx, client, ['bucket', 'link', '--uid', user2, '--bucket', bucket_name, '--bucket-id', bucket_id],
        check_status=True)

    # try to remove user, should fail (has a linked bucket)
    (err, out) = rgwadmin(ctx, client, ['user', 'rm', '--uid', user2])
    assert err

    # TESTCASE 'bucket unlink', 'bucket', 'unlink', 'unlink bucket from user', 'succeeds, bucket unlinked'
    (err, out) = rgwadmin(ctx, client, ['bucket', 'unlink', '--uid', user2, '--bucket', bucket_name],
        check_status=True)

    # relink the bucket to the first user and delete the second user
    (err, out) = rgwadmin(ctx, client,
        ['bucket', 'link', '--uid', user1, '--bucket', bucket_name, '--bucket-id', bucket_id],
        check_status=True)

    (err, out) = rgwadmin(ctx, client, ['user', 'rm', '--uid', user2],
        check_status=True)

    # TESTCASE 'object-rm', 'object', 'rm', 'remove object', 'succeeds, object is removed'

    # upload an object
    object_name = 'four'
    key = boto.s3.key.Key(bucket, object_name)
    key.set_contents_from_string(object_name)
    rl.log_and_clear("put_obj", bucket_name, user1)

    # fetch it too (for usage stats presently)
    s = key.get_contents_as_string()
    rl.log_and_clear("get_obj", bucket_name, user1)
    assert s == object_name
    # list bucket too (for usage stats presently)
    keys = list(bucket.list())
    rl.log_and_clear("list_bucket", bucket_name, user1)
    assert len(keys) == 1
    assert keys[0].name == object_name

    # now delete it
    (err, out) = rgwadmin(ctx, client,
        ['object', 'rm', '--bucket', bucket_name, '--object', object_name],
        check_status=True)

    # TESTCASE 'bucket-stats6','bucket','stats','after deleting key','succeeds, lists one no objects'
    (err, out) = rgwadmin(ctx, client, [
            'bucket', 'stats', '--bucket', bucket_name],
            check_status=True)
    assert out['id'] == bucket_id
    assert out['usage']['rgw.main']['num_objects'] == 0

    # list log objects
    # TESTCASE 'log-list','log','list','after activity','succeeds, lists one no objects'
    (err, out) = rgwadmin(ctx, client, ['log', 'list'], check_status=True)
    assert len(out) > 0

    for obj in out:
        # TESTCASE 'log-show','log','show','after activity','returns expected info'
        if obj[:4] == 'meta' or obj[:4] == 'data' or obj[:18] == 'obj_delete_at_hint':
            continue

        (err, rgwlog) = rgwadmin(ctx, client, ['log', 'show', '--object', obj],
            check_status=True)
        assert len(rgwlog) > 0

        # exempt bucket_name2 from checking as it was only used for multi-region tests
        assert rgwlog['bucket'].find(bucket_name) == 0 or rgwlog['bucket'].find(bucket_name2) == 0
        assert rgwlog['bucket'] != bucket_name or rgwlog['bucket_id'] == bucket_id
        assert rgwlog['bucket_owner'] == user1 or rgwlog['bucket'] == bucket_name + '5' or rgwlog['bucket'] == bucket_name2
        for entry in rgwlog['log_entries']:
            log.debug('checking log entry: ', entry)
            assert entry['bucket'] == rgwlog['bucket']
            possible_buckets = [bucket_name + '5', bucket_name2]
            user = entry['user']
            assert user == user1 or user.endswith('system-user') or \
                rgwlog['bucket'] in possible_buckets

        # TESTCASE 'log-rm','log','rm','delete log objects','succeeds'
        (err, out) = rgwadmin(ctx, client, ['log', 'rm', '--object', obj],
            check_status=True)

    # TODO: show log by bucket+date

    # TESTCASE 'user-suspend2','user','suspend','existing user','succeeds'
    (err, out) = rgwadmin(ctx, client, ['user', 'suspend', '--uid', user1],
        check_status=True)

    # TESTCASE 'user-suspend3','user','suspend','suspended user','cannot write objects'
    denied = False
    try:
        key = boto.s3.key.Key(bucket)
        key.set_contents_from_string('five')
    except boto.exception.S3ResponseError as e:
        denied = True
        assert e.status == 403

    assert denied
    rl.log_and_clear("put_obj", bucket_name, user1)

    # TESTCASE 'user-renable2','user','enable','suspended user','succeeds'
    (err, out) = rgwadmin(ctx, client, ['user', 'enable', '--uid', user1],
        check_status=True)

    # TESTCASE 'user-renable3','user','enable','reenabled user','can write objects'
    key = boto.s3.key.Key(bucket)
    key.set_contents_from_string('six')
    rl.log_and_clear("put_obj", bucket_name, user1)

    # TESTCASE 'gc-list', 'gc', 'list', 'get list of objects ready for garbage collection'

    # create an object large enough to be split into multiple parts
    test_string = 'foo'*10000000

    big_key = boto.s3.key.Key(bucket)
    big_key.set_contents_from_string(test_string)
    rl.log_and_clear("put_obj", bucket_name, user1)

    # now delete the head
    big_key.delete()
    rl.log_and_clear("delete_obj", bucket_name, user1)

    # wait a bit to give the garbage collector time to cycle
    time.sleep(15)

    (err, out) = rgwadmin(ctx, client, ['gc', 'list'])

    assert len(out) > 0

    # TESTCASE 'gc-process', 'gc', 'process', 'manually collect garbage'
    (err, out) = rgwadmin(ctx, client, ['gc', 'process'], check_status=True)

    #confirm
    (err, out) = rgwadmin(ctx, client, ['gc', 'list'])

    assert len(out) == 0

    # TESTCASE 'rm-user-buckets','user','rm','existing user','fails, still has buckets'
    (err, out) = rgwadmin(ctx, client, ['user', 'rm', '--uid', user1])
    assert err

    # delete should fail because ``key`` still exists
    try:
        bucket.delete()
    except boto.exception.S3ResponseError as e:
        assert e.status == 409
    rl.log_and_clear("delete_bucket", bucket_name, user1)

    key.delete()
    rl.log_and_clear("delete_obj", bucket_name, user1)
    bucket.delete()
    rl.log_and_clear("delete_bucket", bucket_name, user1)

    # TESTCASE 'policy', 'bucket', 'policy', 'get bucket policy', 'returns S3 policy'
    bucket = connection.create_bucket(bucket_name)
    rl.log_and_clear("create_bucket", bucket_name, user1)

    # create an object
    key = boto.s3.key.Key(bucket)
    key.set_contents_from_string('seven')
    rl.log_and_clear("put_obj", bucket_name, user1)

    # should be private already but guarantee it
    key.set_acl('private')
    rl.log_and_clear("put_acls", bucket_name, user1)

    (err, out) = rgwadmin(ctx, client,
        ['policy', '--bucket', bucket.name, '--object', key.key],
        check_status=True, format='xml')

    acl = get_acl(key)
    rl.log_and_clear("get_acls", bucket_name, user1)

    assert acl == out.strip('\n')

    # add another grantee by making the object public read
    key.set_acl('public-read')
    rl.log_and_clear("put_acls", bucket_name, user1)

    (err, out) = rgwadmin(ctx, client,
        ['policy', '--bucket', bucket.name, '--object', key.key],
        check_status=True, format='xml')

    acl = get_acl(key)
    rl.log_and_clear("get_acls", bucket_name, user1)

    assert acl == out.strip('\n')

    # TESTCASE 'rm-bucket', 'bucket', 'rm', 'bucket with objects', 'succeeds'
    bucket = connection.create_bucket(bucket_name)
    rl.log_and_clear("create_bucket", bucket_name, user1)
    key_name = ['eight', 'nine', 'ten', 'eleven']
    for i in range(4):
        key = boto.s3.key.Key(bucket)
        key.set_contents_from_string(key_name[i])
    rl.log_and_clear("put_obj", bucket_name, user1)

    (err, out) = rgwadmin(ctx, client,
        ['bucket', 'rm', '--bucket', bucket_name, '--purge-objects'],
        check_status=True)

    # TESTCASE 'caps-add', 'caps', 'add', 'add user cap', 'succeeds'
    caps='user=read'
    (err, out) = rgwadmin(ctx, client, ['caps', 'add', '--uid', user1, '--caps', caps])

    assert out['caps'][0]['perm'] == 'read'

    # TESTCASE 'caps-rm', 'caps', 'rm', 'remove existing cap from user', 'succeeds'
    (err, out) = rgwadmin(ctx, client, ['caps', 'rm', '--uid', user1, '--caps', caps])

    assert not out['caps']

    # TESTCASE 'rm-user','user','rm','existing user','fails, still has buckets'
    bucket = connection.create_bucket(bucket_name)
    rl.log_and_clear("create_bucket", bucket_name, user1)
    key = boto.s3.key.Key(bucket)

    (err, out) = rgwadmin(ctx, client, ['user', 'rm', '--uid', user1])
    assert err

    # TESTCASE 'rm-user2', 'user', 'rm', 'user with data', 'succeeds'
    bucket = connection.create_bucket(bucket_name)
    rl.log_and_clear("create_bucket", bucket_name, user1)
    key = boto.s3.key.Key(bucket)
    key.set_contents_from_string('twelve')
    rl.log_and_clear("put_obj", bucket_name, user1)

    time.sleep(35)

    # need to wait for all usage data to get flushed, should take up to 30 seconds
    timestamp = time.time()
    while time.time() - timestamp <= (2 * 60):      # wait up to 20 minutes
        (err, out) = rgwadmin(ctx, client, ['usage', 'show', '--categories', 'delete_obj'])  # one of the operations we did is delete_obj, should be present.
        if get_user_successful_ops(out, user1) > 0:
            break
        time.sleep(1)

    assert time.time() - timestamp <= (20 * 60)

    # TESTCASE 'usage-show' 'usage' 'show' 'all usage' 'succeeds'
    (err, out) = rgwadmin(ctx, client, ['usage', 'show'], check_status=True)
    assert len(out['entries']) > 0
    assert len(out['summary']) > 0

    r = acc.compare_results(out)
    if len(r) != 0:
        sys.stderr.write(("\n".join(r))+"\n")
        assert(len(r) == 0)

    user_summary = get_user_summary(out, user1)

    total = user_summary['total']
    assert total['successful_ops'] > 0

    # TESTCASE 'usage-show2' 'usage' 'show' 'user usage' 'succeeds'
    (err, out) = rgwadmin(ctx, client, ['usage', 'show', '--uid', user1],
        check_status=True)
    assert len(out['entries']) > 0
    assert len(out['summary']) > 0
    user_summary = out['summary'][0]
    for entry in user_summary['categories']:
        assert entry['successful_ops'] > 0
    assert user_summary['user'] == user1

    # TESTCASE 'usage-show3' 'usage' 'show' 'user usage categories' 'succeeds'
    test_categories = ['create_bucket', 'put_obj', 'delete_obj', 'delete_bucket']
    for cat in test_categories:
        (err, out) = rgwadmin(ctx, client, ['usage', 'show', '--uid', user1, '--categories', cat],
            check_status=True)
        assert len(out['summary']) > 0
        user_summary = out['summary'][0]
        assert user_summary['user'] == user1
        assert len(user_summary['categories']) == 1
        entry = user_summary['categories'][0]
        assert entry['category'] == cat
        assert entry['successful_ops'] > 0

    # should be all through with connection. (anything using connection
    #  should be BEFORE the usage stuff above.)
    rl.log_and_clear("(before-close)", '-', '-', ignore_this_entry)
    connection.close()
    connection = None

    # the usage flush interval is 30 seconds, wait that much an then some
    # to make sure everything has been flushed
    time.sleep(35)

    # TESTCASE 'usage-trim' 'usage' 'trim' 'user usage' 'succeeds, usage removed'
    (err, out) = rgwadmin(ctx, client, ['usage', 'trim', '--uid', user1],
        check_status=True)
    (err, out) = rgwadmin(ctx, client, ['usage', 'show', '--uid', user1],
        check_status=True)
    assert len(out['entries']) == 0
    assert len(out['summary']) == 0

    (err, out) = rgwadmin(ctx, client,
        ['user', 'rm', '--uid', user1, '--purge-data' ],
        check_status=True)

    # TESTCASE 'rm-user3','user','rm','deleted user','fails'
    (err, out) = rgwadmin(ctx, client, ['user', 'info', '--uid', user1])
    assert err

    # TESTCASE 'zone-info', 'zone', 'get', 'get zone info', 'succeeds, has default placement rule'
    #

    if realm is None:
        (err, out) = rgwadmin(ctx, client, ['zone', 'get','--rgw-zone','default'])
    else:
        (err, out) = rgwadmin(ctx, client, ['zone', 'get'])
    orig_placement_pools = len(out['placement_pools'])

    # removed this test, it is not correct to assume that zone has default placement, it really
    # depends on how we set it up before
    #
    # assert len(out) > 0
    # assert len(out['placement_pools']) == 1

    # default_rule = out['placement_pools'][0]
    # assert default_rule['key'] == 'default-placement'

    rule={'key': 'new-placement', 'val': {'data_pool': '.rgw.buckets.2', 'index_pool': '.rgw.buckets.index.2'}}

    out['placement_pools'].append(rule)

    (err, out) = rgwadmin(ctx, client, ['zone', 'set'],
        stdin=StringIO(json.dumps(out)),
        check_status=True)

    if realm is None:
        (err, out) = rgwadmin(ctx, client, ['zone', 'get','--rgw-zone','default'])
    else:
        (err, out) = rgwadmin(ctx, client, ['zone', 'get'])
    assert len(out) > 0
    assert len(out['placement_pools']) == orig_placement_pools + 1

    zonecmd = ['zone', 'placement', 'rm']
    if realm is None:
	zonecmd.extend(['--rgw-zone', 'default'])
    zonecmd.extend(['--placement-id', 'new-placement'])

    (err, out) = rgwadmin(ctx, client, zonecmd, check_status=True)

import sys
from tasks.radosgw_admin import task
from teuthology.config import config
from teuthology.orchestra import cluster, remote
import argparse;

def main():
    if len(sys.argv) > 1:
	host = sys.argv[1]
    client0 = remote.Remote('squidly@%s' % (host))
    ctx = config
    ctx.cluster=cluster.Cluster(remotes=[(client0,
     [ 'ceph.client.rgw.%s' % (host),  ]),])

    ctx.rgw = argparse.Namespace()
    endpoints = {}
    endpoints['ceph.client.rgw.%s' % host] = (host, 80)
    ctx.rgw.role_endpoints = endpoints
    ctx.rgw.realm = None
    ctx.rgw.regions = {'region0': { 'api name': 'api1',
	    'is master': True, 'master zone': 'r0z0',
	    'zones': ['r0z0', 'r0z1'] }}
    ctx.rgw.config = {'ceph.client.rgw.%s' % host: {'system user': {'name': '%s-system-user' % host}}}
    task(config, None)
    exit()

if __name__ == '__main__':
    main()
