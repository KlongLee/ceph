import argparse
import json
import logging
import subprocess
import yaml
import re
import collections
import os
import time
import requests
import urllib

import teuthology
from . import misc
from . import provision
from .config import config
from .lockstatus import get_status

log = logging.getLogger(__name__)
# Don't need to see connection pool INFO messages
logging.getLogger("requests.packages.urllib3.connectionpool").setLevel(
    logging.WARNING)

is_vpm = lambda name: 'vpm' in name


def main(ctx):
    if ctx.verbose:
        teuthology.log.setLevel(logging.DEBUG)

    misc.read_config(ctx)

    ret = 0
    user = ctx.owner
    machines = [misc.canonicalize_hostname(m, user=False)
                for m in ctx.machines]
    machines_to_update = []

    if ctx.targets:
        try:
            with file(ctx.targets) as f:
                g = yaml.safe_load_all(f)
                for new in g:
                    if 'targets' in new:
                        for t in new['targets'].iterkeys():
                            machines.append(t)
        except IOError as e:
            raise argparse.ArgumentTypeError(str(e))

    if ctx.f:
        assert ctx.lock or ctx.unlock, \
            '-f is only supported by --lock and --unlock'
    if machines:
        assert ctx.lock or ctx.unlock or ctx.list or ctx.list_targets \
            or ctx.update, \
            'machines cannot be specified with that operation'
    else:
        assert ctx.num_to_lock or ctx.list or ctx.list_targets or \
            ctx.summary or ctx.brief, \
            'machines must be specified for that operation'
    if ctx.all:
        assert ctx.list or ctx.list_targets or ctx.brief, \
            '--all can only be used with --list, --list-targets, and --brief'
        assert ctx.owner is None, \
            '--all and --owner are mutually exclusive'
        assert not machines, \
            '--all and listing specific machines are incompatible'
    if ctx.num_to_lock:
        assert ctx.machine_type, \
            'must specify machine type to lock'

    if ctx.brief or ctx.list or ctx.list_targets:
        assert ctx.desc is None, '--desc does nothing with --list/--brief'

        if machines:
            statuses = []
            for machine in machines:
                machine = misc.canonicalize_hostname(machine)
                status = get_status(machine)
                if status:
                    statuses.append(status)
                else:
                    log.error("Lockserver doesn't know about machine: %s" %
                              machine)
            # Delete this variable to avoid linter errors when we redefine it
            # in a list comprehension below
            del machine
        else:
            statuses = list_locks()
        vmachines = []

        for vmachine in statuses:
            if vmachine['vm_host']:
                if vmachine['locked']:
                    vmachines.append(vmachine['name'])
        if vmachines:
            # Avoid ssh-keyscans for everybody when listing all machines
            # Listing specific machines will update the keys.
            if machines:
                do_update_keys(vmachines)
                statuses = [get_status(machine)
                            for machine in machines]
            else:
                statuses = list_locks()
        if statuses:
            if ctx.machine_type:
                statuses = [_status for _status in statuses
                            if _status['machine_type'] == ctx.machine_type]
            if not machines and ctx.owner is None and not ctx.all:
                ctx.owner = misc.get_user()
            if ctx.owner is not None:
                statuses = [_status for _status in statuses
                            if _status['locked_by'] == ctx.owner]
            if ctx.status is not None:
                statuses = [_status for _status in statuses
                            if _status['up'] == (ctx.status == 'up')]
            if ctx.locked is not None:
                statuses = [_status for _status in statuses
                            if _status['locked'] == (ctx.locked == 'true')]
            if ctx.desc is not None:
                statuses = [_status for _status in statuses
                            if _status['description'] == ctx.desc]
            if ctx.desc_pattern is not None:
                statuses = [_status for _status in statuses
                            if _status['description'] is not None and
                            _status['description'].find(ctx.desc_pattern) >= 0]

            # When listing, only show the vm_host's name, not every detail
            for s in statuses:
                if not s.get('is_vm', False):
                    continue
                vm_host_name = s.get('vm_host', dict())['name']
                if vm_host_name:
                    s['vm_host'] = vm_host_name
            if ctx.list:
                    print json.dumps(statuses, indent=4)

            elif ctx.brief:
                for s in sorted(statuses, key=lambda s: s.get('name')):
                    locked = "un" if s['locked'] == 0 else "  "
                    mo = re.match('\w+@(\w+?)\..*', s['name'])
                    host = mo.group(1) if mo else s['name']
                    print '{host} {locked}locked {owner} "{desc}"'.format(
                        locked=locked, host=host,
                        owner=s['locked_by'], desc=s['description'])

            else:
                frag = {'targets': {}}
                for f in statuses:
                    frag['targets'][f['name']] = f['ssh_pub_key']
                print yaml.safe_dump(frag, default_flow_style=False)
        else:
            log.error('error retrieving lock statuses')
            ret = 1

    elif ctx.summary:
        do_summary(ctx)
        return 0

    elif ctx.lock:
        for machine in machines:
            if not lock_one(machine, user, ctx.desc):
                ret = 1
                if not ctx.f:
                    return ret
            else:
                machines_to_update.append(machine)
                provision.create_if_vm(ctx, machine)
    elif ctx.unlock:
        if ctx.owner is None and user is None:
            user = misc.get_user()
        # If none of them are vpm, do them all in one shot
        if not filter(is_vpm, machines):
            res = unlock_many(machines, user)
            return 0 if res else 1
        for machine in machines:
            if not unlock_one(ctx, machine, user):
                ret = 1
                if not ctx.f:
                    return ret
            else:
                machines_to_update.append(machine)
    elif ctx.num_to_lock:
        result = lock_many(ctx, ctx.num_to_lock, ctx.machine_type, user,
                           ctx.desc)
        if not result:
            ret = 1
        else:
            machines_to_update = result.keys()
            if ctx.machine_type == 'vps':
                shortnames = ' '.join(
                    [misc.decanonicalize_hostname(name) for name in
                     result.keys()]
                )
                if len(result) < ctx.num_to_lock:
                    log.error("Locking failed.")
                    for machn in result:
                        unlock_one(ctx, machn)
                    ret = 1
                else:
                    log.info("Successfully Locked:\n%s\n" % shortnames)
                    log.info(
                        "Unable to display keys at this time (virtual " +
                        "machines are booting).")
                    log.info(
                        "Please run teuthology-lock --list-targets %s once " +
                        "these machines come up.",
                        shortnames)
            else:
                print yaml.safe_dump(
                    dict(targets=result),
                    default_flow_style=False)
    elif ctx.update:
        assert ctx.desc is not None or ctx.status is not None, \
            'you must specify description or status to update'
        assert ctx.owner is None, 'only description and status may be updated'
        machines_to_update = machines

        if ctx.desc is not None or ctx.status is not None:
            for machine in machines_to_update:
                update_lock(machine, ctx.desc, ctx.status)

    return ret


def lock_many(ctx, num, machinetype, user=None, description=None):
    machinetypes = misc.get_multi_machine_types(machinetype)
    if user is None:
        user = misc.get_user()
    for machinetype in machinetypes:
        uri = os.path.join(config.lock_server, 'nodes', 'lock_many', '')
        data = dict(
            locked_by=user,
            count=num,
            machine_type=machinetype,
            description=description,
        )
        response = requests.post(
            uri,
            data=json.dumps(data),
            headers={'content-type': 'application/json'},
        )
        if response.ok:
            machines = {misc.canonicalize_hostname(machine['name']):
                        machine['ssh_pub_key'] for machine in response.json()}
            log.debug('locked {machines}'.format(
                machines=', '.join(machines.keys())))
            if machinetype == 'vps':
                ok_machs = {}
                for machine in machines:
                    if provision.create_if_vm(ctx, machine):
                        ok_machs[machine] = machines[machine]
                    else:
                        log.error('Unable to create virtual machine: %s',
                                  machine)
                        unlock_one(ctx, machine)
                return ok_machs
            return machines
        elif response.status_code == 503:
            log.error('Insufficient nodes available to lock %d %s nodes.',
                      num, machinetype)
            log.error(response.text)
        else:
            log.error('Could not lock %d %s nodes, reason: unknown.',
                      num, machinetype)
    return []


def lock_one(name, user=None, description=None):
    if user is None:
        user = misc.get_user()
    request = dict(name=name, locked=True, locked_by=user,
                   description=description)
    uri = os.path.join(config.lock_server, 'nodes', name, 'lock', '')
    response = requests.put(uri, json.dumps(request))
    success = response.ok
    if success:
        log.debug('locked %s as %s', name, user)
    else:
        try:
            reason = response.json().get('message')
        except ValueError:
            reason = str(response.status_code)
        log.error('failed to lock {node}. reason: {reason}'.format(
            node=name, reason=reason))
    return response


def unlock_many(names, user):
    uri = os.path.join(config.lock_server, 'nodes', 'unlock_many', '')
    data = dict(
        locked_by=user,
        names=names,
    )
    response = requests.post(
        uri,
        data=json.dumps(data),
        headers={'content-type': 'application/json'},
    )
    if response.ok:
        log.debug("Unlocked: %s", ', '.join(names))
    else:
        log.error("Failed to unlock: %s", ', '.join(names))
    return response.ok


def unlock_one(ctx, name, user=None):
    if user is None:
        user = misc.get_user()
    request = dict(name=name, locked=False, locked_by=user, description=None)
    uri = os.path.join(config.lock_server, 'nodes', name, 'lock', '')
    response = requests.put(uri, json.dumps(request))
    success = response.ok
    if success:
        log.debug('unlocked %s', name)
        if not provision.destroy_if_vm(ctx, name):
            log.error('downburst destroy failed for %s', name)
            log.info('%s is not locked' % name)
    else:
        try:
            reason = response.json().get('message')
        except ValueError:
            reason = str(response.status_code)
        log.error('failed to unlock {node}. reason: {reason}'.format(
            node=name, reason=reason))
    return success


def list_locks(keyed_by_name=False, **kwargs):
    uri = os.path.join(config.lock_server, 'nodes', '')
    if kwargs:
        if 'machine_type' in kwargs:
            kwargs['machine_type'] = kwargs['machine_type'].replace(',','|')
        uri += '?' + urllib.urlencode(kwargs)
    response = requests.get(uri)
    success = response.ok
    if success:
        if not keyed_by_name:
            return response.json()
        else:
            return {node['name']: node
                    for node in response.json()}
    return None


def update_lock(name, description=None, status=None, ssh_pub_key=None):
    status_info = get_status(name)
    if status_info['is_vm']:
        ssh_key = None
        while not ssh_key:
            time.sleep(10)
            ssh_key = ssh_keyscan(name)
    updated = {}
    if description is not None:
        updated['description'] = description
    if status is not None:
        updated['up'] = (status == 'up')
    if ssh_pub_key is not None:
        updated['ssh_pub_key'] = ssh_pub_key

    if updated:
        uri = os.path.join(config.lock_server, 'nodes', name, '')
        response = requests.put(
            uri,
            json.dumps(updated))
        return response.ok
    return True


def ssh_keyscan(hostnames):
    """
    Fetch the SSH public key of one or more hosts
    """
    args = ['ssh-keyscan', '-t', 'rsa']
    if isinstance(hostnames, basestring):
        args.append(hostnames)
    else:
        args.extend(hostnames)
    p = subprocess.Popen(
        args=args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    p.wait()

    keys_dict = dict()
    for line in p.stdout.readlines():
        host, key = line.strip().split(' ', 1)
        keys_dict[host] = key
    return keys_dict


def updatekeys(ctx):
    loglevel = logging.INFO
    if ctx.verbose:
        loglevel = logging.DEBUG

    logging.basicConfig(
        level=loglevel,
    )

    misc.read_config(ctx)

    machines = [misc.canonicalize_hostname(m, user=None) for m in ctx.machines]

    if ctx.targets:
        try:
            with file(ctx.targets) as f:
                g = yaml.safe_load_all(f)
                for new in g:
                    if 'targets' in new:
                        for t in new['targets'].iterkeys():
                            machines.append(t)
        except IOError as e:
            raise argparse.ArgumentTypeError(str(e))

    return do_update_keys(machines)


def do_update_keys(machines):
    reference = list_locks(keyed_by_name=True, up=True)
    if not machines:
        machines = reference.keys()
    keys_dict = ssh_keyscan(machines)
    return push_new_keys(keys_dict, reference)


def push_new_keys(keys_dict, reference):
    ret = 0
    for hostname, pubkey in keys_dict.iteritems():
        log.info('Checking %s', hostname)
        if reference[hostname]['ssh_pub_key'] != pubkey:
            log.info('New key found. Updating...')
            if not update_lock(hostname, ssh_pub_key=pubkey):
                log.error('failed to update %s!', hostname)
                ret = 1
    return ret


def do_summary(ctx):
    lockd = collections.defaultdict(lambda: [0, 0, 'unknown'])
    if ctx.machine_type:
        locks = list_locks(machine_type=ctx.machine_type)
    else:
        locks = list_locks()
    for l in locks:
        who = l['locked_by'] if l['locked'] == 1 \
            else '(free)', l['machine_type']
        lockd[who][0] += 1
        lockd[who][1] += 1 if l['up'] else 0
        lockd[who][2] = l['machine_type']

    locks = sorted([p for p in lockd.iteritems()
                    ], key=lambda sort: (sort[1][2], sort[1][0]))
    total_count, total_up = 0, 0
    print "TYPE     COUNT  UP  OWNER"

    for (owner, (count, upcount, machinetype)) in locks:
            # if machinetype == spectype:
            print "{machinetype:8s} {count:3d}  {up:3d}  {owner}".format(
                count=count, up=upcount, owner=owner[0],
                machinetype=machinetype)
            total_count += count
            total_up += upcount

    print "         ---  ---"
    print "{cnt:12d}  {up:3d}".format(cnt=total_count, up=total_up)
