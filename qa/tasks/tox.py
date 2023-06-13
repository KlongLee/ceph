import argparse
import contextlib
import logging

from teuthology import misc as teuthology
from teuthology.orchestra import run

log = logging.getLogger(__name__)


def get_toxvenv_dir(ctx):
    return '{tdir}/tox-venv'.format(tdir=teuthology.get_testdir(ctx))

@contextlib.contextmanager
def task(ctx, config):
    """
    Deploy tox from pip. It's a dependency for both Keystone and Tempest.
    """
    assert config is None or isinstance(config, list) \
        or isinstance(config, dict), \
        "task tox only supports a list or dictionary for configuration"
    all_clients = ['client.{id}'.format(id=id_)
                   for id_ in teuthology.all_roles_of_type(ctx.cluster, 'client')]
    if config is None:
        config = all_clients
    if isinstance(config, list):
        config = dict.fromkeys(config)

    log.info('Deploying tox from pip...')
    for (client, _) in config.items():
        # yup, we have to deploy tox first. The packaged one, available
        # on Sepia's Ubuntu machines, is outdated for Keystone/Tempest.
        tvdir = get_toxvenv_dir(ctx)
        (remote,) = ctx.cluster.only(client).remotes.keys()
        if remote.os.name == 'rhel' or remote.os.name == 'centos':
            ctx.cluster.only(client).run(args=['ls', '/usr/bin/python3*'])
            ctx.cluster.only(client).run(args=['echo', '$PATH'])
            ctx.cluster.only(client).run(args=['python39', '-m', 'pip', 'install', 'virtualenv'])
            ctx.cluster.only(client).run(args=['python39', '-m', 'venv', tvdir])
        else:
            ctx.cluster.only(client).run(args=['ls', '/usr/bin/python3*'])
            ctx.cluster.only(client).run(args=['echo', '$PATH'])
            ctx.cluster.only(client).run(args=['python3.9', '-m', 'pip', 'install', 'virtualenv'])
            ctx.cluster.only(client).run(args=['python3.9', '-m', 'venv', tvdir])
        ctx.cluster.only(client).run(args=[
            'source', '{tvdir}/bin/activate'.format(tvdir=tvdir),
            run.Raw('&&'),
            'pip', 'install', 'tox==3.15.0'
        ])

    # export the path Keystone and Tempest
    ctx.tox = argparse.Namespace()
    ctx.tox.venv_path = get_toxvenv_dir(ctx)

    try:
        yield
    finally:
        for (client, _) in config.items():
            ctx.cluster.only(client).run(
                args=[ 'rm', '-rf', get_toxvenv_dir(ctx) ])
