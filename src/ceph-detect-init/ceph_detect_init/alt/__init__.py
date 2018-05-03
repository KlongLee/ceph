import os

distro = None
release = None
codename = None


def choose_init():
    """Select a init system

    Returns the name of a init system (systemd, sysvinit ...).
    """
    # yes, this is heuristics
    if os.path.isdir('/run/systemd/system'):
        return 'systemd'

    if os.path.isfile('/sbin/init') and not os.path.islink('/sbin/init'):
        return 'sysvinit'
