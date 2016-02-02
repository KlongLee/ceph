distro = None
release = None
codename = None


def choose_init():
    """Select a init system

    Returns the name of a init system (upstart, sysvinit ...).
    """
    assert(distro and codename)
    if distro.lower() in ('ubuntu', 'linuxmint'):
        if codename >= 'vivid':
            return 'systemd'
        else:
            return 'upstart'
    return 'sysvinit'
