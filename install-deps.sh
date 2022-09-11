#!/usr/bin/env bash
# -*- mode:sh; tab-width:8; indent-tabs-mode:t -*-
#
# Ceph distributed storage system
#
# Copyright (C) 2014, 2015 Red Hat <contact@redhat.com>
#
# Author: Loic Dachary <loic@dachary.org>
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 2.1 of the License, or (at your option) any later version.
#
set -e
DIR=/tmp/install-deps.$$
trap "rm -fr $DIR" EXIT
mkdir -p $DIR
if test $(id -u) != 0 ; then
    SUDO=sudo
fi
export LC_ALL=en_US.UTF-8 # the following is vulnerable to i18n

ARCH=$(uname -m)

function in_jenkins() {
    test -n "$JENKINS_HOME"
}

function munge_ceph_spec_in {
    local with_seastar=$1
    shift
    local with_zbd=$1
    shift
    local for_make_check=$1
    shift
    local OUTFILE=$1
    sed -e 's/@//g' < ceph.spec.in > $OUTFILE
    # http://rpm.org/user_doc/conditional_builds.html
    if $with_seastar; then
        sed -i -e 's/%bcond_with seastar/%bcond_without seastar/g' $OUTFILE
    fi
    if $with_zbd; then
        sed -i -e 's/%bcond_with zbd/%bcond_without zbd/g' $OUTFILE
    fi
    if $for_make_check; then
        sed -i -e 's/%bcond_with make_check/%bcond_without make_check/g' $OUTFILE
    fi
}

function munge_debian_control {
    local version=$1
    shift
    local control=$1
    case "$version" in
        *squeeze*|*wheezy*)
	    control="/tmp/control.$$"
	    grep -v babeltrace debian/control > $control
	    ;;
    esac
    echo $control
}

function ensure_decent_gcc_on_ubuntu {
    in_jenkins && echo "CI_DEBUG: Start ensure_decent_gcc_on_ubuntu() in install-deps.sh"
    # point gcc to the one offered by g++-7 if the used one is not
    # new enough
    local old=$(gcc -dumpfullversion -dumpversion)
    local new=$1
    local codename=$2
    if dpkg --compare-versions $old ge ${new}.0; then
	return
    fi

    if [ ! -f /usr/bin/g++-${new} ]; then
	$SUDO tee /etc/apt/sources.list.d/ubuntu-toolchain-r.list <<EOF
deb [lang=none] http://ppa.launchpad.net/ubuntu-toolchain-r/test/ubuntu $codename main
deb [arch=amd64 lang=none] http://mirror.nullivex.com/ppa/ubuntu-toolchain-r-test $codename main
EOF
	# import PPA's signing key into APT's keyring
	cat << ENDOFKEY | $SUDO apt-key add -
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: SKS 1.1.6
Comment: Hostname: keyserver.ubuntu.com

mI0ESuBvRwEEAMi4cDba7xlKaaoXjO1n1HX8RKrkW+HEIl79nSOSJyvzysajs7zUow/OzCQp
9NswqrDmNuH1+lPTTRNAGtK8r2ouq2rnXT1mTl23dpgHZ9spseR73s4ZBGw/ag4bpU5dNUSt
vfmHhIjVCuiSpNn7cyy1JSSvSs3N2mxteKjXLBf7ABEBAAG0GkxhdW5jaHBhZCBUb29sY2hh
aW4gYnVpbGRziLYEEwECACAFAkrgb0cCGwMGCwkIBwMCBBUCCAMEFgIDAQIeAQIXgAAKCRAe
k3eiup7yfzGKA/4xzUqNACSlB+k+DxFFHqkwKa/ziFiAlkLQyyhm+iqz80htRZr7Ls/ZRYZl
0aSU56/hLe0V+TviJ1s8qdN2lamkKdXIAFfavA04nOnTzyIBJ82EAUT3Nh45skMxo4z4iZMN
msyaQpNl/m/lNtOLhR64v5ZybofB2EWkMxUzX8D/FQ==
=LcUQ
-----END PGP PUBLIC KEY BLOCK-----
ENDOFKEY
	$SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -y || true
	$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y g++-${new}
    fi
}

function ensure_python3_sphinx_on_ubuntu {
    in_jenkins && echo "CI_DEBUG: Running ensure_python3_sphinx_on_ubuntu() in install-deps.sh"
    local sphinx_command=/usr/bin/sphinx-build
    # python-sphinx points $sphinx_command to
    # ../share/sphinx/scripts/python2/sphinx-build when it's installed
    # let's "correct" this
    if test -e $sphinx_command  && head -n1 $sphinx_command | grep -q python$; then
        $SUDO env DEBIAN_FRONTEND=noninteractive apt-get -y remove python-sphinx
    fi
}

function install_pkg_on_ubuntu {
    in_jenkins && echo "CI_DEBUG: Running install_pkg_on_ubuntu() in install-deps.sh"
    local project=$1
    shift
    local sha1=$1
    shift
    local codename=$1
    shift
    local force=$1
    shift
    local pkgs=$@
    local missing_pkgs
    if [ $force = "force" ]; then
	missing_pkgs="$@"
    else
	for pkg in $pkgs; do
	    if ! apt -qq list $pkg 2>/dev/null | grep -q installed; then
		missing_pkgs+=" $pkg"
                in_jenkins && echo "CI_DEBUG: missing_pkgs=$missing_pkgs"
	    fi
	done
    fi
    if test -n "$missing_pkgs"; then
	local shaman_url="https://shaman.ceph.com/api/repos/${project}/master/${sha1}/ubuntu/${codename}/repo"
	$SUDO curl --silent --location $shaman_url --output /etc/apt/sources.list.d/$project.list
	$SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -y -o Acquire::Languages=none -o Acquire::Translation=none || true
	$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install --allow-unauthenticated -y $missing_pkgs
    fi
}

function install_boost_on_ubuntu {
    in_jenkins && echo "CI_DEBUG: Running install_boost_on_ubuntu() in install-deps.sh"
    local ver=1.79
    local installed_ver=$(apt -qq list --installed ceph-libboost*-dev 2>/dev/null |
                              grep -e 'libboost[0-9].[0-9]\+-dev' |
                              cut -d' ' -f2 |
                              cut -d'.' -f1,2)
    if test -n "$installed_ver"; then
        if echo "$installed_ver" | grep -q "^$ver"; then
            return
        else
            $SUDO env DEBIAN_FRONTEND=noninteractive apt-get -y remove "ceph-libboost.*${installed_ver}.*"
            $SUDO rm -f /etc/apt/sources.list.d/ceph-libboost${installed_ver}.list
        fi
    fi
    local codename=$1
    local project=libboost
    local sha1=892ab89e76b91b505ffbf083f6fb7f2a666d4132
    install_pkg_on_ubuntu \
	$project \
	$sha1 \
	$codename \
	check \
	ceph-libboost-atomic$ver-dev \
	ceph-libboost-chrono$ver-dev \
	ceph-libboost-container$ver-dev \
	ceph-libboost-context$ver-dev \
	ceph-libboost-coroutine$ver-dev \
	ceph-libboost-date-time$ver-dev \
	ceph-libboost-filesystem$ver-dev \
	ceph-libboost-iostreams$ver-dev \
	ceph-libboost-program-options$ver-dev \
	ceph-libboost-python$ver-dev \
	ceph-libboost-random$ver-dev \
	ceph-libboost-regex$ver-dev \
	ceph-libboost-system$ver-dev \
	ceph-libboost-test$ver-dev \
	ceph-libboost-thread$ver-dev \
	ceph-libboost-timer$ver-dev
}

function install_libzbd_on_ubuntu {
    in_jenkins && echo "CI_DEBUG: Running install_libzbd_on_ubuntu() in install-deps.sh"
    local codename=$1
    local project=libzbd
    local sha1=1fadde94b08fab574b17637c2bebd2b1e7f9127b
    install_pkg_on_ubuntu \
        $project \
        $sha1 \
        $codename \
        check \
        libzbd-dev
}

motr_pkgs_url='https://github.com/Seagate/cortx-motr/releases/download/2.0.0-rgw'

function install_cortx_motr_on_ubuntu {
    if dpkg -l cortx-motr-dev &> /dev/null; then
        return
    fi
    if [ "$(lsb_release -sc)" = "jammy" ]; then
      install_pkg_on_ubuntu \
        cortx-motr \
        39f89fa1c6945040433a913f2687c4b4e6cbeb3f \
        jammy \
        check \
	cortx-motr \
	cortx-motr-dev
    else
        local deb_arch=$(dpkg --print-architecture)
        local motr_pkg="cortx-motr_2.0.0.git3252d623_$deb_arch.deb"
        local motr_dev_pkg="cortx-motr-dev_2.0.0.git3252d623_$deb_arch.deb"
        $SUDO curl -sL -o/var/cache/apt/archives/$motr_pkg $motr_pkgs_url/$motr_pkg
        $SUDO curl -sL -o/var/cache/apt/archives/$motr_dev_pkg $motr_pkgs_url/$motr_dev_pkg
        # For some reason libfabric pkg is not available in arm64 version
        # of Ubuntu 20.04 (Focal Fossa), so we borrow it from more recent
        # versions for now.
        if [[ "$deb_arch" == 'arm64' ]]; then
            local lf_pkg='libfabric1_1.11.0-2_arm64.deb'
            $SUDO curl -sL -o/var/cache/apt/archives/$lf_pkg http://ports.ubuntu.com/pool/universe/libf/libfabric/$lf_pkg
            $SUDO apt-get install -y /var/cache/apt/archives/$lf_pkg
        fi
        $SUDO apt-get install -y /var/cache/apt/archives/{$motr_pkg,$motr_dev_pkg}
        $SUDO apt-get install -y libisal-dev
    fi
}

function version_lt {
    test $1 != $(echo -e "$1\n$2" | sort -rV | head -n 1)
}

function ensure_decent_gcc_on_rh {
    local old=$(gcc -dumpversion)
    local dts_ver=$1
    if version_lt $old $dts_ver; then
	if test -t 1; then
	    # interactive shell
	    cat <<EOF
Your GCC is too old. Please run following command to add DTS to your environment:

scl enable gcc-toolset-$dts_ver bash

Or add the following line to the end of ~/.bashrc and run "source ~/.bashrc" to add it permanently:

source scl_source enable gcc-toolset-$dts_ver
EOF
	else
	    # non-interactive shell
	    source /opt/rh/gcc-toolset-$dts_ver/enable
	fi
    fi
}

for_make_check=false
if tty -s; then
    # interactive
    for_make_check=true
elif [ $FOR_MAKE_CHECK ]; then
    for_make_check=true
else
    for_make_check=false
fi

if [ x$(uname)x = xFreeBSDx ]; then
    $SUDO pkg install -yq \
        devel/babeltrace \
        devel/binutils \
        devel/git \
        devel/gperf \
        devel/gmake \
        devel/cmake \
        devel/nasm \
        devel/boost-all \
        devel/boost-python-libs \
        devel/valgrind \
        devel/pkgconf \
        devel/libedit \
        devel/libtool \
        devel/google-perftools \
        lang/cython \
        databases/leveldb \
        net/openldap24-client \
        archivers/snappy \
        archivers/liblz4 \
        ftp/curl \
        misc/e2fsprogs-libuuid \
        misc/getopt \
        net/socat \
        textproc/expat2 \
        textproc/gsed \
        lang/gawk \
        textproc/libxml2 \
        textproc/xmlstarlet \
        textproc/jq \
        textproc/py-sphinx \
        emulators/fuse \
        java/junit \
        lang/python36 \
        devel/py-pip \
        devel/py-flake8 \
        devel/py-tox \
        devel/py-argparse \
        devel/py-nose \
        devel/py-prettytable \
        devel/py-yaml \
        www/py-routes \
        www/py-flask \
        www/node \
        www/npm \
        www/fcgi \
        security/nss \
        security/krb5 \
        security/oath-toolkit \
        sysutils/flock \
        sysutils/fusefs-libs \

	# Now use pip to install some extra python modules
	pip install pecan

    exit
else
    [ $WITH_SEASTAR ] && with_seastar=true || with_seastar=false
    [ $WITH_ZBD ] && with_zbd=true || with_zbd=false
    [ $WITH_PMEM ] && with_pmem=true || with_pmem=false
    [ $WITH_RADOSGW_MOTR ] && with_rgw_motr=true || with_rgw_motr=false
    source /etc/os-release
    case "$ID" in
    debian|ubuntu|devuan|elementary|softiron)
        echo "Using apt-get to install dependencies"
        $SUDO apt-get install -y devscripts equivs
        $SUDO apt-get install -y dpkg-dev
        ensure_python3_sphinx_on_ubuntu
        case "$VERSION" in
            *Bionic*)
                ensure_decent_gcc_on_ubuntu 9 bionic
                [ ! $NO_BOOST_PKGS ] && install_boost_on_ubuntu bionic
                $with_zbd && install_libzbd_on_ubuntu bionic
                ;;
            *Focal*)
                ensure_decent_gcc_on_ubuntu 11 focal
                [ ! $NO_BOOST_PKGS ] && install_boost_on_ubuntu focal
                $with_zbd && install_libzbd_on_ubuntu focal
                ;;
            *Jammy*)
                [ ! $NO_BOOST_PKGS ] && install_boost_on_ubuntu jammy
                $SUDO apt-get install -y gcc
                ;;
            *)
                $SUDO apt-get install -y gcc
                ;;
        esac
        if ! test -r debian/control ; then
            echo debian/control is not a readable file
            exit 1
        fi
        touch $DIR/status

        in_jenkins && echo "CI_DEBUG: Running munge_debian_control() in install-deps.sh"
	backports=""
	control=$(munge_debian_control "$VERSION" "debian/control")
        case "$VERSION" in
            *squeeze*|*wheezy*)
                backports="-t $codename-backports"
                ;;
        esac

	# make a metapackage that expresses the build dependencies,
	# install it, rm the .deb; then uninstall the package as its
	# work is done
	build_profiles=""
	if $for_make_check; then
	    build_profiles+=",pkg.ceph.check"
	fi
	if $with_seastar; then
	    build_profiles+=",pkg.ceph.crimson"
	fi
	if $with_pmem; then
	    build_profiles+=",pkg.ceph.pmdk"
	fi

        in_jenkins && cat <<EOF
CI_DEBUG: for_make_check=$for_make_check
CI_DEBUG: with_seastar=$with_seastar
CI_DEBUG: with_jaeger=$with_jaeger
CI_DEBUG: build_profiles=$build_profiles
CI_DEBUG: Now running 'mk-build-deps' and installing ceph-build-deps package
EOF

	$SUDO env DEBIAN_FRONTEND=noninteractive mk-build-deps \
	      --build-profiles "${build_profiles#,}" \
	      --install --remove \
	      --tool="apt-get -y --no-install-recommends $backports" $control || exit 1
        in_jenkins && echo "CI_DEBUG: Removing ceph-build-deps"
	$SUDO env DEBIAN_FRONTEND=noninteractive apt-get -y remove ceph-build-deps
	if [ "$control" != "debian/control" ] ; then rm $control; fi

        # for rgw motr backend build checks
        if $with_rgw_motr; then
            install_cortx_motr_on_ubuntu
        fi
        ;;
    rocky|centos|fedora|rhel|ol|virtuozzo)
        builddepcmd="dnf -y builddep --allowerasing"
        echo "Using dnf to install dependencies"
        case "$ID" in
            fedora)
                $SUDO dnf install -y dnf-utils
                ;;
            rocky|centos|rhel|ol|virtuozzo)
                MAJOR_VERSION="$(echo $VERSION_ID | cut -d. -f1)"
                $SUDO dnf install -y dnf-utils selinux-policy-targeted
                rpm --quiet --query epel-release || \
		    $SUDO dnf -y install --nogpgcheck https://dl.fedoraproject.org/pub/epel/epel-release-latest-$MAJOR_VERSION.noarch.rpm
                $SUDO rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-$MAJOR_VERSION
                $SUDO rm -f /etc/yum.repos.d/dl.fedoraproject.org*
		if test $ID = centos -a $MAJOR_VERSION = 8 ; then
                    # Enable 'powertools' or 'PowerTools' repo
                    $SUDO dnf config-manager --set-enabled $(dnf repolist --all 2>/dev/null|gawk 'tolower($0) ~ /^powertools\s/{print $1}')
		    dts_ver=11
		    # before EPEL8 and PowerTools provide all dependencies, we use sepia for the dependencies
                    $SUDO dnf config-manager --add-repo http://apt-mirror.front.sepia.ceph.com/lab-extras/8/
                    $SUDO dnf config-manager --setopt=apt-mirror.front.sepia.ceph.com_lab-extras_8_.gpgcheck=0 --save
                    $SUDO dnf -y module enable javapackages-tools
                elif test $ID = rhel -a $MAJOR_VERSION = 8 ; then
                    dts_ver=11
                    $SUDO dnf config-manager --set-enabled "codeready-builder-for-rhel-8-${ARCH}-rpms"
		    $SUDO dnf config-manager --add-repo http://apt-mirror.front.sepia.ceph.com/lab-extras/8/
		    $SUDO dnf config-manager --setopt=apt-mirror.front.sepia.ceph.com_lab-extras_8_.gpgcheck=0 --save
		    $SUDO dnf -y module enable javapackages-tools
                fi
                ;;
        esac
        munge_ceph_spec_in $with_seastar $with_zbd $for_make_check $DIR/ceph.spec
        # for python3_pkgversion macro defined by python-srpm-macros, which is required by python3-devel
        $SUDO dnf install -y python3-devel
        $SUDO $builddepcmd $DIR/ceph.spec 2>&1 | tee $DIR/yum-builddep.out
        [ ${PIPESTATUS[0]} -ne 0 ] && exit 1
	if [ -n "$dts_ver" ]; then
            ensure_decent_gcc_on_rh $dts_ver
	fi
        IGNORE_YUM_BUILDEP_ERRORS="ValueError: SELinux policy is not managed or store cannot be accessed."
        sed "/$IGNORE_YUM_BUILDEP_ERRORS/d" $DIR/yum-builddep.out | grep -i "error:" && exit 1
        # for rgw motr backend build checks
        if ! rpm --quiet -q cortx-motr-devel &&
              { [[ $FOR_MAKE_CHECK ]] || $with_rgw_motr; }; then
            $SUDO dnf install -y \
                  "$motr_pkgs_url/isa-l-2.30.0-1.el7.${ARCH}.rpm" \
                  "$motr_pkgs_url/cortx-motr-2.0.0-1_git3252d623_any.el8.${ARCH}.rpm" \
                  "$motr_pkgs_url/cortx-motr-devel-2.0.0-1_git3252d623_any.el8.${ARCH}.rpm"
        fi
        ;;
    opensuse*|suse|sles)
        echo "Using zypper to install dependencies"
        zypp_install="zypper --gpg-auto-import-keys --non-interactive install --no-recommends"
        $SUDO $zypp_install systemd-rpm-macros rpm-build || exit 1
        munge_ceph_spec_in $with_seastar false $for_make_check $DIR/ceph.spec
        $SUDO $zypp_install $(rpmspec -q --buildrequires $DIR/ceph.spec) || exit 1
        ;;
    *)
        echo "$ID is unknown, dependencies will have to be installed manually."
	exit 1
        ;;
    esac
fi

function populate_wheelhouse() {
    in_jenkins && echo "CI_DEBUG: Running populate_wheelhouse() in install-deps.sh"
    local install=$1
    shift

    # although pip comes with virtualenv, having a recent version
    # of pip matters when it comes to using wheel packages
    PIP_OPTS="--timeout 300 --exists-action i"
    pip $PIP_OPTS $install \
      'setuptools >= 0.8' 'pip >= 21.0' 'wheel >= 0.24' 'tox >= 2.9.1' || return 1
    if test $# != 0 ; then
        # '--use-feature=fast-deps --use-deprecated=legacy-resolver' added per
        # https://github.com/pypa/pip/issues/9818 These should be able to be
        # removed at some point in the future.
        pip --use-feature=fast-deps --use-deprecated=legacy-resolver $PIP_OPTS $install $@ || return 1
    fi
}

function activate_virtualenv() {
    in_jenkins && echo "CI_DEBUG: Running activate_virtualenv() in install-deps.sh"
    local top_srcdir=$1
    local env_dir=$top_srcdir/install-deps-python3

    if ! test -d $env_dir ; then
        python3 -m venv ${env_dir}
        . $env_dir/bin/activate
        if ! populate_wheelhouse install ; then
            rm -rf $env_dir
            return 1
        fi
    fi
    . $env_dir/bin/activate
}

function preload_wheels_for_tox() {
    in_jenkins && echo "CI_DEBUG: Running preload_wheels_for_tox() in install-deps.sh"
    local ini=$1
    shift
    pushd . > /dev/null
    cd $(dirname $ini)
    local require_files=$(ls *requirements*.txt 2>/dev/null) || true
    local constraint_files=$(ls *constraints*.txt 2>/dev/null) || true
    local require=$(echo -n "$require_files" | sed -e 's/^/-r /')
    local constraint=$(echo -n "$constraint_files" | sed -e 's/^/-c /')
    local md5=wheelhouse/md5
    if test "$require"; then
        if ! test -f $md5 || ! md5sum -c $md5 > /dev/null; then
            rm -rf wheelhouse
        fi
    fi
    if test "$require" && ! test -d wheelhouse ; then
        type python3 > /dev/null 2>&1 || continue
        activate_virtualenv $top_srcdir || exit 1
        python3 -m pip install --upgrade pip
        populate_wheelhouse "wheel -w $wip_wheelhouse" $require $constraint || exit 1
        mv $wip_wheelhouse wheelhouse
        md5sum $require_files $constraint_files > $md5
    fi
    popd > /dev/null
}

# use pip cache if possible but do not store it outside of the source
# tree
# see https://pip.pypa.io/en/stable/reference/pip_install.html#caching
if $for_make_check; then
    mkdir -p install-deps-cache
    top_srcdir=$(pwd)
    export XDG_CACHE_HOME=$top_srcdir/install-deps-cache
    wip_wheelhouse=wheelhouse-wip
    #
    # preload python modules so that tox can run without network access
    #
    find . -name tox.ini | while read ini ; do
        preload_wheels_for_tox $ini
    done
    rm -rf $top_srcdir/install-deps-python3
    rm -rf $XDG_CACHE_HOME
    type git > /dev/null || (echo "Dashboard uses git to pull dependencies." ; false)
fi

in_jenkins && echo "CI_DEBUG: End install-deps.sh" || true
