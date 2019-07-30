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
export LC_ALL=C # the following is vulnerable to i18n

ARCH=$(uname -m)

function munge_ceph_spec_in {
    local with_seastar=$1
    shift
    local for_make_check=$1
    shift
    local OUTFILE=$1
    sed -e 's/@//g' < ceph.spec.in > $OUTFILE
    # http://rpm.org/user_doc/conditional_builds.html
    if $with_seastar; then
        sed -i -e 's/%bcond_with seastar/%bcond_without seastar/g' $OUTFILE
    fi
    if $for_make_check; then
        sed -i -e 's/%bcond_with make_check/%bcond_without make_check/g' $OUTFILE
    fi
}

function munge_debian_control {
    local version=$1
    shift
    local with_seastar=$1
    shift
    local for_make_check=$1
    shift
    local control=$1
    case "$version" in
        *squeeze*|*wheezy*)
	    control="/tmp/control.$$"
	    grep -v babeltrace debian/control > $control
	    ;;
    esac
    if $with_seastar; then
	sed -i -e 's/^# Crimson[[:space:]]//g' $control
    fi
    if $for_make_check; then
        sed -i 's/^# Make-Check[[:space:]]/             /g' $control
    fi
    echo $control
}

function ensure_decent_gcc_on_ubuntu {
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
deb [arch=amd64 lang=none] http://deb.rug.nl/ppa/mirror/ppa.launchpad.net/ubuntu-toolchain-r/test/ubuntu $codename main
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

    case $codename in
        trusty)
            old=4.8;;
        xenial)
            old=5;;
        bionic)
            old=7;;
    esac
    $SUDO update-alternatives --remove-all gcc || true
    $SUDO update-alternatives \
	 --install /usr/bin/gcc gcc /usr/bin/gcc-${new} 20 \
	 --slave   /usr/bin/g++ g++ /usr/bin/g++-${new}

    if [ -f /usr/bin/g++-${old} ]; then
      $SUDO update-alternatives \
  	 --install /usr/bin/gcc gcc /usr/bin/gcc-${old} 10 \
  	 --slave   /usr/bin/g++ g++ /usr/bin/g++-${old}
    fi

    $SUDO update-alternatives --auto gcc

    # cmake uses the latter by default
    $SUDO ln -nsf /usr/bin/gcc /usr/bin/$(uname -m)-linux-gnu-gcc
    $SUDO ln -nsf /usr/bin/g++ /usr/bin/$(uname -m)-linux-gnu-g++
}

function ensure_decent_cmake_on_ubuntu {
    # TODO: remove me after a while
    # remove Kitware Apt Archive Automatic Signing Key
    $SUDO apt-key del 40CD72DA
    $SUDO rm -f /etc/apt/sources.list.d/kitware.list
    local new=$1
    if command -v cmake > /dev/null; then
        local old=$(cmake --version | grep -Po 'version \K[0-9].*')
        if dpkg --compare-versions $old ge $new; then
          return
        fi
    fi
    install_pkg_on_ubuntu \
	ceph-cmake \
	d278b9d28de0f6b88f56dfe1e8bf684a41577210 \
	xenial \
	force \
	cmake
}

function install_pkg_on_ubuntu {
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
	    if ! dpkg -s $pkg &> /dev/null; then
		missing_pkgs+=" $pkg"
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
    local codename=$1
    install_pkg_on_ubuntu \
	ceph-libboost1.67 \
	dd38c27740c1f9a9e6719a07eef84a1369dc168b \
	$codename \
	check \
	ceph-libboost-atomic1.67-dev \
	ceph-libboost-chrono1.67-dev \
	ceph-libboost-container1.67-dev \
	ceph-libboost-context1.67-dev \
	ceph-libboost-coroutine1.67-dev \
	ceph-libboost-date-time1.67-dev \
	ceph-libboost-filesystem1.67-dev \
	ceph-libboost-iostreams1.67-dev \
	ceph-libboost-program-options1.67-dev \
	ceph-libboost-python1.67-dev \
	ceph-libboost-random1.67-dev \
	ceph-libboost-regex1.67-dev \
	ceph-libboost-system1.67-dev \
	ceph-libboost-test1.67-dev \
	ceph-libboost-thread1.67-dev \
	ceph-libboost-timer1.67-dev
}

function version_lt {
    test $1 != $(echo -e "$1\n$2" | sort -rV | head -n 1)
}

function ensure_decent_gcc_on_rh {
    local old=$(gcc -dumpversion)
    local expected=5.1
    local dts_ver=$1
    if version_lt $old $expected; then
	if test -t 1; then
	    # interactive shell
	    cat <<EOF
Your GCC is too old. Please run following command to add DTS to your environment:

scl enable devtoolset-8 bash

Or add following line to the end of ~/.bashrc to add it permanently:

source scl_source enable devtoolset-8

see https://www.softwarecollections.org/en/scls/rhscl/devtoolset-7/ for more details.
EOF
	else
	    # non-interactive shell
	    source /opt/rh/devtoolset-$dts_ver/enable
	fi
    fi
    if [ $(rpm -q --queryformat "%{VERSION}" devtoolset-$dts_ver-gcc-c++) = 8.3.1 ]; then
        # rollback to avoid using a buggy version
        $SUDO yum remove -y devtoolset-8-gcc-c++ devtoolset-8-gcc devtoolset-8-libstdc++-devel
        $SUDO yum install -y devtoolset-8-gcc-c++-8.2.1-3.el7
    fi
}

if [ x$(uname)x = xFreeBSDx ]; then
    $SUDO pkg install -yq \
        devel/babeltrace \
        devel/binutils \
        devel/git \
        devel/gperf \
        devel/gmake \
        devel/cmake \
        devel/yasm \
        devel/boost-all \
        devel/boost-python-libs \
        devel/valgrind \
        devel/pkgconf \
        devel/libedit \
        devel/libtool \
        devel/google-perftools \
        lang/cython \
        devel/py-virtualenv \
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
    for_make_check=false
    if tty -s; then
        # interactive
        for_make_check=true
    elif [ $FOR_MAKE_CHECK ]; then
        for_make_check=true
    else
        for_make_check=false
    fi
    [ $WITH_SEASTAR ] && with_seastar=true || with_seastar=false
    source /etc/os-release
    case $ID in
    debian|ubuntu|devuan)
        echo "Using apt-get to install dependencies"
        $SUDO apt-get install -y devscripts equivs
        $SUDO apt-get install -y dpkg-dev
        case "$VERSION" in
            *Trusty*)
                ensure_decent_gcc_on_ubuntu 8 trusty
                ;;
            *Xenial*)
                ensure_decent_gcc_on_ubuntu 8 xenial
                ensure_decent_cmake_on_ubuntu 3.10.1
                [ ! $NO_BOOST_PKGS ] && install_boost_on_ubuntu xenial
                ;;
            *Bionic*)
                ensure_decent_gcc_on_ubuntu 9 bionic
                [ ! $NO_BOOST_PKGS ] && install_boost_on_ubuntu bionic
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

	backports=""
	control=$(munge_debian_control "$VERSION" "$with_seastar" "$for_make_check" "debian/control")
        case "$VERSION" in
            *squeeze*|*wheezy*)
                backports="-t $codename-backports"
                ;;
        esac

	# make a metapackage that expresses the build dependencies,
	# install it, rm the .deb; then uninstall the package as its
	# work is done
	$SUDO env DEBIAN_FRONTEND=noninteractive mk-build-deps --install --remove --tool="apt-get -y --no-install-recommends $backports" $control || exit 1
	$SUDO env DEBIAN_FRONTEND=noninteractive apt-get -y remove ceph-build-deps
	if [ "$control" != "debian/control" ] ; then rm $control; fi
	$SUDO apt-get install -y libxmlsec1 libxmlsec1-nss libxmlsec1-openssl libxmlsec1-dev
        ;;
    centos|fedora|rhel|ol|virtuozzo)
        yumdnf="yum"
        builddepcmd="yum-builddep -y --setopt=*.skip_if_unavailable=true"
        if test "$(echo "$VERSION_ID >= 22" | bc)" -ne 0; then
            yumdnf="dnf"
            builddepcmd="dnf -y builddep --allowerasing"
        fi
        echo "Using $yumdnf to install dependencies"
	if [ "$ID" = "centos" -a $(uname -m) = aarch64 ]; then
	    $SUDO yum-config-manager --disable centos-sclo-sclo || true
	    $SUDO yum-config-manager --disable centos-sclo-rh || true
	    $SUDO yum remove centos-release-scl || true
	fi
        case $ID in
            fedora)
                if test $yumdnf = yum; then
                    $SUDO $yumdnf install -y yum-utils
                fi
                ;;
            centos|rhel|ol|virtuozzo)
                MAJOR_VERSION="$(echo $VERSION_ID | cut -d. -f1)"
                $SUDO yum install -y yum-utils
                if test $ID = rhel ; then
                    $SUDO yum-config-manager --enable rhel-$MAJOR_VERSION-server-optional-rpms
                fi
                $SUDO yum-config-manager --add-repo https://dl.fedoraproject.org/pub/epel/$MAJOR_VERSION/x86_64/
                $SUDO yum install --nogpgcheck -y epel-release
                $SUDO rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-$MAJOR_VERSION
                $SUDO rm -f /etc/yum.repos.d/dl.fedoraproject.org*
                if test $ID = centos -a $MAJOR_VERSION = 7 ; then
		    case $(uname -m) in
			x86_64)
			    $SUDO yum -y install centos-release-scl
			    dts_ver=8
			    ;;
			aarch64)
			    $SUDO yum -y install centos-release-scl-rh
			    $SUDO yum-config-manager --disable centos-sclo-rh
			    $SUDO yum-config-manager --enable centos-sclo-rh-testing
			    dts_ver=8
			    ;;
		    esac
                elif test $ID = rhel -a $MAJOR_VERSION = 7 ; then
                    $SUDO yum-config-manager \
			  --enable rhel-server-rhscl-7-rpms \
			  --enable rhel-7-server-devtools-rpms
                    dts_ver=8
                fi
                ;;
        esac
        munge_ceph_spec_in $with_seastar $for_make_check $DIR/ceph.spec
        $SUDO $yumdnf install -y \*rpm-macros
        $SUDO $builddepcmd $DIR/ceph.spec 2>&1 | tee $DIR/yum-builddep.out
        [ ${PIPESTATUS[0]} -ne 0 ] && exit 1
	if [ -n "$dts_ver" ]; then
            ensure_decent_gcc_on_rh $dts_ver
	fi
        IGNORE_YUM_BUILDEP_ERRORS="ValueError: SELinux policy is not managed or store cannot be accessed."
        sed "/$IGNORE_YUM_BUILDEP_ERRORS/d" $DIR/yum-builddep.out | grep -qi "error:" && exit 1
        # for building python-saml and its dependencies
        $SUDO $yumdnf install -y xmlsec1 xmlsec1-nss xmlsec1-openssl xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel
        ;;
    opensuse*|suse|sles)
        echo "Using zypper to install dependencies"
        zypp_install="zypper --gpg-auto-import-keys --non-interactive install --no-recommends"
        $SUDO $zypp_install systemd-rpm-macros
        munge_ceph_spec_in $with_seastar $for_make_check $DIR/ceph.spec
        $SUDO $zypp_install $(rpmspec -q --buildrequires $DIR/ceph.spec) || exit 1
        $SUDO $zypp_install libxmlsec1-1 libxmlsec1-nss1 libxmlsec1-openssl1 xmlsec1-devel xmlsec1-openssl-devel
        ;;
    alpine)
        # for now we need the testing repo for leveldb
        TESTREPO="http://nl.alpinelinux.org/alpine/edge/testing"
        if ! grep -qF "$TESTREPO" /etc/apk/repositories ; then
            $SUDO echo "$TESTREPO" | sudo tee -a /etc/apk/repositories > /dev/null
        fi
        source alpine/APKBUILD.in
        $SUDO apk --update add abuild build-base ccache $makedepends
        if id -u build >/dev/null 2>&1 ; then
           $SUDO addgroup build abuild
        fi
        ;;
    *)
        echo "$ID is unknown, dependencies will have to be installed manually."
	exit 1
        ;;
    esac
fi

function populate_wheelhouse() {
    local install=$1
    shift

    # although pip comes with virtualenv, having a recent version
    # of pip matters when it comes to using wheel packages
    pip --timeout 300 $install 'setuptools >= 0.8' 'pip >= 7.0' 'wheel >= 0.24' || return 1
    if test $# != 0 ; then
        pip --timeout 300 $install $@ || return 1
    fi
}

function activate_virtualenv() {
    local top_srcdir=$1
    local interpreter=$2
    local env_dir=$top_srcdir/install-deps-$interpreter

    if ! test -d $env_dir ; then
        # Make a temporary virtualenv to get a fresh version of virtualenv
        # because CentOS 7 has a buggy old version (v1.10.1)
        # https://github.com/pypa/virtualenv/issues/463
        virtualenv ${env_dir}_tmp
        # install setuptools before upgrading virtualenv, as the latter needs
        # a recent setuptools for setup commands like `extras_require`.
        ${env_dir}_tmp/bin/pip install --upgrade setuptools
        ${env_dir}_tmp/bin/pip install --upgrade virtualenv
        ${env_dir}_tmp/bin/virtualenv --python $interpreter $env_dir
        rm -rf ${env_dir}_tmp

        . $env_dir/bin/activate
        if ! populate_wheelhouse install ; then
            rm -rf $env_dir
            return 1
        fi
    fi
    . $env_dir/bin/activate
}

# use pip cache if possible but do not store it outside of the source
# tree
# see https://pip.pypa.io/en/stable/reference/pip_install.html#caching
mkdir -p install-deps-cache
top_srcdir=$(pwd)
export XDG_CACHE_HOME=$top_srcdir/install-deps-cache
wip_wheelhouse=wheelhouse-wip

#
# preload python modules so that tox can run without network access
#
find . -name tox.ini | while read ini ; do
    (
        cd $(dirname $ini)
        require=$(ls *requirements.txt 2>/dev/null | sed -e 's/^/-r /')
        md5=wheelhouse/md5
        if test "$require"; then
            if ! test -f $md5 || ! md5sum -c $md5 ; then
                rm -rf wheelhouse
            fi
        fi
        if test "$require" && ! test -d wheelhouse ; then
            for interpreter in python2.7 python3 ; do
                type $interpreter > /dev/null 2>&1 || continue
                activate_virtualenv $top_srcdir $interpreter || exit 1
                populate_wheelhouse "wheel -w $wip_wheelhouse" $require || exit 1
            done
            mv $wip_wheelhouse wheelhouse
            md5sum *requirements.txt > $md5
        fi
    )
done

for interpreter in python2.7 python3 ; do
    rm -rf $top_srcdir/install-deps-$interpreter
done
rm -rf $XDG_CACHE_HOME
git --version || (echo "Dashboard uses git to pull dependencies." ; false)
