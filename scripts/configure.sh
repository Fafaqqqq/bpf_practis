#!/bin/bash

PROJECT=bpf_test
CMAKE=cmake
PROFILE=Debug

BLDDIR=.build/$PROJECT/$PROFILE
[ ! -d "$BLDDIR" ] && mkdir -p $BLDDIR

[ ! -x "../bpf/vmlinux.h" ] && bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

cd $BLDDIR
$CMAKE -G Ninja -DCMAKE_BUILD_TYPE=$PROFILE $OLDPWD
cd $OLDPWD
