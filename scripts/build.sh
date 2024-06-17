#!/bin/bash

PROJECT=bpf_test
CMAKE=cmake
PROFILE=Debug

CURR_DIR=$PWD

BLDDIR=.build/$PROJECT/$PROFILE

$CMAKE --build $BLDDIR -- -j8
