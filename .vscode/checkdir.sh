#!/bin/bash
if [ $# -lt 1 ]; then
    echo "error.. need args"
    exit 1
fi
if [ ! -d $1 ];then
mkdir $1
fi