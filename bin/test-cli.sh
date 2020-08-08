#!/usr/bin/env bash

basedir=$( dirname $( readlink -f ${BASH_SOURCE[0]} ) )

php "${basedir}/minisign" -Vm "${basedir}/usage.txt" -P 9Gxq9/iRbNZeDzpF4SOwgwqTUt4v3A8gsPO9LktyQRI=
