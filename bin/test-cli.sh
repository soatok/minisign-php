#!/usr/bin/env bash

set -e
basedir=$( dirname $( readlink -f ${BASH_SOURCE[0]} ) )

# Collect garbage if a test failed:
if [ -f "${basedir}/usage.txt.minisig.minisig" ]; then
  unlink "${basedir}/usage.txt.minisig.minisig"
fi
if [ -f "${basedir}/minisign.key" ]; then
  unlink "${basedir}/minisign.key"
fi
if [ -f "${basedir}/minisign.pub" ]; then
  unlink "${basedir}/minisign.pub"
fi

php "${basedir}/minisign" -Vm "${basedir}/usage.txt" -P 9Gxq9/iRbNZeDzpF4SOwgwqTUt4v3A8gsPO9LktyQRI=

echo -e "\e[96mTesting minisign -G\e[39m"
printf "correct horse battery staple\ncorrect horse battery staple\n" | \
  php "${basedir}/minisign" -G -s "${basedir}/minisign.key" -p "${basedir}/minisign.pub"

echo -e "\e[96mTesting minisign -S\e[39m"
printf "correct horse battery staple\n" | \
  php "${basedir}/minisign" -S -m "${basedir}/usage.txt.minisig" -s "${basedir}/minisign.key"

echo -e "\e[96mTesting minisign -V\e[39m"
php "${basedir}/minisign" -V -m "${basedir}/usage.txt.minisig" -p "${basedir}/minisign.pub"

echo -e "\e[96mTesting minisign -S (with pre-hash)\e[39m"
printf "correct horse battery staple\n" | \
  php "${basedir}/minisign" -S -H -m "${basedir}/usage.txt.minisig" -s "${basedir}/minisign.key"

echo -e "\e[96mTesting minisign -V (with pre-hash)\e[39m"
php "${basedir}/minisign" -V -m "${basedir}/usage.txt.minisig" -p "${basedir}/minisign.pub"

# Cleanup...
unlink "${basedir}/usage.txt.minisig.minisig"
unlink "${basedir}/minisign.key"
unlink "${basedir}/minisign.pub"

echo -e "\e[92mCommand Line Interface OK\e[39m"
