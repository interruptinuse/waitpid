#!/usr/bin/env bash
CR="$(cat RELEASE)"
read -e -i "$(IFS=. read -r -a CRA <<< "$CR" ; (( CRA[-1]++)) ; IFS=. ; echo "${CRA[*]}")" -r -p "$CR -> " NR
IFS=. read -r -a CRA <<< "$CR"
IFS=. read -r -a NRA <<< "$NR"
CR="$(echo "$CR" | sed 's,\.,\\.,g')"
CRC="$(IFS=, ; echo "${CRA[*]}")"
NRC="$(IFS=, ; echo "${NRA[*]}")"
[[ -z ${CR} ]] && { echo "Current release string is empty" ; exit 1 ; }
[[ -z ${NR} ]] && { echo     "New release string is empty" ; exit 1 ; }
sed -i "s/$CR/$NR/g"   RELEASE waitpid.rc
sed -i "s/$CRC/$NRC/g"         waitpid.rc
set -ex
git reset HEAD
git add RELEASE waitpid.rc
export TZ=UTC
git commit -m "v$NR"
git tag "v$NR" HEAD
