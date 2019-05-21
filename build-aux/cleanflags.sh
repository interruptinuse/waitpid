#!/usr/bin/env bash
# Usage: CXXFLAGS="$(build-aux/cleanflags.sh "$CXXFLAGS")"

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  FLAGS=($1) ; shift 1

  unset RESULT
  typeset -a RESULT

  unset OPTS
  typeset -A OPTS

  for ((i=${#FLAGS[@]}-1; i>=0; i--)); do
    FLAG="${FLAGS[$i]}"
    case "$FLAG" in
      -std=*)
        if [[ -n ${OPTS[std]} ]]; then
          continue
        else
          OPTS[std]="$FLAG"
          RESULT+=("$FLAG")
        fi
        ;;
      *)
        RESULT+=("$FLAG")
        ;;
    esac
  done

  RESULTS=()
  for ((i=${#RESULT[@]}-1; i>=0; i--)); do
    RESULTS+=("${RESULT[$i]}")
  done

  IFS=" " echo "${RESULTS[*]}"
fi
