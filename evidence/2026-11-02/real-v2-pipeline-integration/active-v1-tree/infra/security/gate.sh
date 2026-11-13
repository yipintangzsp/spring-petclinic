#!/bin/sh
# Record gate outcomes without concealing tool failures.
gate() {
  name=$1 mode=$2 code=$3 msg=$4
  case "$mode" in warn|enforce) ;; *) echo "Invalid gate mode for $name" >&2; return 2;; esac
  case "$code" in ''|*[!0-9]*) echo "Invalid gate exit status for $name" >&2; return 2;; esac
  mkdir -p .devsecops/gates
  printf 'name=%s\nmode=%s\nexit_code=%s\nmessage=%s\n' "$name" "$mode" "$code" "$msg" > ".devsecops/gates/$name.txt"
  if [ "$code" -ne 0 ]; then
    echo "GATE $name $mode: $msg (exit $code)" >&2
    if [ "$mode" = enforce ]; then return 1; fi
    touch .devsecops/gates/warnings
  fi
  return 0
}
