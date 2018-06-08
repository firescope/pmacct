#!/bin/bash
if [[ "$#" -ne 2 ]]; then
    echo "Usage: heathcheck.sh <executable name> <minimum expected number of running executable processes>" >&2;
    echo "Example: heathcheck.sh nfacctd 4" >&2;
    exit 1;
fi

count=$(pgrep -c $1);
if [[ $count -ge $2 ]]
  then
    echo "Number of $1 processes found: $count";
  else
    echo "Expecting $2 or more $1 processes running but detected $count" >&2;
    exit 1;
fi

pids="/var/run/pmacct/$1*.pid*";
for pid in $(cat $pids);
  do
    if [[ ! $(ps -p $pid) ]]
      then
        echo "Missing $1 process $pid" >&2;
        exit 1;
      else
        echo "Verified $1 process $pid is running";
      fi
  done

# Everything is healthy
exit 0;
