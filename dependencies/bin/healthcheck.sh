#!/bin/bash
if [ "$#" -ne 2 ]; then
    echo "Usage: heathcheck.sh <executable name> <expected number of running executable processes>";
    echo "Example: heathcheck.sh nfacctd 4";
    exit 1;
fi


count=`pgrep -c $1`;
if [ $count -ne $2 ]
  then
    echo "Expecting $2 $1 processes running but detected $count";
    exit 1;
  else
    echo "Found expected number($count) of $1 processes";
fi

pids="/var/run/pmacct/$1*.pid*";
for pid in `cat $pids`;
  do
    if ! ps -p $pid > /dev/null
      then
        echo "$1 process $pid not found";
        exit 1;
      else
        echo "$1 process $pid is running";
      fi
  done

# Everything is healthy
exit 0;
