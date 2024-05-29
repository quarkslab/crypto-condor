#!/bin/bash

FILE=$1
if [[ "$FILE" == "" ]]; then
  echo "Usage: $0 filename"
  exit 1
fi
if [ ! -f $FILE ]; then
  echo "File $FILE not found!"
  exit 1
fi

HOSTOS=$(uname | awk '{print toupper($0)}')
if [ "$HOSTOS" = "DARWIN" ]; then
  N=$(stat -L -f %z $FILE)
  echo "Size: $N bytes = $((N*8)) bits"
  DYLD_LIBRARY_PATH="mylib/.libs:probdist/.libs:testu01/.libs" examples/nist $FILE $((N*8))
else
  N=$(stat -L -c %s $FILE)
  echo "Size: $N bytes = $((N*8)) bits"
  LD_LIBRARY_PATH="mylib/.libs:probdist/.libs:testu01/.libs" examples/nist $FILE $((N*8))
fi
