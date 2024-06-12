#!/bin/bash

CC="${CC:-/usr/bin/cc}"
set -e
(
  cd testu01
  # pdflatex guidetestu01.tex
  # pdflatex guidetestu01.tex
)

sh ./bootstrap
./configure
make
(
  cd examples
  $CC nist.c -o nist -I../include -L../mylib/.libs -L../probdist/.libs -L../testu01/.libs -ltestu01 -lprobdist -lmylib -lm
)
echo -e "\nDone!\nTo execute the NIST suites:"
echo 'LD_LIBRARY_PATH="mylib/.libs;probdist/.libs;testu01/.libs" examples/nist <file> <nr_bits>'
# echo -e "Documentation is available here:\ntestu01/guidetestu01.pdf"

# Example computing automatically the bitsize
# FILE=foobar
# N=$(stat -L -c %s $FILE)
# echo "Size: $N bytes = $((N*8)) bits"
# LD_LIBRARY_PATH="$(pwd)/mylib/.libs;$(pwd)/probdist/.libs;$(pwd)/testu01/.libs" $(pwd)/examples/nist $FILE $((N*8))
