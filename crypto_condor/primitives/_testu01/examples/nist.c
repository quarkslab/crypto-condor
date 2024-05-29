#include <stdlib.h>

#include "gdef.h"
#include "swrite.h"
#include "bbattery.h"

// gcc nist.c -o nist -I../include -L../mylib/.libs -L../probdist/.libs -L../testu01/.libs -ltestu01 -lprobdist -lmylib -lm

int main(int argc, char** argv)
{
   swrite_Basic = FALSE;
   bbattery_NISTFile(argv[1], atof(argv[2]));
   return 0;
}
