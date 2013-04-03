/**
 * Big integer header file
 */
#ifndef BIGINT_H_
#define BIGINT_H_

#include "limserv.h"

typedef struct BigInt{
	  int bnBits;                    /* number of bits in bn                 */
	  int bnBytes;                   /* number of bytes in bn                */
	  char bnBuff[MAX_LIM_BUF_SIZE]; /* bn buffer                            */
} BigInt;

/**
 * returns res = a + b
 */
int
add(BigInt* a, BigInt* b, BigInt* res);

/**
 * returns res = a - b
 */
int
sub(BigInt* a, BigInt* b, BigInt* res);

#endif
