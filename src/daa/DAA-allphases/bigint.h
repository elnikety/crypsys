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

BigInt BIpower(BigInt,BigInt);
BigInt BIdivide(BigInt,BigInt);
BigInt BImod(BigInt,BigInt);
BigInt BIadd(BigInt,BigInt);
BigInt BImul(BigInt,BigInt);
unsigned BIcompare(BigInt,BigInt);
BigInt BImodPower(BigInt,BigInt,BigInt);
unsigned BIdivides(BigInt,BigInt);
BigInt BIsub(BigInt,BigInt);
unsigned BIisProbablyPrime(BigInt);
BigInt BIStringtoNumber(char*);
BigInt BIextract(BigInt, unsigned, unsigned);
BigInt BIshiftLeft(BigInt, unsigned);

#endif
