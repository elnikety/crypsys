/**
 * Big integer header file
 */
#ifndef BIGINT_H_
#define BIGINT_H_

#include "../include/limserv.h"

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
BigInt BImodInv(BigInt a,BigInt n); // Computes the inverse of a mod n
unsigned BIcompare(BigInt f,BigInt s); // returns f - s
BigInt BImodPower(BigInt,BigInt,BigInt);
unsigned BIdivides(BigInt,BigInt);
BigInt BIsub(BigInt,BigInt);
unsigned BIisProbablyPrime(BigInt);
BigInt BIStringtoNumber(char*);
BigInt BIextract(BigInt, unsigned offset, unsigned len);//gives the number from the bit offset to the bit offset + len
BigInt BIshiftLeft(BigInt, unsigned);
char* BIgetBytes(BigInt);
BigInt BItoNumber(char*);

#endif
