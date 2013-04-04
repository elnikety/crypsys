/**
 * Big integer header file
 */
#ifndef BIGINT_H_
#define BIGINT_H_

#include "limserv.h"

typedef struct BigInt{
	  int nBits;                    /* number of bits in bn                 */
	  int nBytes;                   /* number of bytes in bn                */
	  char nBuff[MAX_LIM_BUF_SIZE]; /* bn buffer                            */
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

int
BIpower(BigInt *a, BigInt *b, BigInt *n, BigInt *res);

int
BImod(BigInt *a, BigInt *n, BigInt *res);

int
BImul(BigInt *a, BigInt *b, BigInt *res);

//returns the number of bits in n
unsigned int
noOfBits(BigInt n);

#endif
