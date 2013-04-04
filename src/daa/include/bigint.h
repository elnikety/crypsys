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

int
BIpower(BigInt *a, BigInt *b, BigInt *n, BigInt *res);

int
BImod(BigInt *a, BigInt *n, BigInt *res);

int
BImul(BigInt *a, BigInt *b, BigInt *res);

int
BIdiv(BigInt *a, BigInt *b, BigInt *res);

int
BIsub(BigInt *a, BigInt *b, BigInt *res);

int
BIadd(BigInt *a, BigInt *b, BigInt *res);

int
BIcmp(BigInt *a, BigInt *b);

int
isPrime(BigInt *p);

int
BIdivides(BigInt *a, BigInt *b);

int
setBI(BigInt *n, int value);

//returns the number of bits in n
unsigned int
noOfBits(BigInt n);

/* rng functions */
int
get_rnd(BigInt *n, int bits);

int
get_rnd_prime(BigInt *p, int bits);

int
get_rnd_range(BigInt *n, BigInt *min, BigInt *max);

int
get_rnd_prime_range(BigInt *p, BigInt *min, BigInt *max);

/* shift operators */
int
BIshiftLeft(BigInt *n, int shift, BigInt *res);

#endif
