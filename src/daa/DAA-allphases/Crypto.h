#ifndef CRYPTO_H_
#define CRYPTO_H_

#include "Definitions.h"

//used for hashing bsn
BigInt hashName(char* name);

char* hashString(char* s)
{
  char* hashedValue;

  // Do the hash here

  return hashedValue;
}

unsigned* getCnt();
BigInt getRandomNumber(unsigned);
typedef BigInt Hash;

Hash getSha1Hash();
void addBytes(Hash*, char*);
/*
sends the bytes of [n] to [h] in big-endian
order. */
void addBI(Hash* h, BigInt n);
char* hashResult(Hash);

#endif
