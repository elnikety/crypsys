#ifndef DEFINITIONS_H_
#define DEFINITIONS_H_

#include "bigint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CHAR_ARRAY_LENGTH 1000
#define MAX_NUM_ARRAY_LENGTH 1000

typedef enum Bool{True, False} Bool;
typedef enum Bit{zero, one} Bit;

typedef struct BigIntList{
    BigInt n;
    struct BigIntList* next;
}BigIntList;

void BilInsert(BigIntList*, BigInt);

typedef struct BigIntListList{
  BigIntList* l;
  struct BigIntListList* next;
}BigIntListList;

void BillInsert(BigIntListList*, BigIntList*);

typedef struct Proof{
  char str[MAX_CHAR_ARRAY_LENGTH];
  BigIntListList* nat;
}Proof;

typedef struct PublicKey {
  BigInt n;
  BigInt gPrime;
  BigInt g;
  BigInt h;
  BigInt s;
  BigInt z;
  BigInt r0;
  BigInt r1;
  Proof prf;
}PublicKey;

//returns the number of bits in n
unsigned noOfBits(BigInt n);

void Abort(char *s)
{
  printf("%s\n",s);
  exit(0);
}

unsigned lengthBIL(BigIntList*);
unsigned lengthBILL(BigIntListList*);

typedef struct Key{
  BigInt bigGamma;
  BigInt rho;
  BigInt gamma;
}Key;

typedef Key RogueKey;

typedef struct rm{
  BigInt r;
  BigInt m;
}TupleRM;

typedef TupleRM Tuple;

typedef struct RandomNumber
{
  BigInt n;
}RandomNumber;

BigInt randomNumberIn(BigInt, BigInt);

/**********************Constants*********************/
const unsigned hash_bits = 160;
const unsigned rogue_modulus_bits = 1632;
const unsigned rogue_security_bits = 208;
const unsigned halfkeyBits = 104;
const unsigned rsa_modulus_bits = 2048;
const unsigned distribution_bits = 80;
const unsigned prime_total_bits = 368;
const unsigned prime_random_bits = 120;
const unsigned random_bits = 2536;
#endif
