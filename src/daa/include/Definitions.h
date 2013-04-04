#include "bigint.h"

#ifndef DEFINITIONS_H_
#define DEFINITIONS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CHAR_ARRAY_LENGTH 1000
#define MAX_NUM_ARRAY_LENGTH 1000

#define rsa_modulus_bits	2048
#define hash_bits	160
#define rogue_modulus_bits	1632
#define rogue_security_bits	208
#define halfkeyBits	104
#define distribution_bits	80

typedef enum Bool{True, False} Bool;
typedef enum Bit{zero, one} Bit;

typedef struct BigIntList{
    BigInt *n;
    struct BigIntList* next;
}BigIntList;

void BilInsert(BigIntList*, BigInt *bi);

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
} PublicKey;

typedef struct Key {
  BigInt bigGamma;
  BigInt rho;
  BigInt gamma;
} Key;

typedef struct rm {
  BigInt r;
  BigInt m;
} TupleRM;

unsigned int
lengthBIL(BigIntList*);

unsigned int
lengthBILL(BigIntListList*);

#endif
