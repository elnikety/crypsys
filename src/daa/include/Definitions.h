#include "bigint.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CHAR_ARRAY_LENGTH 1000
#define MAX_NUM_ARRAY_LENGTH 1000

#define rsa_modulus_bits	2048
#define hash_bits	160

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
}PublicKey;

void Abort(char *s)
{
  printf("%s\n",s);
  exit(0);
}

unsigned int
lengthBIL(BigIntList*);

unsigned int
lengthBILL(BigIntListList*);
