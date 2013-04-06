#ifndef SIGN_H_
#define SIGN_H_

#include "Definitions.h"
#include "Join.h"
#include "Crypto.h"

typedef enum Origin{Card, Verifier} Origin;

typedef struct Message{
  char bsn[MAX_CHAR_ARRAY_LENGTH];
  char m[MAX_CHAR_ARRAY_LENGTH];
  Origin b;
  BigInt n_v;
}Message;

typedef struct Responses{
  BigInt sv;
  BigInt sf0;
  BigInt sf1;
  BigInt se;
  BigInt see;
  BigInt sw;
  BigInt sew;
  BigInt sr;
  BigInt ser;
}Responses;

typedef struct SigNat{
  BigInt zeta;
  BigInt bigt1;
  BigInt bigt2;
  BigInt bign_V;
  BigInt c;
  BigInt n_t;
  Responses ss;
}SigNat;

#endif
