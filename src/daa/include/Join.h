#ifndef JOIN_H_
#define JOIN_H_

#include "Definitions.h"
#include "bigint.h"
#include "Rogue.h"

typedef struct State {
  PublicKey group;
  Key rogue;
  BigInt f0;
  BigInt f1;
  BigInt zeta_I;
  BigInt n_I;
  BigInt vPrime;
  BigInt u;
} State;

typedef struct TripleJoinResult {
  State s;
  BigInt U;
  BigInt N_I;
} TripleJoinResult;

typedef struct TripleBI{
  BigInt f;
  BigInt s;
  BigInt t;
}TripleBI;

typedef TripleBI Secret;

typedef struct PF{
  char str[MAX_CHAR_ARRAY_LENGTH];
  BigInt n1;
  TripleBI t1;
}PF;

typedef struct ProofNonce{
  PF proof;
  BigInt n_h;
} ProofNonce;

typedef struct PFIssuer{
  char* cPrime;
  BigInt s_e;
} PFIssuer;

typedef struct Cert{
  BigInt biga;
  BigInt e;
} Cert;


#endif
