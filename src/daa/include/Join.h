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

#endif
