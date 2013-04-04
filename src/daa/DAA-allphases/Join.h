#ifndef JOIN_H_
#define JOIN_H_

#include "Definitions.h"
#include "Crypto.h"
#include "Rogue.h"

typedef struct State{
  PublicKey group;
  RogueKey rogue;
  BigInt f0;
  BigInt f1;
  BigInt zeta_I;
  BigInt n_I;
  BigInt vPrime;
  BigInt u;
}State;

typedef struct TripleJoinResult{
  State s;
  BigInt U;
  BigInt N_I;
}TripleJoinResult;

typedef struct f0f1 {
  BigInt f0;
  BigInt f1;
}fof1;

BigInt blind(PublicKey group, BigInt f0, BigInt f1, BigInt vPrime)
{
  BigInt r0, r1, s, n, t0, t1, t2, t3, t4, result;
  r0 = group.r0; r1 = group.r1;
  s = group.s; n = group.n;
  t0 = BIpower(r0,f0);   t1 = BIpower(r1,f1);
  t2 = BIpower(s,vPrime);
  t3 = BImul(t0, t1);
  t4 = BImul(t2, t3);
  result = BImod(t4,n);
}

#endif
