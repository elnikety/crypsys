#include "Join.h"

char* keyHash(BigInt rho, char* daaSeed, char* pkPrimeHash, unsigned* cnt)
{
  char *result;
  return result;
}

Tuple key(RogueKey rogue, char* pkPrime)
{
  char daaSeed[MAX_CHAR_ARRAY_LENGTH], pkPrimeHash[MAX_CHAR_ARRAY_LENGTH];
  unsigned* cnt;
  char* h;
  BigInt f,f0,f1;
  Tuple ft;
  strcpy(daaSeed,"DAAseed");
  strcpy(pkPrimeHash,hashString(pkPrime));
  cnt = getCnt();
  h = keyHash(rogue.rho, daaSeed, pkPrimeHash, cnt);
  f = BImod(BIStringtoNumber(h),rogue.rho);
  f0 = BIextract(f,0,halfkeyBits);
  f1 = BIextract(f,0,halfkeyBits);
  return ft;
}

TripleJoinResult join(PublicKey group, RogueKey rogue, char* pkPrime, char* bsn)
{
  Tuple f0f1;
  BigInt zeta_I, n_I, vPrime, u;
  State state;
  TripleJoinResult r;
  unsigned  blinding_factor_bits = rsa_modulus_bits + distribution_bits ;
  f0f1 = key(rogue,pkPrime);
  zeta_I = base(bsn, rogue);
  n_I = tag(rogue, zeta_I, f0f1.r, f0f1.m);
  vPrime = getRandomNumber(blinding_factor_bits);
  u = blind(group, f0f1.r, f0f1.m, vPrime);
  state.group = group;
  state.rogue = rogue;
  state.f0 = f0f1.r;
  state.f1 = f0f1.m;
  state.zeta_I = zeta_I;
  state.n_I = n_I;
  state.vPrime = vPrime;
  state.u = u;
  r.s = state;
  r.U = u;
  r.N_I = n_I;
  return r;
}
