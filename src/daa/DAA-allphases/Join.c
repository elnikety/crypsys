#include "Join.h"

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
  f1 = BIextract(f,halfkeyBits,halfkeyBits);
  return ft;
}

TripleJoinResult join(PublicKey group, RogueKey rogue, char* pkPrime, char* bsn)
{
  Tuple f0f1;
  BigInt zeta_I, n_I, vPrime, u, n_h;
  State state;
  TripleJoinResult r;
  unsigned  blinding_factor_bits = rsa_modulus_bits + distribution_bits ;
  f0f1 = key(rogue,pkPrime);
  zeta_I = base(bsn, rogue);
  n_I = tag(rogue, zeta_I, f0f1.r, f0f1.m);
  vPrime = getRandomNumber(blinding_factor_bits);
  u = blind(group, f0f1.r, f0f1.m, vPrime);
  n_h = getRandomNumber(distribution_bits);
  state.group = group;
  state.rogue = rogue;
  state.f0 = f0f1.r;
  state.f1 = f0f1.m;
  state.zeta_I = zeta_I;
  state.n_I = n_I;
  state.vPrime = vPrime;
  state.u = u;
  state.n_h = n_h;
  r.s = state;
  r.U = u;
  r.N_I = n_I;
  return r;
}

TripleBI joinRand()
{
  BigInt rf0,rf1,rvPrime;
  unsigned fbits,vPrimebits;
  TripleBI r;
  fbits = halfkeyBits + distribution_bits + hash_bits;
  rf0 = getRandomNumber(fbits);
  rf1 = getRandomNumber(fbits);
  vPrimebits = rsa_modulus_bits+2*distribution_bits+hash_bits;
  rvPrime = getRandomNumber(vPrimebits);
  r.f = rf0;   r.s = rf1; r.t = rvPrime;
  return r;
}

Tuple joinCommit(State state, TripleBI rs)
{
  Tuple res;
  PublicKey group;
  RogueKey rogue;
  BigInt zeta_I, rf0, rf1, rvPrime, tu, tn_I;
  group = state.group; rogue = state.rogue; zeta_I = state.zeta_I;
  rf0 = rs.f; rf1 = rs.s; rvPrime = rs.t;
  tu = blind(group, rf0, rf1, rvPrime);
  tn_I = tag(rogue, zeta_I, rf0, rf1);
  res.r = tu; res.m = tn_I;
  return res;
}

void joinHashInputs(char* hResult, PublicKey group, BigInt bign_I, BigInt bigu, BigInt n_i, BigInt n_t, BigInt vu, BigInt vn_I)
{
  BigInt n, r0, r1, s;
  Hash hash;
  char bytes[MAX_CHAR_ARRAY_LENGTH], c_h[MAX_CHAR_ARRAY_LENGTH];
  n = group.n; r0 = group.r0; r1 = group.r1; s = group.s;
  hash = getSha1Hash(); //new fresh hash value
  strcpy(bytes,BIgetBytes(n)); addBytes(&hash, bytes);
  strcpy(bytes,BIgetBytes(r0)); addBytes(&hash, bytes);
  strcpy(bytes,BIgetBytes(r1)); addBytes(&hash, bytes);
  strcpy(bytes,BIgetBytes(s)); addBytes(&hash, bytes);
  strcpy(bytes,BIgetBytes(bigu)); addBytes(&hash, bytes);
  strcpy(bytes,BIgetBytes(bign_I)); addBytes(&hash, bytes);
  strcpy(bytes,BIgetBytes(vu)); addBytes(&hash, bytes);
  strcpy(bytes,BIgetBytes(vn_I)); addBytes(&hash, bytes);
  strcpy(bytes,BIgetBytes(n_i)); addBytes(&hash, bytes);
  strcpy(c_h,hashResult(hash));
  hash = getSha1Hash();
  addBytes(&hash, c_h);
  strcpy(bytes,BIgetBytes(n_t)); addBytes(&hash, bytes);
  strcpy(hResult,hashResult(hash));
}

TripleBI joinRespond(State state, TripleBI rs, char* c)
{
  BigInt f0,f1,vPrime,rf0,rf1,rvPrime,cn,t1,sf0,sf1,svPrime;
  TripleBI res;
  f0 = state.f0; f1 = state.f1; vPrime = state.vPrime;
  rf0 = rs.f; rf1 = rs.s; rvPrime = rs.t;
  cn = BItoNumber(c);
  t1 = BImul(cn,rf0); sf0 = BIadd(t1,f0);
  t1 = BImul(cn,rf1); sf1 = BIadd(t1,f1);
  t1 = BImul(cn,rvPrime); svPrime = BIadd(t1,vPrime);
  res.f = sf0; res.s = sf1; res.t = svPrime;
  return res;
}

ProofNonce prove(State state, BigInt n_i)
{
  ProofNonce pn;
  PF pf;
  char error[MAX_CHAR_ARRAY_LENGTH], c[MAX_CHAR_ARRAY_LENGTH];
  TripleBI rs, ss;
  Tuple ts;
  BigInt n_t,n_I,u;
  PublicKey group;
  if(noOfBits(n_i) > hash_bits){
    strcpy(error,"n_i out of bounds");
    Abort(error);
  }
  rs = joinRand();
  ts = joinCommit(state, rs);
  n_t = getRandomNumber(distribution_bits);
  group = state.group; n_I = state.n_I; u = state.u;
  joinHashInputs(c, group, n_I, u, n_i, n_t, ts.r, ts.m);
  ss = joinRespond(state, rs, c);
  strcpy(pf.str,c);
  pf.n1 = n_t;
  pf.t1 = ss;
  pn.proof = pf;
  pn.n_h = state.n_h;
  return pn;
}
