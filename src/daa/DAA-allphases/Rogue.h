#ifndef ROGUE_H_
#define ROGUE_H_

#include "Definitions.h"

TupleRM recoverR(BigInt bigGamma, BigInt rho)
{
  BigInt biOne;
  TupleRM R;
  BigInt bigGammaPrime = BIsub(bigGamma,biOne);
  R.r = BIdivide(bigGammaPrime, rho);
  R.m = BImod(bigGammaPrime, rho);
  return R;
}

void checkBase(RogueKey key, BigInt zeta)
{
  BigInt v = BImodPower(zeta, key.rho, key.bigGamma);
  BigInt BIone;
  char error[MAX_CHAR_ARRAY_LENGTH];
  if(BIcompare(v, BIone)!=0){
    strcpy(error,"ζ unusable");
    Abort(error);
  }
}

BigInt computeBase(char* bsn, RogueKey key)
{
  BigInt h;
  TupleRM rm;
  BigInt rhoPrime,i;
  BigInt biOne; //contant one
  if(bsn == NULL){
    rhoPrime = BIsub(key.rho, biOne);
    i = randomNumberIn(biOne, rhoPrime);
    return BImodPower(key.gamma, i, key.bigGamma);
  }
  else{
    rm = recoverR(key.bigGamma, key.rho);
    h = hashName(bsn);
    return BImodPower(h,rm.r,key.bigGamma);
  }
}

BigInt base(char* bsn, RogueKey key)
{
  BigInt zeta;
  zeta = computeBase(bsn,key);
  checkBase(key, zeta);
  return zeta;
}

BigInt tag(RogueKey key, BigInt zeta, BigInt f0, BigInt f1)
{
  BigInt ft,f; 
  char error[MAX_CHAR_ARRAY_LENGTH];
  ft = BIshiftLeft(f1, halfkeyBits);
  f = BIadd(f0,ft);
  if(BInoofBits(f) >= rogue_security_bits){
    strcpy(error,"tag");
    Abort(error); 
  }
  return BImodPower(zeta, f, key.bigGamma);
}

#endif
