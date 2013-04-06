#include "Sign.h"

BigInt pick(unsigned numbits)
{
  return getRandomNumber(numbits);
}

Tuple pick2(unsigned numbits)
{
  Tuple r;
  r.r = pick(numbits); r.m = pick(numbits);
  return r;
}

BigInt rval(BigInt r, BigInt v, BigInt c)
{
  return BIadd(r, BImul(c,v));
}

extern void base(char* bsn, Key *key, BigInt *zeta);
extern void tag(Key *key, BigInt *zeta, BigInt *f0, BigInt *f1, BitInt *res);

void
sign(PublicKey *group, Key *rogue, Secret *secret, Cert *cert,
		Message *msg, SigNat *signat)
{
	  char bsn[MAX_CHAR_ARRAY_LENGTH], m[MAX_CHAR_ARRAY_LENGTH];
	  char error[MAX_CHAR_ARRAY_LENGTH],c_h[MAX_CHAR_ARRAY_LENGTH];
	  char hash[MAX_CHAR_ARRAY_LENGTH], inner[MAX_CHAR_ARRAY_LENGTH];

	  BigInt temp1, temp2, temp3, temp4, temp5, temp6, temp7;
	  BigInt tmp, rv, tilde_T1t;

	  TupleRM wr, rf0rf1;

	  int bits;

	  if(noOfBits(&msg->n_v) > hash_bits){
		    strcpy(error,"n_v out of bounds");
		    Abort(error);
	  }

	  bits = rsa_modulus_bits + distribution_bits;
	  get_rnd(&wr->r, bits);
	  get_rnd(&wr->m, bits);

	  BIpow(&group->h, &wr->r, &group->n, &tmp);
	  BImul(&cert->biga, &tmp, &tmp);
	  BImod(&tmp, &group->n, &signat->bigt1);

	  BIpow(&group->g, &wr->r, &temp1);
	  BIpow(&group->h, &cert->e, &temp2);
	  BIpow(&group->gPrime, &wr->m, &temp3);
	  BImul(&temp1, &temp2, &temp4);
	  BImul(&temp4, &temp3, &temp5);
	  BImod(&temp5, &group->n, &signat->bigt2);

	  base(msg->bsn, rogue, &signat->zeta);
	  tag(rogue, &signat->zerta, &secret->f, &secret->s, &signat->bign_V);

	  bits = random_bits + distribution_bits + hash_bits;
	  get_rnd(&rv, bits);

	  get_rnd(&rf0rf1->r, bits);
	  get_rnd(&rf0rf1->m, bits);

	  r0=group.r0; r1=group.r1; s=group.s;
	  rf0 = rf0rf1.r; rf1 = rf0rf1.m;

	  BIpow(&group->r0, &rf0rf1->r, &group->n, &temp1);
	  BIpow(&group->r1, &rf0rf1->m, &group->n, &temp2);
	  BIpow(&group->s, &rv, &group->n, &temp3);
	  BImul(&temp1, &temp2, &temp4);
	  BImul(&temp4, &temp3, &temp5);
	  BImod(&temp5, &group->n, &tilde_T1t);


}

SigNat sign(PublicKey group, RogueKey rogue, Secret secret, Cert cert, Message msg)
{
  char bsn[MAX_CHAR_ARRAY_LENGTH], m[MAX_CHAR_ARRAY_LENGTH];
  char error[MAX_CHAR_ARRAY_LENGTH],c_h[MAX_CHAR_ARRAY_LENGTH];
  char hash[MAX_CHAR_ARRAY_LENGTH], inner[MAX_CHAR_ARRAY_LENGTH];
  BigInt n_v, c, sv, sf0, sf1, se, see, sew, sr, ser, sw;
  Origin b;
  BigInt n,gPrime,g,h,r0,r1,s;
  BigInt biga,e, p2;
  BigInt f0,f1,v;
  Tuple wr,rf0rf1,rwrr,rewrer;
  BigInt bigt1, bigt2, temp1, temp2, temp3, temp4, temp5, temp6, temp7, w, r;
  BigInt zeta,bign_V,rf0,rf1, rv, bigt2inv, tilde_TPrime2,n_t;
  BigInt tilde_T1t, tilde_rf, tilde_N_V,rw,rr,re,ree,rew, rer,hinv, tilde_T1, tilde_T2;
  Hash hashPub, hashHost ,hashTpm1, hashTpm2;
  Responses ss;
  SigNat signat;

  strcpy(bsn,msg.bsn); strcpy(m,msg.m);
  b = msg.b; n_v = msg.n_v;

  n=group.n; gPrime=group.gPrime; g=group.g; h=group.h;
  r0=group.r0; r1=group.r1; s=group.s;
  
  biga = cert.biga; e = cert.e;
  f0 = secret.f; f1=secret.s; v=secret.t;

  wr = pick2(rsa_modulus_bits+distribution_bits);

  w = wr.r; r = wr.m;

  zeta = base(bsn,rogue);
  bign_V = tag(rogue,zeta,f0,f1);

  rv = pick(random_bits+distribution_bits+hash_bits);
  rf0rf1 = pick2(halfkeyBits+distribution_bits+hash_bits);
  rf0 = rf0rf1.r; rf1 = rf0rf1.m;
  
  temp1 = BIpower(r0,rf0); temp2 = BIpower(r1,rf1); temp3 = BIpower(s,rv);
  temp4 = BImul(temp1, temp2); temp5 = BImul(temp4, temp3);
  tilde_T1t = BImod(temp5,n);

  temp1 = BIshiftLeft(rf1,halfkeyBits);
  temp2 = BIadd(rf0, temp1);
  tilde_rf = BImod(temp2,rogue.rho);
  tilde_N_V = BImodPower(zeta,tilde_rf,rogue.bigGamma);
  
  re = pick(prime_random_bits+distribution_bits+hash_bits);
  ree = pick(2*prime_total_bits+distribution_bits+hash_bits+1);
  rwrr = pick2(rsa_modulus_bits+2*distribution_bits+hash_bits);
  rw = rwrr.r; rr = rwrr.m;
  rewrer = pick2(prime_total_bits+rsa_modulus_bits+2*distribution_bits+hash_bits+1);
  rew = rewrer.r; rer = rewrer.m;
  hinv = BImodInv(h,n);

  temp1 = tilde_T1t; temp2 = BIpower(bigt1,re); temp3 = BIpower(hinv,rew);
  temp4 = BImul(temp1, temp2); temp5 = BImul(temp4, temp3);
  tilde_T1 = BImod(temp5,n);

  temp1 = BIpower(g,rw); temp2 = BIpower(h,re); temp3 = BIpower(gPrime,rr);
  temp4 = BImul(temp1, temp2); temp5 = BImul(temp4, temp3);
  tilde_T2 = BImod(temp5,n);
  
  bigt2inv = BImodInv(bigt2,n);
  temp1 = BIpower(bigt2inv,re); temp2 = BIpower(g,rew); temp3 = BIpower(h,ree); temp4 = BIpower(gPrime,rer);
  temp5 = BImul(temp1, temp2); temp6 = BImul(temp5, temp3); temp7 = BImul(temp6, temp4);
  tilde_TPrime2 = BImod(temp7,n);

  //hash public inputs
  hashPub = getSha1Hash();
  addBI(&hashPub,group.n); addBI(&hashPub,group.g); addBI(&hashPub,group.gPrime); addBI(&hashPub,group.h);
  addBI(&hashPub,group.r0); addBI(&hashPub,group.r1); addBI(&hashPub,group.s); addBI(&hashPub,group.z);
  addBI(&hashPub,rogue.gamma); addBI(&hashPub,rogue.bigGamma); addBI(&hashPub,rogue.rho);
  addBI(&hashPub,zeta); addBI(&hashPub,bigt1); addBI(&hashPub,bigt2); addBI(&hashPub,bign_V);
  strcpy(hash,hashResult(hashPub));

  //hash host inputs
  hashHost = getSha1Hash();
  addBI(&hashHost,tilde_T1); addBI(&hashHost,tilde_T2); addBI(&hashHost,tilde_TPrime2);
  addBI(&hashHost,tilde_N_V); addBI(&hashHost,n_v);
  strcpy(c_h,hashResult(hashHost));

  n_t = pick(distribution_bits);
  
  hashTpm1 = getSha1Hash();
  addBytes(&hashTpm1,c_h); 
  addBI(&hashTpm1,n_t); 
  strcpy(inner,hashResult(hashTpm1));
  hashTpm2 = getSha1Hash();
  addBytes(&hashTpm2,inner); 
  if(b == Card)
    addByte(&hashTpm2,0);
  else if (b == Verifier)
    addByte(&hashTpm2,1);
  else
    ;
  addBytes(&hashTpm2, m);
  c = BItoNumber(hashResult(hashTpm2));
  sv = rval(rv,v,c);
  sf0 = rval(rf0,f0,c);
  sf1 = rval(rf1,f1,c);
  p2 = BIshiftLeft(BItoNumber("1"),prime_total_bits-1);
  se = rval(re,BIsub(e, p2),c);
  see = rval(ree,BImul(e,e),c);
  sw = rval(rw,w,c);
  sew = rval(rew,BImul(e,w),c);
  sr = rval(rr,r,c);
  ser = rval(rer,BImul(e,r),c);

  ss.sv = sv; 
  ss.sf0 = sf0; 
  ss.sf1 = sf1; 
  ss.se = se; 
  ss.see = see; 
  ss.sw = sw; 
  ss.sew = sew; 
  ss.sr = sr; 
  ss.ser = ser;
  
  signat.zeta = zeta;
  signat.bigt1 = bigt1;
  signat.bigt2 = bigt2;
  signat.bign_V = bign_V;
  signat.c = c;
  signat.n_t = n_t;
  signat.ss = ss;

  return signat;
}

