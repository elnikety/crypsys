#include <Definitions.h>

void Abort(char *s)
{
  printf("%s\n",s);
  exit(0);
}

/* === Group Setup === */

Bit NumStringBit(char* b, unsigned i)
{
  Bit bit;
  unsigned q,r,byte;
  unsigned nbits = 8*strlen(b);

  i = nbits - 1 - i;
  q = i / 8; i = i % 8; 
  i = 7 - i; byte = b[i] - '0';
  bit = (byte >> i)&1 ? one : zero;
  return bit;
}

void bitCheckSum(BigInt *n, BigInt *h, BigInt *g, Bit br,
		BigInt *s, BitInt *r)
{
  BigInt bip, biv;
  BigInt *p, *v;

  p = &bip;
  v = &biv;

  BIpower(h, s, n, p);
  BImod(p, n, v);

  if(br)
  {
	  BImul(g, v, r);
	  BImod(r, n, r);
  }
  else
  {
	  memcpy(r, v, sizeof(BigInt));
  }
}

void ithCheckSum(BigInt *n, char* b, BigInt *g, BigInt *h,
		unsigned i, BigInt *s, BitInt *r)
{
  Bit br;
  br = NumStringBit(b,i);

  bitCheckSum(n, h, g, br, s, r);
}

BigIntList* logCheckSum(BigInt *n, char* b, BigInt *g,
		BigInt *h, BigIntList* ss)
{
  BigIntList* rs;
  BigInt* no = malloc(sizeof(BigInt));
  unsigned i = 0;

  while(ss!=NULL){

    ithCheckSum(n,b,g,h,i++, ss->n, no);
    BilInsert(rs, no);
    ss = ss->next;

  }

  return rs;
}

BigIntListList* fMap(BigInt *n, char* b, BigIntList* gs,
		BigIntList* hs, BigIntListList* sss)
{
  BigIntListList *vss, *vssHead ;
  BigIntList* vs;

  while(gs!=NULL){

    vs = logCheckSum(n, b, gs->n, hs->n, sss->l);
    //Todo: allocate a list node 
    BillInsert(vss,vs);
    gs = gs->next;
    hs = hs->next;
    sss = sss->next;
    vss = vss->next;
  }

  return vss;
}

void ProveLogCheck(BigInt *n, BigInt *gPrime, BigIntList* gs,
		BigIntList* hs, Proof *p)
{
  char error[MAX_CHAR_ARRAY_LENGTH];
  unsigned gl = lengthBIL(gs);
  unsigned hl = lengthBIL(hs);
  BigIntListList* vss;

  if(gl!=hl){
    strcpy(error,"verify");
    Abort(error);
  }
  if(strlen(p->str)*8 != hash_bits){
    strcpy(error,"bad challenge");
    Abort(error);
  }
  if (lengthBILL(p->nat)!=gl){
    strcpy(error,"bad response");
    Abort(error);
  }
  vss = fMap(n, p->str, gs, hs, p->nat);

  //TODO free allocated BigInt
  // what do you do with vss?
}

void GroupCheck(PublicKey *pk)
{
  BigIntList *gs, *hs;
  unsigned i;

  //TODO allocate gs and hs

  if( noOfBits(&pk->n) != rsa_modulus_bits && \
      noOfBits(&pk->gPrime) != rsa_modulus_bits && \
      noOfBits(&pk->g) != rsa_modulus_bits && \
      noOfBits(&pk->h) != rsa_modulus_bits && \
      noOfBits(&pk->s) != rsa_modulus_bits && \
      noOfBits(&pk->z) != rsa_modulus_bits && \
      noOfBits(&pk->r0) != rsa_modulus_bits && \
      noOfBits(&pk->r1) != rsa_modulus_bits \
      )
      exit(1);
   
   BilInsert(gs, &pk->g);   BilInsert(gs, &pk->h);     BilInsert(gs, &pk->s);
   BilInsert(gs, &pk->z);   BilInsert(gs, &pk->r0);    BilInsert(gs, &pk->r1);

   BilInsert(hs, &pk->gPrime); 		BilInsert(hs, &pk->gPrime);
   BilInsert(hs, &pk->h); 			BilInsert(hs, &pk->h);
   BilInsert(hs, &pk->s); 			BilInsert(hs, &pk->s);

   ProveLogCheck(&pk->n, &pk->gPrime, gs, hs, &pk->prf);
}

/* === Rogue Setup === */
void recoverR(BigInt *bigGamma, BigInt *rho, TupleRM *r)
{

	BigInt one, gammaPrime;
	BigInt *biOne, *bigGammaPrime;

	biOne = &one;
	bigGammaPrime = &gammaPrime;

	setBI(biOne, 1);
	BIsub(bigGamma, biOne, bigGammaPrime);

	BIdiv(bigGammaPrime, rho, &r->r);
	BImod(bigGammaPrime, rho, &r->m);
}

void checkBase(Key *key, BigInt *zeta)
{
	BigInt vbi, *v, onebi, *one;
	char error[MAX_CHAR_ARRAY_LENGTH];

	v = &vbi;
	one = &onebi;

	BIpower(zerta, &key->rho, &key->bigGamma, v);
	setBI(one, 1);

	if(BIcmp(v, one) != 0)
	{
	    strcpy(error,"ζ unusable");
	    Abort(error);
	}
}

void computeBase(char* bsn, Key *key, BigInt *ret)
{
	BigInt hbi, *h, onebi, *one;
	BigInt rhoPbi, *rhoP, ibi, *i;
	TupleRM rm;

	h = &hbi;
	i = &ibi;
	one = &onebi;
	rhoP = &rhoPbi;

	setBI(one, 1);

	if(bsn)
	{
		recoverR(&key->bigGamma, &key->rho, &rm);
		hashName(bsn, h);
		BIpower(h, &rm.r, &key->bigGamma, ret);
	}
	else
	{
		BIsub(&key->rho, one, rhoP);
		get_rnd_range(i, one, rhoP);
		BIpower(&key->gamma, i, &key->bigGamma, ret);
	}
}

void base(char* bsn, Key *key, BigInt *zeta)
{
	computeBase(bsn, key, zeta);
	checkBase(key, zeta);
}

void tag(Key *key, BigInt *zeta, BigInt *f0, BigInt *f1, BitInt *res)
{
  BigInt ftbi, fbi, *ft, *f;
  char error[MAX_CHAR_ARRAY_LENGTH];

  ft = &ftbi;
  f = &fbi;

  BIshiftLeft(f1, halfkeyBits, ft);
  BIadd(f0, f1, f);

  if(noOfBits(f) >= rogue_security_bits){
	    strcpy(error,"tag");
	    Abort(error);
  }

  BIpower(zerta, f, &key->bigGamma, res);
}


void RogueCheck(Key *k)
{
  char error[MAX_CHAR_ARRAY_LENGTH];
  TupleRM rm;
  BigInt zero, one, v;
  BigInt *biZero, *biOne, *biv;

  setBI(biZero, 0);
  setBI(biOne, 1);

  if(noOfBits(&k->bigGamma) != rogue_modulus_bits){
    strcpy(error,"Γ is out of bounds");
    Abort(error);
  }

  if(noOfBits(&k->rho) != rogue_security_bits){
    strcpy(error,"ρ is out of bounds");
    Abort(error);
  }

  if(!isPrime(&k->bigGamma)){
    strcpy(error,"Γ is composite");
    Abort(error);
  }
  if(!isPrime(&k->rho)){
    strcpy(error,"ρ is composite");
    Abort(error);
  }

  recoverR(&k->bigGamma, &k->rho, &rm);

  if(BIcmp(&rm.m, biZero)!=0){
    strcpy(error,"ρ does not divide Γ - 1");
    Abort(error);
  }

  if(BIdivides(&k->rho, &rm.r)!=0){
    strcpy(error,"ρ divides r");
    Abort(error);
  }

  BIpower(&k->gamma, &k->rho, &k->bigGamma, biv);

  if(BIcmp(biv, biOne)!=0){
    strcpy(error,"γ bad");
    Abort(error);
  }

}
