#include <Definitions.h>

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

  if(noOfBits(pk->n) != rsa_modulus_bits && \
      noOfBits(pk->gPrime) != rsa_modulus_bits && \
      noOfBits(pk->g) != rsa_modulus_bits && \
      noOfBits(pk->h) != rsa_modulus_bits && \
      noOfBits(pk->s) != rsa_modulus_bits && \
      noOfBits(pk->z) != rsa_modulus_bits && \
      noOfBits(pk->r0) != rsa_modulus_bits && \
      noOfBits(pk->r1) != rsa_modulus_bits \
      )
      exit(1);
   
   BilInsert(gs, pk->g);    BilInsert(gs, pk->h);    BilInsert(gs, pk->s);
   BilInsert(gs, pk->z);   BilInsert(gs, pk->r0);    BilInsert(gs, pk->r1);

   BilInsert(hs, pk->gPrime); BilInsert(hs, pk->gPrime);
   BilInsert(hs, pk->h); BilInsert(hs, pk->h);
   BilInsert(hs, pk->s); BilInsert(hs, pk->s);

   ProveLogCheck(pk->n, pk->gPrime, gs, hs, pk->prf);
}
