#include "Definitions.h"
#include "Rogue.h"

/*****************Group Setup*************************************************************/
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

BigInt bitCheckSum(BigInt n, BigInt h, BigInt g, Bit br, BigInt s)
{
  BigInt r;
  BigInt p,v;
  p = BIpower(h,s);
  v = BImod(p,n);
  br ? BImod(BImul(g,v),n) : v;
  return r;
}

BigInt ithCheckSum(BigInt n, char* b, BigInt g, BigInt h,unsigned i, BigInt s)
{
  BigInt r;
  Bit br;
  br = NumStringBit(b,i);
  r = bitCheckSum(n,h,g,br,s);
  return r;
}

BigIntList* logCheckSum(BigInt n, char* b, BigInt g, BigInt h, BigIntList* ss)
{
  BigIntList* rs;
  BigInt no;
  unsigned i = 0;
  while(ss!=NULL){
    no = ithCheckSum(n,b,g,h,i++, ss->n);
    BilInsert(rs,no);
    ss = ss->next;
  }
  return rs;
}

BigIntListList* fMap(BigInt n, char* b, BigIntList* gs, BigIntList* hs, BigIntListList* sss)
{
  BigIntListList *vss, *vssHead ;
  BigIntList* vs;
  while(gs!=NULL){
    vs = logCheckSum(n, b, gs->n,hs->n,sss->l);
    //Todo: allocate a list node 
    BillInsert(vss,vs);
    gs = gs->next;
    hs = hs->next;
    sss = sss->next;
    vss = vss->next;
  }
  return vss;
}

void ProveLogCheck(BigInt n, BigInt gPrime, BigIntList* gs, BigIntList* hs, Proof p)
{
  char error[MAX_CHAR_ARRAY_LENGTH];
  unsigned gl = lengthBIL(gs);
  unsigned hl = lengthBIL(hs);
  BigIntListList* vss;

  if(gl!=hl){
    strcpy(error,"verify");
    Abort(error);
  }
  if(strlen(p.str)*8 != hash_bits){
    strcpy(error,"bad challenge");
    Abort(error);
  }
  if (lengthBILL(p.nat)!=gl){
    strcpy(error,"bad response");
    Abort(error);
  }
  vss = fMap(n,p.str,gs,hs,p.nat);
}

void GroupCheck(PublicKey pk)
{
  BigIntList *gs, *hs;
  unsigned i;

  if(noOfBits(pk.n) != rsa_modulus_bits && \
      noOfBits(pk.gPrime) != rsa_modulus_bits && \
      noOfBits(pk.g) != rsa_modulus_bits && \
      noOfBits(pk.h) != rsa_modulus_bits && \
      noOfBits(pk.s) != rsa_modulus_bits && \
      noOfBits(pk.z) != rsa_modulus_bits && \
      noOfBits(pk.r0) != rsa_modulus_bits && \
      noOfBits(pk.r1) != rsa_modulus_bits \
      )
      exit(1);
   
   BilInsert(gs,pk.g);    BilInsert(gs,pk.h);    BilInsert(gs,pk.s);
   BilInsert(gs,pk.z);   BilInsert(gs,pk.r0);    BilInsert(gs,pk.r1);

   BilInsert(hs,pk.gPrime); BilInsert(hs,pk.gPrime);
   BilInsert(hs,pk.h); BilInsert(hs,pk.h);
   BilInsert(hs,pk.s); BilInsert(hs,pk.s);

   ProveLogCheck(pk.n, pk.gPrime, gs, hs, pk.prf);  
}
/******************************************************************************************/

/*****************Rogue Setup*************************************************************/
void RogueCheck(Key k)
{
  char error[MAX_CHAR_ARRAY_LENGTH];
  Tuple rm;
  BigInt biZero, biOne,v;

  if(noOfBits(k.bigGamma) != rogue_modulus_bits){
    strcpy(error,"Γ is out of bounds");
    Abort(error);
  }
  if(noOfBits(k.rho) != rogue_security_bits){
    strcpy(error,"ρ is out of bounds");
    Abort(error);
  }
  if(!BIisProbablyPrime(k.bigGamma)){
    strcpy(error,"Γ is composite");
    Abort(error);
  }
  if(!BIisProbablyPrime(k.rho)){
    strcpy(error,"ρ is composite");
    Abort(error);
  }
  rm = recoverR(k.bigGamma, k.rho);
  if(BIcompare(rm.m, biZero)!=0){
    strcpy(error,"ρ does not divide Γ - 1");
    Abort(error);
  }
  if(BIdivides(k.rho,rm.r)!=0){
    strcpy(error,"ρ divides r");
    Abort(error);
  }
  v = BImodPower(k.gamma, k.rho, k.bigGamma);
  if(BIcompare(v,biOne)!=0){
    strcpy(error,"γ bad");
    Abort(error);
  }
}
/*****************************************************************************************/
