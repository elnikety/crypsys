
#include "../include/Join.h"
#include "../include/Definitions.h"
#include <string.h>

extern void recoverR(BigInt *bigGamma, BigInt *rho, TupleRM *r);

#define LONG_HASH_LEN	1800

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

void
blind(PublicKey *group, BigInt *f0, BigInt *f1, BigInt *vPrime, BigInt *res)
{
	  BigInt *r0, *r1, *s, *n, *t0, *t1, *t2, *t3, *t4;
	  BigInt t0bi, t1bi, t2bi, t3bi, t4bi;

	  s = &sbi;
	  n = &nbi;
	  t0 = &t0bi;
	  t1 = &t1bi;
	  t2 = &t2bi;
	  t3 = &t3bi;
	  t4 = &t4bi;

	  r0 = &group->r0;
	  r1 = &group->r1;

	  s = &group->s;
	  n = &group->n;

	  BIpower(r0, f0, n, t0);
	  BIpower(r1, f1, n, t1);
	  BIpower(s, vPrime, n, t2);

	  BImul(t0, t1, t3);
	  BImul(t2, t3, t4);
	  BImod(t4, n, res);
}

void
key(Key *rogue, char* pkPrime, TupleRM *tuple)
{
	//TODO
	char daaSeed[MAX_CHAR_ARRAY_LENGTH];
	char pkPrimeHash[MAX_CHAR_ARRAY_LENGTH];
	char resHash[MAX_CHAR_ARRAY_LENGTH];
	char *seed = "DAAseed";
	unsigned int count, hash_len;

	BigInt *f, fbi;

	hash_len = 1024;	//TODO
	f = &fbi;

	memcpy(daaSeed, seed, strlen(seed) + 1);
	hashString(pkPrime, strlen(pkPrime) + 1, pkPrimeHash);

	count = get_count();
	keyHash(&rogue->rho, daaSeed, pkPrimeHash, count, resHash);

	BIparse_and_partition(h, hash_len, f, &tuple->r, &tuple->m, halfkeyBits);
}

void
join(PublicKey *group, Key *rogue, char* pkPrime, char* bsn, TripleJoinResult* res)
{
	TupleRM f0f1;
	BigInt zeta_Ibi, *zeta_I, n_Ibi, *n_I;
	BigInt vPrimebi, *vPrime, ubi, *u;

	int blinding_factor_bits;

	blinding_factor_bits = rsa_modulus_bits + distribution_bits;
	key(rogue, pkPrime, &f0f1);

	get_rnd(vPrime, blinding_factor_bits);
	blind(group, &f0f1.r, &f0f1.m, vPrime, u);

	memcpy(&res->state.group, group, sizeof(PublicKey));
	memcpy(&res->state.rogue, rogue, sizeof(BigInt));
	memcpy(&res->state.f0, &f0f1.r, sizeof(BigInt));
	memcpy(&res->state.f1, &f0f1.m, sizeof(BigInt));
	memcpy(&res->state.zeta_I, zeta_I, sizeof(BigInt));
	memcpy(&res->state.n_I, n_I, sizeof(BigInt));
	memcpy(&res->state.vPrime, vPrime, sizeof(BigInt));
	memcpy(&res->state.u, u, sizeof(BigInt));

	memcpy(&res->state.n_I, n_I, sizeof(BigInt));
	memcpy(&res->state.u, u, sizeof(BigInt));
}

void
joinRand(TripleBI *r)
{
	int fbits, vPrimebits;

	fbits = halfkeyBits + distribution_bits + hash_bits;
	vPrimebits = rsa_modulus_bits + 2 * distribution_bits + hash_bits;

	get_rnd(&r->f, fbits);
	get_rnd(&r->s, fbits);
	get_rnd(&r->t, vPrimebits);
}

void
joinCommit(State *state, TripleBI *rs, TupleRM *res)
{
	blind(&state->group, &rs->f, &rs->s, &rs->t, &res->r);
	tag(&state->rogue, &state->zeta_I, &rs->f, &rs->s, &res->m);
}

void joinHashInputs(char* hResult, PublicKey *group,
		BigInt *bign_I, BigInt *bigu, BigInt *n_i,
		BigInt *n_t, BigInt *vu, BigInt *vn_I)
{

	  char bytes[MAX_CHAR_ARRAY_LENGTH], c_h[MAX_CHAR_ARRAY_LENGTH];
	  //TODO

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

void
joinRespond(State *state, TripleBI *rs, char *c, TripleBI *res)
{
	BigInt cnbi, *cn, t1bi, *t1;

	cn = &cnbi;
	t1 = &t1bi;

	setBI_char(c, cn);

	BImul(cn, &rs->f, t1);
	BIadd(t1, &state->f0, &res->f);

	BImul(cn, &rs->s, t1);
	BIadd(t1, &state->f1, &res->s);

	BImul(cn, &rs->t, t1);
	BIadd(t1, &state->vPrime, &res->t);
}

void
prove(State *state, BigInt *n_i, ProofNonce *pn)
{
	  PF *pf;
	  char error[MAX_CHAR_ARRAY_LENGTH], c[MAX_CHAR_ARRAY_LENGTH];
	  TripleBI rs;
	  TupleRM ts;

	  if(noOfBits(n_i) > hash_bits)
	  {
		    strcpy(error,"n_i out of bounds");
		    Abort(error);
	  }

	  pf = &pn->proof;

	  joinRand(&rs);
	  joinCommit(state, &rs, &ts);

	  get_rnd(&pf->n1, distribution_bits);

	  joinHashInputs(c, &state->group, &state->n_I, &state->u,
			  n_i, &pf->n1, &ts->r, &ts->m);

	  joinRespond(state, &rs, c, &pf->t1);
	  memcpy(pf->str, c, MAX_CHAR_ARRAY_LENGTH);

	  memcpy(&pn->n_h, &state->n_h, sizeof(BigInt));
}

void
computeA(PublicKey *pub, BigInt *bigu, BigInt *vDoublePrime,
		BigInt *power, BigInt *r)
{
	BigInt xy, denom, base;

	BIpower(&pub->s, vDoublePrime, &pub->n);
	BImul(bigu, &pub->n, &xy);
	BImod(&xy, n, &denom);

	BIinv(&denom, n, &xy);
	BImul(&pub->z, &xy, &xy);
	BImod(&xy, n, &base);

	BIpower(&base, power, n, r);
}

void
hashInputs(char* hashRes, PublicKey *pub, BigInt *bigu, BigInt *n_h,
		BigInt *vDoublePrime, BigInt *biga, BigInt *bigaPrime)
{
	char hash[MAX_CHAR_ARRAY_LENGTH];
	BigInt hashbi;

	getSha1Hash(hash, LONG_HASH_LEN);
	setBI_char(hash, &hashbi);

	//TODO

  Hash sha1hash;
  z = pub.z;s = pub.s;n = pub.n;
  sha1hash = getSha1Hash();
  addBI(&sha1hash,n); addBI(&sha1hash,z); addBI(&sha1hash,s); addBI(&sha1hash,bigu);
  addBI(&sha1hash,vDoublePrime); addBI(&sha1hash,biga); addBI(&sha1hash,bigaPrime);
  addBI(&sha1hash,n_h);
  strcpy(hashRes,hashResult(sha1hash));
}

//checker for issuers proof
void
check(State *state, PFIssuer *proof, Cert *cert, BigInt *vDoublePrime, Secret *secret)
{
	char error[MAX_CHAR_ARRAY_LENGTH], c[MAX_CHAR_ARRAY_LENGTH];
	BigInt u, minPrime, maxPrime, biOne, cPrimeNat;
	BigInt x, y, xy, bigahat, v;

	setBI(&biOne, 1);

	BIshiftLeft(&biOne, (prime_total_bits-1), &minPrime);


	BIshiftLeft(&biOne, (prime_random_bits-1), &maxPrime);
	BIadd(&minPrime, &maxPrime, &maxPrime);

	if(BIcmp(&cert->e, &minPrime) < 0 || BIcmp(&cert->e, &maxPrime) > 0)
	{
	    strcpy(error,"e out of range");
	    Abort(error);
	}

	if(!isPrime(&cert->e))
	{
	    strcpy(error,"e is not a prime");
	    Abort(error);
	}

	setBI_char(proof->cPrime, &cPrimeNat);
	BIpow(&cert->biga, &cPrimeNat, &pub->n, &x);

	computeA(pub, &state->u, vDoublePrime, &proof->s_e, &y);

	BImul(&x, &y, &xy);
	BImod(&xy, &pub->n, &bighat);
	//TODO you're using c without initializing it
	hashInputs(c, pub, &state->u, &state->n_h, vDoublePrime, &cert->biga, &bigahat);

	//TODO check LONG_HASH_LEN
	if(memcpy(c, proof->cPrime, LONG_HASH_LEN) != 0)
	{
	    strcpy(error,"Hashes dont match");
	    Abort(error);
	}

	BIadd(vDoublePrime, &state->vPrime, &v);
	memcpy(&secret->f, &state->f0, sizeof(BigInt));
	memcpy(&secret->s, &state->f1, sizeof(BigInt));
	memcpy(&secret->t, &v, sizeof(BigInt));
}
