
#include "../include/Join.h"
#include "../include/Definitions.h"
#include <string.h>

extern void recoverR(BigInt *bigGamma, BigInt *rho, TupleRM *r);

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
