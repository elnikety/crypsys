/* structs, types, constants and prototypes for pkaserv */
#if !defined(_pkaserv_h_)
#define _pkaserv_h_

#include "xc_types.h"

/* id for pka server */
#define PKASERV_PKA 0x7

/* maximum token length padded to the next multiple of 8 bytes */
#define MAX_PADDED_PKA_TOKEN_LENGTH 2504

/*  Status codes */

/* return code for signature verify operation if signature is correct */
#define PKA_CORRECT_SIG 1
/* return code for normal pka operations */
#define PKA_OK         0
/* unusual pka error detected */
#define PKA_WHAT      -1
/* bad parameter passed to a pka call */
#define PKA_BADPARM   -2
/* system error, such as malloc failure */
#define PKA_SYS_ERROR -3
/* pka operation failed */
#define PKA_FAIL      -4
/* signature not verified */
#define PKA_SIGN_VERIFY_FAIL -5

/* generate a key of type dsa */
#define DSA_KEYGEN 0
/* sign data with a dsa key */
#define DSA_SIGN 1
/* verify a signature of some data using the data and a key */
#define DSA_VERIFY 2
/* generate a key of type RSA */
#define RSA_KEYGEN 3
/* encrypt data using an RSA key */
#define RSA_ENC 4
/* decrypt data using an RSA key */
#define RSA_DEC 5

#pragma pack(1)
/* pka request header, contains all necessary info for any of the pka requests */
/* some fields may be left blank ( or zero ) if unused */
typedef struct pkaReqHdr_t
{
  /* user options, represents which pka operation to perform */
  unsigned long options;
  /* size of key to generate in bits */
  unsigned long bitSize;
  /* length of keyToken in bytes */
  unsigned long tokenLength;
  /* key to use, can be dsa or rsa depending on options */
  unsigned char keyToken[MAX_PADDED_PKA_TOKEN_LENGTH];
  /* length of signature in bytes, unused  otherwise */
  unsigned long signatureLength;
  /* signature if signing / verifying, otherwise unused */
  unsigned char signature[MAX_PADDED_PKA_TOKEN_LENGTH];
  /* length of data in bytes */
  unsigned long dataLength;
  /* data to sign/encrypt/decrypt/verify, etc */
  unsigned char data[MAX_PADDED_PKA_TOKEN_LENGTH];
  /* pad to make a multiple of 8 bytes */
  unsigned char pad[4]; 
}pkaReqHdr_t;
#pragma pack()

#pragma pack(1)
/* pka reply header */
typedef struct pkaRepHdr_t
{
  /* reply header length in bytes */
  unsigned long replyLength;
  /* process id of servicing thread */
  unsigned long pid;
  /* pad to make this struct at least 64 bytes long */
  unsigned char pad[ 64 - ( 2 * sizeof( unsigned long ) ) ];
}pkaRepHdr_t;
#pragma pack()

/*************************************************************************************/
/* the off card structures are used to store key tokens and signatures in a format   */
/* that can be used on the host system.  The 4765 stores these tokens using lengths  */
/* and pointers, but on the host, the pointer values would be useless.               */
/* after generating a key token or signature token on the card, these on card tokens */
/* are then translated into the off card token format, and passed back to the host   */
/* the process is reversed when sending offCard tokens as input to a card function   */
/* the tokens are passed from the host in the off card format, and then translated   */
/* into the on card token types consisting of lengths and pointers.                  */
/*************************************************************************************/

#pragma pack(1)
typedef struct offCardDSAToken_t {
  unsigned long key_type;           /* DSS key type          */
  unsigned long key_token_length;   /* Total length of token */
  unsigned long prime_p_bit_length; /* bit length of prime p  */

  unsigned long p_length;          /* big prime p      */
  unsigned long g_length;          /* generator g      */
  unsigned long x_length;          /* private exponent */
  unsigned long y_length;          /* public exponent  */
  unsigned long q_length;          /* small prime p    */

  unsigned long p_offset;          /* offset of p from start of token */
  unsigned long q_offset;          /* offset of q from start of token */
  unsigned long g_offset;          /* offset of g from start of token */
  unsigned long x_offset;          /* offset of x from start of token */
  unsigned long y_offset;          /* offset of y from start of token */

  unsigned char keydata_start;     /* start of key data */

}offCardDSAToken_t;
#pragma pack()

#pragma pack(1)
typedef struct offCardRSAToken_t
{   unsigned long  type;               /* RSA key type.               */
    unsigned long  tokenLength;        /* Total length of the token.  */
    unsigned long  n_BitLength;        /* Modulus n bit length.       */
                                       /* -- Start of the data length.*/
    unsigned long  n_Length;           /* Modulus n = p * q           */
    unsigned long  e_Length;           /* Public exponent e           */
                                       /*   e = 1/d * mod(p-1)(q-1)   */
    union
    {   unsigned long  p_Length;       /* Prime number p .            */
        unsigned long  d_Length;       /* Secret exponent d .         */
                                       /*   d = 1/e * mod(p-1)(q-1)   */
    } x;
    unsigned long  q_Length;           /* Prime number q .            */
    unsigned long  dpLength;           /* dp = d * mod(p-1) .         */
    unsigned long  dqLength;           /* dq = d * mod(q-1) .         */
    unsigned long  apLength;           /* ap = (q**(p-1)) * mod(n)    */
    unsigned long  aqLength;           /* aq = n + 1 - ap .           */
    unsigned long  r_Length;           /* Blinding value r .          */
    unsigned long  r1Length;           /* Blinding value 1/r .        */
                                       /* -- Start of the data offsets*/
    unsigned long  n_Offset;           /* Modulus n .                 */
    unsigned long  e_Offset;           /* Public exponent e .         */
    union
    {   unsigned long  p_Offset;       /* Prime number p .            */
        unsigned long  d_Offset;       /* Secret exponent d .         */
    } y;
    unsigned long  q_Offset;           /* Prime number q .            */
    unsigned long  dpOffset;           /* dp .                        */
    unsigned long  dqOffset;           /* dq .                        */
    unsigned long  apOffset;           /* ap .                        */
    unsigned long  aqOffset;           /* aq .                        */
    unsigned long  r_Offset;           /* Blinding value r .          */
    unsigned long  r1Offset;           /* Blinding value 1/r .        */
                                       /* -- Start of the variable -- */
    unsigned char  tokenData;          /* -- length token data.    -- */

}offCardRSAToken_t;
#pragma pack()

#pragma pack(1)
/* off card dsa signature token type */
typedef struct offCardDSASignature_t
{
  unsigned long signature_token_length; /* length of signature token in bytes */
  unsigned long r_length;               /* length of r in bytes               */
  unsigned long s_length;               /* length of s in bytes               */
  unsigned long r_offset;               /* offset of r from start of token    */
  unsigned long s_offset;               /* offset of s from start of token    */
  unsigned char signatureData;          /* start of signature data            */
}offCardDSASignature_t;

#pragma pack()
#endif
