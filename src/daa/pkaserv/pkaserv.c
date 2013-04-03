/*********************************************************************** 
 * pkaserv.c - Skeleton PKA Encrypt, Decrypt, Sign, & Verify server.   * 
 *             This function shows how to use the yCrypto PKA key      * 
 *             generation, encryption, decryption, signature, and      * 
 *             verification services. Key transport is not meant to    *
 *             be a secure example.                                    *
 *                                                                     * 
 ***********************************************************************/

#include <stdlib.h>   /* for malloc, et al         */
#include <string.h>   /* for memset et al          */
#include <pthread.h>  /* for pthread_self          */

#include "xc_types.h" /* xCrypto types             */
#include "xc_api.h"   /* xCrypto api calls         */

#include "skelcmn.h"  /* common skeleton functions */
#include "pkaservi.h" /* header for this file      */

void 
pkaServer( xcVirtualPacket_t * pVPkt,
           responseStruct    * pResponse )
{

  pkaReqHdr_t    *pPKAReqHdr = NULL;/* pointer to request header from host*/
  pkaRepHdr_t     replyHdr;         /* reply header to host               */
  pthread_t       pid = pthread_self( ); /* process id for this thread    */

  unsigned long   userRequest = 0;  /* which pka related task chosen   */
  unsigned char  *pKey = NULL;      /* pointer to key passed from host */

  unsigned long   bitSize     = 0;  /* bit size of key                        */
  unsigned long   tokenLength = 0;  /* length of token passed from host       */
  unsigned long   dataLength  = 0;  /* length of data buffer passed from host */
  unsigned long    signatureLength = 0;  /* length of signature in bytes      */
  unsigned char   *pSignature = NULL;    /* pointer to signature              */
  unsigned char   *pData = NULL;         /* pointer to data var in host header*/

  /* initialize vars */
  memset( &replyHdr, 0x00, sizeof( pkaRepHdr_t ) );

  /* grab header information, even if it is not all used */
  pPKAReqHdr = (pkaReqHdr_t *)&(pVPkt->data_start);
  pKey = (unsigned char *)pPKAReqHdr->keyToken;
  pData = (unsigned char *)pPKAReqHdr->data;
  bitSize = pPKAReqHdr->bitSize;
  userRequest = pPKAReqHdr->options;
  tokenLength = pPKAReqHdr->tokenLength;
  signatureLength = pPKAReqHdr->signatureLength;
  pSignature = (unsigned char *)pPKAReqHdr->signature;
  dataLength = pPKAReqHdr->dataLength;

  /* process request */
  switch( userRequest )
  {
    case DSA_KEYGEN:
      /* generate a DSA key */
      DSAKeyGenerate( pResponse, bitSize );
    break;

    case DSA_SIGN:
    case DSA_VERIFY:
      /* sign or verify */
     DSASignVerify( pResponse,
                    pKey,
                    pData,
                    dataLength,
                    pSignature,
                    signatureLength,
                    userRequest );
    break;

    case RSA_KEYGEN:
      /* Generate a key of type DSA */
      RSAKeyGenerate( pResponse, bitSize );
    break;

    case RSA_ENC:
    case RSA_DEC:
      /* encrypt or decrypt with RSA */
      RSAEncryptOrDecrypt( pResponse,
                           userRequest,
                           pKey,
                           pData,
                           dataLength );
    break;

    default:
      /* what happened? we shouldn't get here  */
      /* send back a dummy response */
      createDummyResponse( pResponse, PKA_WHAT, pid );
    break;
  }

  replyHdr.replyLength = pResponse->dataLength;
  replyHdr.pid = (unsigned long)pid;

  pResponse->headerLength = sizeof( pkaRepHdr_t );
  memcpy( pResponse->header, &replyHdr, pResponse->headerLength );

  return;
}

/* sign or verify some data */
void  
DSASignVerify( responseStruct * pResponse,
               unsigned char  * pKey,
               unsigned char  * pData,
               unsigned long    dataLength,
               unsigned char  * pSignature,
               unsigned long    signatureLength,
               int              userRequest )
{

  /* return code */
  int rc = 0;
  /* reply length in bytes */
  int replyLength = 0;
  /* key always comes from host in off card format */
  offCardDSAToken_t *pOffCardDSAToken = (offCardDSAToken_t *)pKey;
  /* we will translate off card key to xcDSAKeyToken_t format */
  xcDSAKeyToken_t *pDSAKeyToken = NULL;
  /* request block for sign/verify request */
  xcDSA_RB_t *pDSA_rb;
  /* pointer to signature token in xCrypto format */
  xcDSASignatureToken_t *pDSASignatureToken = NULL;
  /* pointer to off card signature */
  offCardDSASignature_t *pOffCardDSASignature = NULL;

  /* allocate memory, check allocation, memset */
  pDSAKeyToken = (xcDSAKeyToken_t *) malloc( MAX_PADDED_PKA_TOKEN_LENGTH );
  pDSA_rb = (xcDSA_RB_t *)malloc(sizeof(xcDSA_RB_t) );
  pDSASignatureToken = (xcDSASignatureToken_t *)malloc( sizeof( xcDSASignatureToken_t ) + 40);

  /* check that allocations gave back valid data */
  if( pDSAKeyToken == NULL  || pDSA_rb == NULL || pDSASignatureToken == NULL )
  {
    if( pDSA_rb )
      free( pDSA_rb );
    if( pDSAKeyToken )
      free( pDSAKeyToken );
    if( pDSASignatureToken )
      free( pDSASignatureToken );
    /* send back a dummy response with system error as rc */
    createDummyResponse( pResponse, PKA_SYS_ERROR, pthread_self() );
    return;
  }

  /* initialize variables */
  memset( pDSAKeyToken, 0x00, MAX_PADDED_PKA_TOKEN_LENGTH );
  memset( pDSA_rb, 0x00, sizeof( xcDSA_RB_t ) );
  memset( pDSASignatureToken, 0x00, sizeof(xcDSASignatureToken_t ) + 40 );

  /* convert to a token type the card understands */
  convertFromOffCardDSAToken( pOffCardDSAToken, pDSAKeyToken );

  /* set up signature as needed */
  if( userRequest == DSA_SIGN )
  {
    /* if request is for sign, simply set up pointers to give xcDSA a place */
    /* to put the signature */
    pDSASignatureToken->signature_token_length = sizeof(xcDSASignatureToken_t);
    pDSASignatureToken->r_length = 20;/* always fixed at 20 */
    pDSASignatureToken->s_length = 20;/* always fixed at 20 */
    pDSASignatureToken->r_Ptr = (unsigned char *)pDSASignatureToken +
                                sizeof(xcDSASignatureToken_t);
    pDSASignatureToken->s_Ptr = (unsigned char*)pDSASignatureToken +
                                sizeof(xcDSASignatureToken_t) +
                                pDSASignatureToken->r_length;
  }
  else  //DSA verify
  {
    /* if request is for verify, we need to translate the signature from the */
    /* off card format, to the on card format */
    offCardDSASignature_t *pTempOffCardSig = (offCardDSASignature_t*)pSignature;

    pDSASignatureToken->signature_token_length = sizeof(xcDSASignatureToken_t);
    pDSASignatureToken->r_length = 20; /* always 20 */
    pDSASignatureToken->s_length = 20; /* always 20 */

    pDSASignatureToken->r_Ptr = (unsigned char*)pDSASignatureToken +
                                sizeof( xcDSASignatureToken_t );
    pDSASignatureToken->s_Ptr = (unsigned char*)pDSASignatureToken +
                                 sizeof( xcDSASignatureToken_t ) +
                                pDSASignatureToken->r_length;

    memcpy( pDSASignatureToken->r_Ptr, (unsigned char*)pSignature +
                                pTempOffCardSig->r_offset,
                                pTempOffCardSig->r_length );

    memcpy( pDSASignatureToken->s_Ptr, (unsigned char*)pSignature +
                                pTempOffCardSig->s_offset,
                                pTempOffCardSig->s_length );

  }

  /* set up request block */
  pDSA_rb->key_token = pDSAKeyToken;
  pDSA_rb->sig_token = pDSASignatureToken;
  pDSA_rb->data = pData;
  pDSA_rb->data_size = dataLength;
  pDSA_rb->key_token_size = sizeof(xcDSAKeyToken_t);
  pDSA_rb->sig_token_size = sizeof(xcDSASignatureToken_t);

  /* set options to reflect user's choice */
  if( userRequest == DSA_SIGN )
  {
    pDSA_rb->options = DSA_SIGNATURE_SIGN;
  }
  else //userRequest == DSA_VERIFY
  {
     pDSA_rb->options = DSA_SIGNATURE_VERIFY;
     /* key type must be public for verify operation */
     pDSA_rb->key_token->key_type = DSA_PUBLIC_KEY_TYPE;
  }

  /* call xCrypto DSA Service */
  rc = xcDSA( getFileDescriptor( FD_PKA ),
              pDSA_rb );


  /* if the sign/ verify failed, return a dummy block of data */
  if( rc == PKA_OK )
  {
    /* otherwise, translate to an off card dsa signature type */
    /* and send back */

    pResponse->status = PKA_OK;

    pOffCardDSASignature = (offCardDSASignature_t*)pResponse->data;
    pOffCardDSASignature->signature_token_length = sizeof(offCardDSASignature_t) +
                                                   pDSASignatureToken->r_length +
                                                   pDSASignatureToken->s_length -1;
    pOffCardDSASignature->r_length = pDSASignatureToken->r_length;
    pOffCardDSASignature->s_length = pDSASignatureToken->s_length;
    pOffCardDSASignature->r_offset = sizeof(offCardDSASignature_t) -1;
    pOffCardDSASignature->s_offset = sizeof(offCardDSASignature_t) -1 +
                                     pOffCardDSASignature->r_length;

    memcpy( (unsigned char*)pOffCardDSASignature + pOffCardDSASignature->r_offset,
            pDSASignatureToken->r_Ptr,
            pDSASignatureToken->r_length );

    memcpy( (unsigned char*)pOffCardDSASignature + pOffCardDSASignature->s_offset,
            pDSASignatureToken->s_Ptr,
            pDSASignatureToken->s_length );


    replyLength = ( (pOffCardDSASignature->signature_token_length + 7) / 8  ) * 8 ;
    pResponse->dataLength = replyLength;
  }
  else
  {
    createDummyResponse( pResponse, PKA_SIGN_VERIFY_FAIL, pthread_self( ) );
  }

  /* free all memory malloc'd by this function */
  if( pDSA_rb )
    free( pDSA_rb );
  if( pDSAKeyToken )
    free( pDSAKeyToken );
  if( pDSASignatureToken )
    free( pDSASignatureToken );

  return;
}

/* converts from an off card token to an on card token */
int 
convertFromOffCardDSAToken( offCardDSAToken_t * pOffCardDSAToken,
                            xcDSAKeyToken_t   * pDSAKeyToken )
{
  if( pOffCardDSAToken == NULL || pDSAKeyToken == NULL )
    return -1;

  pDSAKeyToken->key_type = pOffCardDSAToken->key_type;
  pDSAKeyToken->key_token_length = sizeof(xcDSAKeyToken_t);
  pDSAKeyToken->prime_p_bit_length = pOffCardDSAToken->prime_p_bit_length;
  pDSAKeyToken->p_length = pOffCardDSAToken->p_length;
  pDSAKeyToken->g_length = pOffCardDSAToken->g_length;
  pDSAKeyToken->x_length = pOffCardDSAToken->x_length;
  pDSAKeyToken->y_length = pOffCardDSAToken->y_length;
  pDSAKeyToken->q_length = pOffCardDSAToken->q_length;

  /* P */
  pDSAKeyToken->p_Ptr = (unsigned char*)pDSAKeyToken  +
                        sizeof( xcDSAKeyToken_t ) +
                        pOffCardDSAToken->p_offset;

  memcpy( pDSAKeyToken->p_Ptr,
          (unsigned char*)pOffCardDSAToken + sizeof(offCardDSAToken_t) -1 +
          pOffCardDSAToken->p_offset,
          pOffCardDSAToken->p_length );

  /* Q */
  pDSAKeyToken->q_Ptr = (unsigned char*)pDSAKeyToken +
                        sizeof( xcDSAKeyToken_t ) +
                        pOffCardDSAToken->q_offset;

  memcpy( pDSAKeyToken->q_Ptr,
          (unsigned char*)pOffCardDSAToken + sizeof(offCardDSAToken_t) -1 +
          pOffCardDSAToken->q_offset,
          pOffCardDSAToken->q_length );

  /* G */
  pDSAKeyToken->g_Ptr = (unsigned char*)pDSAKeyToken +
                        sizeof( xcDSAKeyToken_t )  +
                        pOffCardDSAToken->g_offset;

  memcpy( pDSAKeyToken->g_Ptr,
          (unsigned char*)pOffCardDSAToken + sizeof(offCardDSAToken_t) -1 +
          pOffCardDSAToken->g_offset,
          pOffCardDSAToken->g_length );

  /* X */
  pDSAKeyToken->x_Ptr = (unsigned char*)pDSAKeyToken +
                        sizeof( xcDSAKeyToken_t )  +
                        pOffCardDSAToken->x_offset;

  memcpy( pDSAKeyToken->x_Ptr,
          (unsigned char*)pOffCardDSAToken + sizeof(offCardDSAToken_t) -1 +
          pOffCardDSAToken->x_offset,
          pOffCardDSAToken->x_length );


  /* Y */
  pDSAKeyToken->y_Ptr = (unsigned char*)pDSAKeyToken +
                        sizeof( xcDSAKeyToken_t )  +
                        pOffCardDSAToken->y_offset;

  memcpy( pDSAKeyToken->y_Ptr,
          (unsigned char*)pOffCardDSAToken + sizeof(offCardDSAToken_t) -1 +
          pOffCardDSAToken->y_offset,
          pOffCardDSAToken->y_length );

  return 0;
}

/* converts from an off card rsa token to an on card token */
int convertFromOffCardRSAToken( offCardRSAToken_t * pOffCardRSAToken,
                                xcRsaKeyToken_t   * pRSAKeyToken )
{
  int rc = 0;

  if( pOffCardRSAToken == NULL || pRSAKeyToken == NULL )
    return -1;

  /* no need to byte reverse...stored in card format */
  //pRSAKeyToken = (xcRsaKeyToken_t*)pTempBuffer;

  pRSAKeyToken->type = pOffCardRSAToken->type;
  /* token length is always the size of xcRSAKeyToken_t */
  /* pOffCardRSAToken->tokenLength represents the scc style length */
  /* and should not be used here */
  pRSAKeyToken->tokenLength = sizeof(xcRsaKeyToken_t);
  pRSAKeyToken->n_BitLength = pOffCardRSAToken->n_BitLength;
  pRSAKeyToken->n_Length = pOffCardRSAToken->n_Length;
  pRSAKeyToken->e_Length = pOffCardRSAToken->e_Length;
  pRSAKeyToken->x.p_Length = pOffCardRSAToken->x.p_Length;
  pRSAKeyToken->q_Length = pOffCardRSAToken->q_Length;
  pRSAKeyToken->dpLength = pOffCardRSAToken->dpLength;
  pRSAKeyToken->dqLength = pOffCardRSAToken->dqLength;
  pRSAKeyToken->apLength = pOffCardRSAToken->apLength;
  pRSAKeyToken->aqLength = pOffCardRSAToken->aqLength;
  pRSAKeyToken->r_Length = pOffCardRSAToken->r_Length;
  pRSAKeyToken->r1Length = pOffCardRSAToken->r1Length;

  /* N */
  pRSAKeyToken->n_Ptr = (unsigned char*)pRSAKeyToken +
                        sizeof(xcRsaKeyToken_t)  +
                        pOffCardRSAToken->n_Offset;

  memcpy( pRSAKeyToken->n_Ptr,
          (unsigned char *)pOffCardRSAToken + sizeof(offCardRSAToken_t) -1 +
          pOffCardRSAToken->n_Offset,
          pOffCardRSAToken->n_Length );


  /* E */
  pRSAKeyToken->e_Ptr = (unsigned char*)pRSAKeyToken +
                        sizeof(xcRsaKeyToken_t)  +
                        pOffCardRSAToken->e_Offset;

  memcpy( pRSAKeyToken->e_Ptr,
          (unsigned char *)pOffCardRSAToken + sizeof(offCardRSAToken_t) -1 +
          pOffCardRSAToken->e_Offset,
          pOffCardRSAToken->e_Length );


  /* P */
  pRSAKeyToken->y.p_Ptr = (unsigned char*)pRSAKeyToken +
                          sizeof(xcRsaKeyToken_t)  +
                          pOffCardRSAToken->y.p_Offset;

  memcpy( pRSAKeyToken->y.p_Ptr,
          (unsigned char*)pOffCardRSAToken + sizeof(offCardRSAToken_t) -1  + pOffCardRSAToken->y.p_Offset,
          pOffCardRSAToken->x.p_Length );


  /* Q */
  pRSAKeyToken->q_Ptr = (unsigned char*)pRSAKeyToken +
                        sizeof(xcRsaKeyToken_t)  +
                        pOffCardRSAToken->q_Offset;

  memcpy( pRSAKeyToken->q_Ptr,
          (unsigned char*)pOffCardRSAToken + sizeof(offCardRSAToken_t) -1  + pOffCardRSAToken->q_Offset,
          pOffCardRSAToken->q_Length );


  /* dp */

  pRSAKeyToken->dpPtr = (unsigned char*)pRSAKeyToken +
                        sizeof(xcRsaKeyToken_t)  +
                        pOffCardRSAToken->dpOffset;

  memcpy( pRSAKeyToken->dpPtr,
          (unsigned char*)pOffCardRSAToken + sizeof(offCardRSAToken_t)  -1 + pOffCardRSAToken->dpOffset,
          pOffCardRSAToken->dpLength );

  /* dq */
  pRSAKeyToken->dqPtr = (unsigned char*)pRSAKeyToken +
                        sizeof(xcRsaKeyToken_t)  +
                        pOffCardRSAToken->dqOffset;

  memcpy( pRSAKeyToken->dqPtr,
          (unsigned char*)pOffCardRSAToken + sizeof(offCardRSAToken_t)  -1 + pOffCardRSAToken->dqOffset,
          pOffCardRSAToken->dqLength );

  /* ap */
  pRSAKeyToken->apPtr = (unsigned char*)pRSAKeyToken +
                        sizeof(xcRsaKeyToken_t)  +
                        pOffCardRSAToken->apOffset;

  memcpy( pRSAKeyToken->apPtr,
          (unsigned char *)pOffCardRSAToken + sizeof(offCardRSAToken_t)  -1 +
          pOffCardRSAToken->apOffset,
          pOffCardRSAToken->apLength );



  /* aq */
  pRSAKeyToken->aqPtr = (unsigned char*)pRSAKeyToken +
                        sizeof(xcRsaKeyToken_t)  +
                        pOffCardRSAToken->aqOffset;

  memcpy( pRSAKeyToken->aqPtr,
          (unsigned char*)pOffCardRSAToken + sizeof(offCardRSAToken_t)  -1 + pOffCardRSAToken->aqOffset,
          pOffCardRSAToken->aqLength );


  /* r */
  pRSAKeyToken->r_Ptr = (unsigned char*)pRSAKeyToken +
                        sizeof(xcRsaKeyToken_t)  +
                        pOffCardRSAToken->r_Offset;

  memcpy( pRSAKeyToken->r_Ptr,
          (unsigned char*)pOffCardRSAToken + sizeof(offCardRSAToken_t)  -1 + pOffCardRSAToken->r_Offset,
          pOffCardRSAToken->r_Length );

  /* r1 */
  pRSAKeyToken->r1Ptr = (unsigned char*)pRSAKeyToken +
                        sizeof(xcRsaKeyToken_t)  +
                        pOffCardRSAToken->r1Offset;

  memcpy( pRSAKeyToken->r1Ptr,
          (unsigned char*)pOffCardRSAToken + sizeof(offCardRSAToken_t)  -1 + pOffCardRSAToken->r1Offset,
          pOffCardRSAToken->r1Length );

  return rc;
}

/* converts an on card key to an off card key type for DSA */
int  
convertToOffCardDSAToken( xcDSAKeyToken_t   * pDSAKeyToken,
                          offCardDSAToken_t * pOffCardDSAToken )
{
  int rc = 0;
  int tempOffset = 0;

  if( pDSAKeyToken == NULL || pOffCardDSAToken == NULL )
    return -1;

  pOffCardDSAToken->key_type = pDSAKeyToken->key_type;

  pOffCardDSAToken->prime_p_bit_length = pDSAKeyToken->prime_p_bit_length;
  pOffCardDSAToken->p_length = pDSAKeyToken->p_length;
  pOffCardDSAToken->g_length = pDSAKeyToken->g_length;
  pOffCardDSAToken->x_length = pDSAKeyToken->x_length;
  pOffCardDSAToken->y_length = pDSAKeyToken->y_length;
  pOffCardDSAToken->q_length = pDSAKeyToken->q_length;

  /* reset temp offset, translate to offsets */
  tempOffset = 0;

  /* p */
  pOffCardDSAToken->p_offset = tempOffset;
  memcpy( &pOffCardDSAToken->keydata_start + pOffCardDSAToken->p_offset,
           pDSAKeyToken->p_Ptr,
           pOffCardDSAToken->p_length );
  tempOffset += pOffCardDSAToken->p_length;

  /* q */
  pOffCardDSAToken->q_offset = tempOffset;
  memcpy( &pOffCardDSAToken->keydata_start + pOffCardDSAToken->q_offset,
           pDSAKeyToken->q_Ptr,
           pOffCardDSAToken->q_length );
  tempOffset += pOffCardDSAToken->q_length;

  /* g */
  pOffCardDSAToken->g_offset = tempOffset;
  memcpy( &pOffCardDSAToken->keydata_start + pOffCardDSAToken->g_offset,
           pDSAKeyToken->g_Ptr,
           pOffCardDSAToken->g_length );
  tempOffset += pOffCardDSAToken->g_length;

  /* x */
  pOffCardDSAToken->x_offset = tempOffset;
  memcpy( &pOffCardDSAToken->keydata_start + pOffCardDSAToken->x_offset,
           pDSAKeyToken->x_Ptr,
           pOffCardDSAToken->x_length );
  tempOffset += pOffCardDSAToken->x_length;

  /* y */
  pOffCardDSAToken->y_offset = tempOffset;
  memcpy( &pOffCardDSAToken->keydata_start + pOffCardDSAToken->y_offset,
           pDSAKeyToken->y_Ptr,
           pOffCardDSAToken->y_length );
  tempOffset += pOffCardDSAToken->y_length;

  /* overall token length */
  pOffCardDSAToken->key_token_length =  sizeof( offCardDSAToken_t ) + tempOffset;

  return rc;
}

/* converts an on card key to an off card key type for RSA */
int 
convertToOffCardRSAToken( xcRsaKeyToken_t   * pRSAKeyToken,
                          offCardRSAToken_t * pOffCardRSAToken )
{
  int rc = 0;
  int tempOffset = 0;

  if( pRSAKeyToken == NULL || pOffCardRSAToken == NULL )
    return -1;

  pOffCardRSAToken->type = pRSAKeyToken->type;

  /* set lengths */
  pOffCardRSAToken->n_BitLength = pRSAKeyToken->n_BitLength;
  pOffCardRSAToken->n_Length = pRSAKeyToken->n_Length;
  pOffCardRSAToken->e_Length = pRSAKeyToken->e_Length;
  pOffCardRSAToken->x.p_Length = pRSAKeyToken->x.p_Length;
  pOffCardRSAToken->q_Length = pRSAKeyToken->q_Length;
  pOffCardRSAToken->dpLength = pRSAKeyToken->dpLength;
  pOffCardRSAToken->dqLength = pRSAKeyToken->dqLength;
  pOffCardRSAToken->apLength = pRSAKeyToken->apLength;
  pOffCardRSAToken->aqLength = pRSAKeyToken->aqLength;
  pOffCardRSAToken->r_Length = pRSAKeyToken->r_Length;
  pOffCardRSAToken->r1Length = pRSAKeyToken->r1Length;

  /* calculate offsets, and fill in tokenData */
  tempOffset = 0;

  /* N */
  pOffCardRSAToken->n_Offset = tempOffset;
  memcpy( &pOffCardRSAToken->tokenData + pOffCardRSAToken->n_Offset,
           pRSAKeyToken->n_Ptr,
           pOffCardRSAToken->n_Length );
  tempOffset += pOffCardRSAToken->n_Length;


  /* E */
  pOffCardRSAToken->e_Offset = tempOffset;
  memcpy( &pOffCardRSAToken->tokenData + pOffCardRSAToken->e_Offset,
          pRSAKeyToken->e_Ptr,
          pOffCardRSAToken->e_Length );
  tempOffset += pOffCardRSAToken->e_Length;

  /* P or D */
  pOffCardRSAToken->y.p_Offset = tempOffset;
  memcpy( &pOffCardRSAToken->tokenData + pOffCardRSAToken->y.p_Offset,
          pRSAKeyToken->y.p_Ptr,
          pOffCardRSAToken->x.p_Length );
  tempOffset += pOffCardRSAToken->x.p_Length;

  /* Q */
  pOffCardRSAToken->q_Offset = tempOffset;
  memcpy( &pOffCardRSAToken->tokenData + pOffCardRSAToken->q_Offset,
          pRSAKeyToken->q_Ptr,
          pOffCardRSAToken->q_Length );
  tempOffset += pOffCardRSAToken->q_Length;

  /* dp */
  pOffCardRSAToken->dpOffset = tempOffset;
  memcpy( &pOffCardRSAToken->tokenData + pOffCardRSAToken->dpOffset,
          pRSAKeyToken->dpPtr,
          pOffCardRSAToken->dpLength );
  tempOffset += pOffCardRSAToken->dpLength;

  /* dq */
  pOffCardRSAToken->dqOffset = tempOffset;
  memcpy( &pOffCardRSAToken->tokenData + pOffCardRSAToken->dqOffset,
          pRSAKeyToken->dqPtr,
          pOffCardRSAToken->dqLength );
  tempOffset += pOffCardRSAToken->dqLength;

  /* ap */
  pOffCardRSAToken->apOffset = tempOffset;
  memcpy( &pOffCardRSAToken->tokenData + pOffCardRSAToken->apOffset,
          pRSAKeyToken->apPtr,
          pOffCardRSAToken->apLength );
  tempOffset += pOffCardRSAToken->apLength;

  /* aq */
  pOffCardRSAToken->aqOffset = tempOffset;
  memcpy( &pOffCardRSAToken->tokenData + pOffCardRSAToken->aqOffset,
          pRSAKeyToken->aqPtr,
          pOffCardRSAToken->aqLength );
  tempOffset += pOffCardRSAToken->aqLength;

  /* r */
  pOffCardRSAToken->r_Offset = tempOffset;
  memcpy( &pOffCardRSAToken->tokenData + pOffCardRSAToken->r_Offset,
          pRSAKeyToken->r_Ptr,
          pOffCardRSAToken->r_Length );
  tempOffset += pOffCardRSAToken->r_Length;

  /* r1 */
  pOffCardRSAToken->r1Offset = tempOffset;
  memcpy( &pOffCardRSAToken->tokenData + pOffCardRSAToken->r1Offset,
          pRSAKeyToken->r1Ptr,
          pOffCardRSAToken->r1Length );
  tempOffset += pOffCardRSAToken->r1Length;


  pOffCardRSAToken->tokenLength = sizeof( offCardRSAToken_t ) + tempOffset;

  return rc;
}

/* sets up pointers and lengths */
int 
initializexCryptoRSAToken( xcRsaKeyToken_t * pRSAKeyToken,
                           int               n_bit_size )
{
   int rc = 0;

   if( pRSAKeyToken == NULL )
     return -1;

   int tempOffset = 0;

   pRSAKeyToken->tokenLength = MAX_PADDED_PKA_TOKEN_LENGTH;
   pRSAKeyToken->n_BitLength = n_bit_size;
   pRSAKeyToken->n_Length = n_bit_size / 8;
   pRSAKeyToken->e_Length = pRSAKeyToken->n_Length;
   pRSAKeyToken->x.p_Length = pRSAKeyToken->n_Length;
   pRSAKeyToken->q_Length = pRSAKeyToken->n_Length;
   pRSAKeyToken->dpLength = pRSAKeyToken->n_Length;
   pRSAKeyToken->dqLength = pRSAKeyToken->n_Length;
   pRSAKeyToken->apLength = pRSAKeyToken->n_Length;
   pRSAKeyToken->aqLength = pRSAKeyToken->n_Length;
   pRSAKeyToken->r_Length = pRSAKeyToken->n_Length;
   pRSAKeyToken->r1Length = pRSAKeyToken->n_Length;

   tempOffset = sizeof( xcRsaKeyToken_t );

   pRSAKeyToken->n_Ptr = (unsigned char *)pRSAKeyToken + tempOffset;
   tempOffset += pRSAKeyToken->n_Length;

   pRSAKeyToken->e_Ptr = (unsigned char*)pRSAKeyToken + tempOffset;

   tempOffset += pRSAKeyToken->e_Length;

   pRSAKeyToken->y.p_Ptr = (unsigned char*)pRSAKeyToken + tempOffset;
   tempOffset += pRSAKeyToken->x.p_Length;

   pRSAKeyToken->q_Ptr = (unsigned char*)pRSAKeyToken + tempOffset;
   tempOffset += pRSAKeyToken->q_Length;

   pRSAKeyToken->dpPtr = (unsigned char*)pRSAKeyToken + tempOffset;
   tempOffset += pRSAKeyToken->dpLength;

   pRSAKeyToken->dqPtr = (unsigned char*)pRSAKeyToken + tempOffset;
   tempOffset += pRSAKeyToken->dqLength;

   pRSAKeyToken->apPtr = (unsigned char*)pRSAKeyToken + tempOffset;
   tempOffset += pRSAKeyToken->apLength;

   pRSAKeyToken->aqPtr = (unsigned char*)pRSAKeyToken + tempOffset;
   tempOffset += pRSAKeyToken->aqLength;

   pRSAKeyToken->r_Ptr = (unsigned char*)pRSAKeyToken + tempOffset;
   tempOffset += pRSAKeyToken->r_Length;

   pRSAKeyToken->r1Ptr = (unsigned char*)pRSAKeyToken + tempOffset;

   return rc;
}

int 
initializexCryptoDSAToken( xcDSAKeyToken_t * pDSAKeyToken,
                           int               prime_p_bit_size )
{
  int rc = 0;
  int tempOffset = 0;

  if( pDSAKeyToken == NULL )
    return -1;

  pDSAKeyToken->p_length = prime_p_bit_size / 8;
  pDSAKeyToken->q_length = 20;
  pDSAKeyToken->x_length = 20;
  pDSAKeyToken->y_length = prime_p_bit_size / 8;
  pDSAKeyToken->g_length = prime_p_bit_size / 8;
  pDSAKeyToken->key_type = DSA_PRIVATE_KEY_TYPE;

  tempOffset = sizeof( xcDSAKeyToken_t );

  pDSAKeyToken->p_Ptr = (unsigned char*)pDSAKeyToken +  tempOffset;
  tempOffset += pDSAKeyToken->p_length;

  pDSAKeyToken->q_Ptr = (unsigned char*)pDSAKeyToken +  tempOffset;
  tempOffset += pDSAKeyToken->q_length;

  pDSAKeyToken->g_Ptr = (unsigned char*)pDSAKeyToken +  tempOffset;
  tempOffset += pDSAKeyToken->g_length;

  pDSAKeyToken->x_Ptr = (unsigned char*)pDSAKeyToken +  tempOffset;
  tempOffset += pDSAKeyToken->x_length;

  pDSAKeyToken->y_Ptr = (unsigned char*)pDSAKeyToken +  tempOffset;


  pDSAKeyToken->key_token_length = MAX_PADDED_PKA_TOKEN_LENGTH;
  pDSAKeyToken->prime_p_bit_length = prime_p_bit_size;

  return rc;
}

/* Generate a DSA Key */
void 
DSAKeyGenerate( responseStruct * pResponse, 
                int              bitSize )
{
  int rc = 0; /* return code */
  int replyLength = 0; /* reply length in bytes */

  /* DSA Key Generation Request Block */
  xcDSAKeyGen_RB_t *pDSAKeyGen_rb = NULL;
  /* DSA Key Token, in on Card Format */
  xcDSAKeyToken_t *pDSAKeyToken = NULL;
  /* DSA Key Token, in off Card Format */
  offCardDSAToken_t *pOffCardDSAToken = (offCardDSAToken_t *)pResponse->data;

  /* allocate memory as required */
  pDSAKeyGen_rb = (xcDSAKeyGen_RB_t *) malloc( sizeof( xcDSAKeyGen_RB_t ) );
  pDSAKeyToken = (xcDSAKeyToken_t *) malloc( MAX_PADDED_PKA_TOKEN_LENGTH );

  /* check that mallocs completed */
  if( pDSAKeyGen_rb == NULL || pDSAKeyToken == NULL  )
  {
    if( pDSAKeyGen_rb )
      free( pDSAKeyGen_rb );
    if( pDSAKeyToken )
      free( pDSAKeyToken );

    createDummyResponse( pResponse, PKA_SYS_ERROR, pthread_self() );

    return;
  }

  /* initialize buffers */
  memset( pOffCardDSAToken, 0x00, MAX_PADDED_PKA_TOKEN_LENGTH );
  memset( pDSAKeyGen_rb, 0x00, sizeof( xcDSAKeyGen_RB_t ) );
  memset( pDSAKeyToken, 0x00, MAX_PADDED_PKA_TOKEN_LENGTH );

  /* initialize token lengths and pointers */
  initializexCryptoDSAToken( pDSAKeyToken, bitSize );

  /* set up request block */
  pDSAKeyGen_rb->key_token        = pDSAKeyToken;
  pDSAKeyGen_rb->prime_p_size     = bitSize;
  pDSAKeyGen_rb->random_seed      = NULL;
  pDSAKeyGen_rb->random_seed_size = 0;
  pDSAKeyGen_rb->key_token_size   = MAX_PKA_TOKEN_LENGTH;

  /* generate key */
  rc = xcDSAKeyGenerate( getFileDescriptor( FD_PKA ),
                         pDSAKeyGen_rb );

  if( rc )
  {
    if( pDSAKeyGen_rb )
      free( pDSAKeyGen_rb );
    if( pDSAKeyToken )
      free( pDSAKeyToken );
    if( pOffCardDSAToken )
      free( pOffCardDSAToken );

    /*something bad happened.*/
    createDummyResponse( pResponse, PKA_FAIL, pthread_self() );
    return;
  }

  /* everything is fine, send back key token in the proper (off card) format  */
  convertToOffCardDSAToken( pDSAKeyToken, pOffCardDSAToken );

  /* make sure reply is a multiple of 8 bytes */
  replyLength =( ( pOffCardDSAToken->key_token_length + 7 ) / 8 ) * 8;

  pResponse->status = PKA_OK;
  pResponse->dataLength = replyLength;

  /* free memory allocated by this function */
  if( pDSAKeyGen_rb )
    free( pDSAKeyGen_rb );
  if( pDSAKeyToken )
    free( pDSAKeyToken );

  return;
}

/* Generate Key of Type RSA */
void 
RSAKeyGenerate( responseStruct * pResponse, 
                int              bitSize )
{
  /* return code */
  int rc = 0;
  /* xc RSA Key Generation Request Block */
  xcRSAKeyGen_RB_t *pRSAKeyGen_rb = NULL;
  /* off Card RSA Token, generated key is translated to this type, and sent back to host */
  offCardRSAToken_t *pOffCardRSAToken = (offCardRSAToken_t *)pResponse->data;
  /* xcRSA Key Token */
  xcRsaKeyToken_t *pRSAKeyToken = NULL;
  /* temp integer */
  /*int*/ unsigned int tempInt = 0;
  /* reply length in bytes */
  int replyLength = 0;

  /* allocate room for request block and token */
  pRSAKeyGen_rb = (xcRSAKeyGen_RB_t *) malloc( sizeof( xcRSAKeyGen_RB_t ) );
  pRSAKeyToken = (xcRsaKeyToken_t *) malloc( MAX_PADDED_PKA_TOKEN_LENGTH );

  /* check that allocations completed */
  if( pRSAKeyGen_rb == NULL || pRSAKeyToken == NULL )
  {
    if( pRSAKeyGen_rb )
      free( pRSAKeyGen_rb );
    if( pRSAKeyToken )
      free( pRSAKeyToken );

    createDummyResponse( pResponse, PKA_SYS_ERROR, pthread_self() );
    return;
  }

  /* initialize variables */
  memset( pRSAKeyGen_rb, 0x00, sizeof( xcRSAKeyGen_RB_t ) );
  memset( pRSAKeyToken, 0x00, MAX_PADDED_PKA_TOKEN_LENGTH );
  /* Note: buffer delcared and allocated in skelxc.c as a 4k buffer */
  memset( pOffCardRSAToken, 0x00, MAX_PADDED_PKA_TOKEN_LENGTH );

  /* Set Up RSA Key Generation Request Block */
  pRSAKeyGen_rb->regen_data = NULL;
  pRSAKeyGen_rb->regen_size = 0;
  pRSAKeyGen_rb->mod_size   = bitSize;
  pRSAKeyGen_rb->key_type   = RSA_PRIVATE;
  pRSAKeyGen_rb->public_exp = RSA_EXPONENT_65537;
  tempInt = MAX_PADDED_PKA_TOKEN_LENGTH;
  pRSAKeyGen_rb->key_size   = &tempInt;

  pRSAKeyGen_rb->key_type  = RSA_PRIVATE_CHINESE_REMAINDER ;

  /* set up the various lengths and pointers of our token */
  initializexCryptoRSAToken( pRSAKeyToken, bitSize );

  pRSAKeyGen_rb->key_token = pRSAKeyToken;

  /* Generate a Key Token */
  rc = xcRSAKeyGenerate( getFileDescriptor( FD_PKA ),
                         pRSAKeyGen_rb );

  /* set up response, depending on return code */
  if( rc == PKA_OK  )
  {
    /* translate into off card key token type */
    convertToOffCardRSAToken( pRSAKeyToken, pOffCardRSAToken );
    /* make sure reply is a multiple of 8 bytes */
    pResponse->status= PKA_OK;
    replyLength =( ( pOffCardRSAToken->tokenLength + 7 ) / 8 ) * 8;
    pResponse->dataLength = replyLength;
  }
  else
  {
    /* key generate did not complete as expected */
    createDummyResponse( pResponse, PKA_FAIL, pthread_self() );
  }

  /* free memory allocated by this function  */
  if( pRSAKeyGen_rb )
    free( pRSAKeyGen_rb );
  if( pRSAKeyToken )
    free( pRSAKeyToken );

  return;
}


/* Encrypt or Decrypt Some Data with a key of type RSA */
void 
RSAEncryptOrDecrypt( responseStruct * pResponse,
                     int              userRequest,
                     unsigned char  * pKey,
                     unsigned char  * pData,
                     int              dataLength )
{
  /* return code for crypto function call */
  int rc = 0;
  /* xc RSA Key token */
  xcRsaKeyToken_t *pRSAKeyToken = NULL;
  /* xc RSA  request block */
  xcRSA_RB_t *pRSA_rb = NULL;
  /* off card token, needs to be translated to xcRsaKeyToken_t before use */
  offCardRSAToken_t *pOffCardRSAToken = (offCardRSAToken_t *)pKey;

  /* allocate space for key and request block */
  pRSAKeyToken = (xcRsaKeyToken_t *) malloc( MAX_PADDED_PKA_TOKEN_LENGTH );
  pRSA_rb = (xcRSA_RB_t *) malloc( sizeof ( xcRSA_RB_t ) );

  /* check that mallocs allocated memory properly */
  if(  pRSAKeyToken == NULL || pRSA_rb == NULL  )
  {
    if( pRSA_rb )
      free( pRSA_rb );
    if( pRSAKeyToken )
      free( pRSAKeyToken );

    createDummyResponse( pResponse, PKA_SYS_ERROR, pthread_self( ) );
    return;
  }

  /* initialize buffers */
  memset( pRSAKeyToken, 0x00, MAX_PADDED_PKA_TOKEN_LENGTH );
  memset( pResponse->data, 0x00, MAX_PADDED_PKA_TOKEN_LENGTH );
  /* convert to an on card token format */
  convertFromOffCardRSAToken(pOffCardRSAToken, pRSAKeyToken );

  /* set up RSA request block */
  pRSA_rb->data_in = pData;
  pRSA_rb->data_out = pResponse->data;
  pRSA_rb->key_token = pRSAKeyToken;
  pRSA_rb->key_size = pRSAKeyToken->tokenLength;
  pRSA_rb->data_size = dataLength * 8;//convert from bytes to bits
  pRSA_rb->output_size = dataLength;/* dataLength should be the modulus length of the key */

  /* set options to reflect user's reqeust */
  if( userRequest == RSA_ENC )
    pRSA_rb->options = RSA_PUBLIC | RSA_ENCRYPT;
  else //userRequest == RSA_DEC
    pRSA_rb->options = RSA_PRIVATE | RSA_DECRYPT;

  /* call xCrypto's RSA Service */
  rc = xcRSA( getFileDescriptor( FD_PKA ),
              pRSA_rb );

  /* encrypt or decrypt failed. send back msg and dummy data */
  if( rc  == PKA_OK )
  {
    pResponse->status = PKA_OK;
    pResponse->dataLength = pRSA_rb->output_size;
  }
  else
  {
    createDummyResponse( pResponse, PKA_FAIL, pthread_self() );
  }

  /* free any memory allocated by this function */
  if( pRSAKeyToken )
    free( pRSAKeyToken );
  if( pRSA_rb )
    free( pRSA_rb );

  return;
}

