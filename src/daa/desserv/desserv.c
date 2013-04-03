/*********************************************************************** 
 * desserv.c - Skeleton DES Encrypt, Decrypt, and Macgen server.       * 
 *             This function services yCrypto requests for DES         * 
 *             functions                                               * 
 *                                                                     * 
 ***********************************************************************/

#include <stdlib.h>   /* for malloc et al          */
#include <string.h>   /* for memset et al          */
#include <pthread.h>  /* for pthread_self          */

#include "xc_types.h" /* for xcrypto types         */
#include "xc_api.h"   /* xcrypto api calls         */

#include "desservi.h" /* header file for this file */

/* DES Encryption, Decryption, and MAC Generation Server */
void 
DESServer( xcVirtualPacket_t * pVPkt, 
           responseStruct    * pResponse )
{
  desReqHdr_t    *pDESReqHdr = NULL;    /* pointer to des request header   */
  desRepHdr_t    *pDESRepHdr = NULL;    /* pointer to des reply header     */
  unsigned long   userRequest = 0;      /* what option did user choose?    */
  unsigned char  *pKey = NULL;          /* pointer to key passed from host */

  unsigned char  *pData = NULL;         /* pointer to data                 */
  pthread_t       pid = pthread_self(); /* process id                      */

  /* extract request header and other relevant data*/
  pDESReqHdr = (desReqHdr_t *)&( pVPkt->data_start );

  /* extract key and data */
  pKey  = pDESReqHdr->key;
  pData = pDESReqHdr->data;

  /* find out what user wants to do */
  userRequest = pDESReqHdr->options;

  /* allocate and check for errors */
  pDESRepHdr = (desRepHdr_t *) malloc( sizeof( desRepHdr_t ) );

  if( pDESRepHdr ==  NULL )
  {
    /* couldn't malloc enough memory, return an error */
    createDummyResponse( pResponse, DES_SYS_ERROR, pid );
    return;
  }

  /* initialize the reply header */
  memset( pDESRepHdr, 0x00, sizeof( desRepHdr_t ) );

  /* perform appropriate task */
  switch( userRequest )
  {
    case DES_ENC8:
    case DES_DEC8:
      /* encrypt or decrypt 8 bytes with a single length key */
      encOrDec8Bytes( pResponse, userRequest, pKey, pData );
    break;

    case DES3_ENC8:
    case DES3_DEC8:
      /* encrypt or decrypt 8 bytes with triple length key */
      des3EncOrDec( pResponse, userRequest, pKey, pData );
    break;

    case DES_MACGEN:
      /* generate a MAC */
      desMACGen( pResponse, pKey, pData );
    break;

    default:
      /* invalid request type -- send back dummy data */
      createDummyResponse( pResponse, DES_WHAT, pid );
    break;
  }

  /* set up response structures */

  /* header */
  pDESRepHdr->replyLength = pResponse->dataLength;/* always send back 8 bytes */
  pDESRepHdr->pid = (unsigned long)pid;

  pResponse->headerLength = sizeof( desRepHdr_t );
  memcpy( pResponse->header, pDESRepHdr, pResponse->headerLength );
  /* NOTE:                                                 */
  /* pResponse->data and pResponse->dataLength already set */
  /* after a call to one of the xCrypto des functions */
  pResponse->userDef = 0;

  /* free malloc'd items */
  if( pDESRepHdr )
    free( pDESRepHdr );

  return;
}

/* Encrypt or Decrypt 8 bytes using a single length ( 8 bytes ) DES Key */
void  
encOrDec8Bytes( responseStruct * pResponse,
                int              userRequest,
                unsigned char  * pKey,
                unsigned char  * pData )
{
  int rc = 0;                     /* return code                       */
  xcDES8bytes_RB_t *pDES8bytes_rb;/* pointer to rb for des8byte request*/

  /* allocate memory for request block */
  pDES8bytes_rb = (xcDES8bytes_RB_t *)malloc( sizeof(xcDES8bytes_RB_t) );

  if( pDES8bytes_rb == NULL )
  {
    /* if NULL, a malloc error was encountered, return appropriate error code*/
    createDummyResponse(pResponse, DES_SYS_ERROR, pthread_self() );
    return;
  }

  /* initialize request block as appropriate*/
  memset( pDES8bytes_rb, 0x00, sizeof( xcDES8bytes_RB_t ) );

  memcpy( pDES8bytes_rb->key, pKey, 8);/* keys are always 8 bytes */
  memcpy( pDES8bytes_rb->input_data, pData, TEXT_BLOCK_LENGTH );

  /* mark flags appropriately */
  if( userRequest == DES_ENC8 )
    pDES8bytes_rb->options = DES_ENCRYPT;
  else if( userRequest == DES_DEC8 )
    pDES8bytes_rb->options = DES_DECRYPT;

  /* call xCrypto DES 8 bytes service */
  rc = xcDES8bytes( getFileDescriptor( FD_DES ), pDES8bytes_rb );

  /* setup reply as appropriate */
  if( rc )
  {
    createDummyResponse( pResponse, DES_FAIL, pthread_self() );
  }
  else
  {
    /* send back encrypted or decrypted 8 bytes of data */
    pResponse->status = DES_OK;
    memcpy( pResponse->data, pDES8bytes_rb->output_data, 8 );
    pResponse->dataLength = 8;
  }

  /* free memory allocated by this function */
  if( pDES8bytes_rb )
    free( pDES8bytes_rb );

  return;
}

/* Encrypt or Decrypt 8 Bytes using a triple length ( 24 bytes ) DES Key */
void 
des3EncOrDec( responseStruct * pResponse,
              int              userRequest,
              unsigned char  * pKey,
              unsigned char  * pData )
{
  int rc = 0;                     /* return code */
  xcTDES_RB_t      *pTDES_rb;     /* pointer to tdes rb */
  xcDES_vector_t    tempocv;      /* temp output chaining vector */
  xcDES_vector_t    tempicv;      /* temp input chaining vector */
  unsigned char     tempdest[8];  /* temp destination */

  /* allocate space for TDES request block */
  pTDES_rb = ( xcTDES_RB_t *)malloc( sizeof( xcTDES_RB_t ) );

  if( pTDES_rb == NULL )
  {
    createDummyResponse(pResponse, DES_SYS_ERROR, pthread_self() );
    return;
  }

  /* initialize variables */
  memset( pTDES_rb, 0x00, sizeof( xcTDES_RB_t ) );
  memset( &tempocv, 0x00, sizeof( tempocv ) );
  memset( &tempicv, 0x00, sizeof( tempicv ) );
  memset( tempdest, 0x00, sizeof( tempdest ) );

  /* set up  triple encrypt or decrypt request block */
  pTDES_rb->key1 = (xcDES_key_t*)(pKey);
  pTDES_rb->key2 = (xcDES_key_t *)(pKey + 8 );
  pTDES_rb->key3 = (xcDES_key_t *)(pKey + 16);
  pTDES_rb->init_v = (xcDES_vector_t *)&tempicv;
  pTDES_rb->term_v = (xcDES_vector_t *)&tempocv;
  pTDES_rb->source_length = TEXT_BLOCK_LENGTH;
  pTDES_rb->source.data_ptr = pData;
  pTDES_rb->destination_length = TEXT_BLOCK_LENGTH;
  pTDES_rb->destination.data_ptr = tempdest;

  /* set options to reflect user's request */
  if( userRequest == DES3_ENC8 )
    pTDES_rb->options = DES_ENCRYPT;
  else
    pTDES_rb->options = DES_DECRYPT;

  /* Call xCrypto TDES Service */
  rc = xcTDES( getFileDescriptor( FD_DES ), pTDES_rb );

  /* set up reply as appropriate */
  if( rc )
  {
    createDummyResponse( pResponse, DES_FAIL, pthread_self() );
  }
  else
  {
    pResponse->status = DES_OK;
    pResponse->dataLength = pTDES_rb->destination_length;
    memcpy( pResponse->data,
            pTDES_rb->destination.data_ptr,
            pResponse->dataLength );
   }

  if( pTDES_rb )
    free( pTDES_rb );

  return;
}

/* Generate a MAC */
void 
desMACGen( responseStruct * pResponse,
           unsigned char  * pKey,
           unsigned char  * pData )
{

  int rc = 0;                    /* return code */
  xcDES_RB_t       *pDES_rb;     /* pointer to des rb */
  xcDES_vector_t    tempocv;     /* temp output chaining vector */
  xcDES_vector_t    tempicv;     /* temp input chaining vector */
  unsigned char     tempdest[8]; /* temp destination */

  /* allocate space for des request block */
  pDES_rb = (xcDES_RB_t *)malloc(sizeof(xcDES_RB_t ) );

  if( pDES_rb == NULL )
  {
    createDummyResponse( pResponse, DES_SYS_ERROR, pthread_self() );
    return;
  }

  /* initialize variables */
  memset( &tempocv, 0x00, sizeof( tempocv ) );
  memset( &tempicv, 0x00, sizeof( tempicv ) );
  memset( tempdest, 0x00, sizeof( tempdest ) );
  memset( pDES_rb, 0x00, sizeof( xcDES_RB_t ) );

  /* set up des request block for mac generate */
  pDES_rb->key                  = (xcDES_key_t*) pKey;
  pDES_rb->init_v               = (xcDES_vector_t *)&tempicv;
  pDES_rb->term_v               = (xcDES_vector_t *)&tempocv;
  pDES_rb->source_length        = TEXT_BLOCK_LENGTH;
  pDES_rb->source.data_ptr      = pData;
  pDES_rb->destination_length   = TEXT_BLOCK_LENGTH;
  pDES_rb->destination.data_ptr = tempdest;
  pDES_rb->options              = DES_ENCRYPT | DES_MAC;

  /* Call the xCrypto DES Service */
  rc = xcDES( getFileDescriptor(FD_DES), pDES_rb );

  /* set up response as appropriate */
  if( rc )
  {
    createDummyResponse( pResponse, DES_FAIL, pthread_self() );
  }
  else
  {
    pResponse->status = DES_OK;
    pResponse->dataLength = pDES_rb->destination_length;
    memcpy( pResponse->data,
            tempocv,
            TEXT_BLOCK_LENGTH );
  }

  /* free memory allocated by this function */
  if( pDES_rb )
    free( pDES_rb );

  return;
}

