/*********************************************************************** 
 * aesserv.c - Skeleton DES Encrypt, Decrypt, and Macgen server.       * 
 *             This function services yCrypto requests for AES         * 
 *             functions                                               * 
 *                                                                     * 
 ***********************************************************************/

#include <stdlib.h>   /* for malloc et al           */
#include <string.h>   /* for memset et al           */

#include "xc_types.h" /* for xcrypto types          */
#include "xc_api.h"   /* xcrypto api calls          */

#include "aesserv.h"  /* headers for this file      */
#include "aesservi.h" /* more headers for this file */

/* AES Encryption, Decryption, and MAC Generation Server */
void 
AESServer( xcVirtualPacket_t * pVPkt, 
           responseStruct    * pResponse )
{
  long             rc = 0;      /* return code                       */
  aesReqHdr_t    * pAESReqHdr;  /* pointer to aes request header     */
  aesRepHdr_t    * pAESRepHdr;  /* pointer to aes reply header       */
  xcAES_RB_t       aes_rb;      /* AES Request block                 */
  pthread_t        pid = pthread_self( );/* process id               */
  xcAES_vector_t   term_v;      /* term_v for input to xcAES         */
  int              reply_length;/* length of data to send back       */
  int              fd;
  unsigned char    buffer[64];

  /* extract request header and other relevant data*/
  pAESReqHdr = (aesReqHdr_t *)&( pVPkt->data_start );

  /* common initialization */
  memset( &aes_rb, 0x00, sizeof( xcAES_RB_t ) );
  memset( term_v, 0x00, sizeof( term_v ) );

  /* Set up xcAES request block */

  /* key passed in from host */
  aes_rb.key             = (xcAES_key_t *)pAESReqHdr->key;
  /* initialization vector passed in from host (ignored for ECB mode) */
  aes_rb.init_v          = (xcAES_vector_t *)pAESReqHdr->init_v;
  /* term_v is output only, just indicate location for call to xcAES */
  aes_rb.term_v          = (xcAES_vector_t *)&term_v;
  /* for this example, we always work with 16 bytes of data */
  aes_rb.source_length   = sizeof( pAESReqHdr->source );
  /* source comes in from host request header */
  aes_rb.source.data_ptr = pAESReqHdr->source;
  /* options comes from host and is already byte reversed */
  aes_rb.options         = pAESReqHdr->options;

  aes_rb.destination_length = aes_rb.source_length;
  aes_rb.destination.data_ptr = buffer;

  /* copy prepadding */
  memcpy( aes_rb.prePadding, 
          pAESReqHdr->prePadding, 
          sizeof(aes_rb.prePadding ) );

  /* copy postpadding */
  memcpy( aes_rb.postPadding,
          pAESReqHdr->postPadding,
          sizeof( aes_rb.postPadding ) );

  /* get the AES file descriptor */
  fd = getFileDescriptor( FD_AES );

  /* call xcAES */
  rc = xcAES( fd, &aes_rb );

  /* Sanity check result */
  if( rc != DMGood )
  {
    createDummyResponse( pResponse, rc, pid );
    return;
  }

  /* set up response structures */

  /* allocate room for reply header and check for errors */
  pAESRepHdr = (aesRepHdr_t *)malloc( sizeof( aesRepHdr_t ) );

  if( pAESRepHdr ==  NULL )
  {
    /* couldn't malloc enough memory, return an error */
    createDummyResponse( pResponse, AES_SYS_ERROR, pid );
    return;
  }

  /* initialize reply header */
  memset( pAESRepHdr, 0x00, sizeof( aesRepHdr_t ) );

  /* copy the output into the response structure */
  if( (aes_rb.options & AES_MAC) != 0 )
  {
    /* copy the mac data */
    memcpy( pResponse->data,
            aes_rb.destination.data_ptr,
            sizeof( xcAES_vector_t ) );

    reply_length = sizeof( xcAES_vector_t );

  }
  else /* encrypt/decrypt */
  {
    reply_length = aes_rb.destination_length;

    /* copy the encrypt/decrypt output */
    memcpy( pResponse->data, 
            aes_rb.destination.data_ptr,
            aes_rb.destination_length );

    /* and optionally return chaining vector */ 
    if( (aes_rb.options & AES_CBC_MODE) != 0 )
    {
      memcpy( (char *)pResponse->data + aes_rb.destination_length,
              aes_rb.term_v,
              sizeof( xcAES_vector_t ) );

      reply_length += sizeof( xcAES_vector_t );
    }
  }

  /* response header initializaiton */
  pAESRepHdr->reply_length = reply_length;
  pAESRepHdr->pid          = (unsigned long)pid;

  /* copy response header into response */
  pResponse->headerLength = sizeof( aesRepHdr_t );
  memcpy( pResponse->header, pAESRepHdr, pResponse->headerLength );

  /* set up response */
  pResponse->userDef = 0;
  pResponse->status  = rc;

  pResponse->dataLength = reply_length;

  /* free malloc'd items */
  if( pAESRepHdr )
    free( pAESRepHdr );

  return;

}
