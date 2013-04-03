/*********************************************************************** 
 * hshserv.c - Skeleton HASH server.                                   * 
 *             This function shows how to create a SHA1 hash using     * 
 *             the yCrypto api in a multi threaded environment         * 
 *                                                                     * 
 ***********************************************************************/

#include <stdlib.h>   /* malloc, et al                 */
#include <string.h>   /* for memset et al              */
#include <pthread.h>  /* for pthread_self              */

#include "xc_types.h" /* various xCrypto types         */
#include "xc_api.h"   /* xCrypto functions             */

#include "skelcmn.h"  /* common functions for skeleton */
#include "hshservi.h" /* this file's header file       */

/* thread for hash server */
void  
hashServer( xcVirtualPacket_t * pVPkt, 
            responseStruct    * pResponse )
{
  long                 rc;                   /* return code for various functions */
  xcSHA1_RB_t          sha1rb;               /* sha request block */
  hashHdr_t           *hashHdrPtr = NULL;    /* request header from host */
  hashHdr_t            hshReplyHdr;          /* reply header to host */
  pthread_t            pid = pthread_self(); /* process id for this thread */
  int                  dataLen;              /* length of data to hash */
  unsigned char       *dataToHashPtr = NULL; /* pointer to data to be hashed */

  /* initialize variables */
  memset( &sha1rb, 0x00, sizeof( xcSHA1_RB_t ) );
  memset( &hshReplyHdr, 0x00, sizeof( hashHdr_t ) );

  /* extract what we need from pvpkt */
  hashHdrPtr = (hashHdr_t*) &(pVPkt->data_start );
  dataLen = hashHdrPtr->dataLen;

  /* cast to char * so sizeof's pointer math is correct */
  dataToHashPtr = (unsigned char*)hashHdrPtr + sizeof( hashHdr_t );

  /* source length is padded w/0's to a multiple of 8  */
  /* on the host                                       */
  sha1rb.source_length   = dataLen;
  sha1rb.options         =  SHA1_MSGPART_ONLY;
  sha1rb.source.data_ptr = (void*)dataToHashPtr;

  /* call sha1 service */
  if( (rc = xcSha1( getFileDescriptor(FD_SHA), &sha1rb )  ) != 0 )
    pResponse->status = HSH_SYS_ERROR;
  else
    pResponse->status = HSH_OK;

  /* time to send a message back to host, set up reply */
  hshReplyHdr.dataLen = SHA1_PADDED_LEN;/* must be a multiple of 8 bytes */
  hshReplyHdr.pid     = pid;

  pResponse->headerLength = sizeof( hashHdr_t );
  memcpy( pResponse->header, &hshReplyHdr, sizeof( hashHdr_t ) );
  pResponse->dataLength = SHA1_PADDED_LEN;//must pass back a mult of 8
  /* only copy the 20 bytes we need, rest of buffer padded with 0's in skelxc.c */
  memcpy( pResponse->data, sha1rb.hash_value, SHA1_HASH_SIZE );
  pResponse->userDef = 0;

  return;
}


