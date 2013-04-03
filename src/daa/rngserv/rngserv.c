/*********************************************************************** 
 * rngserv.c - Skeleton Random Number Generation server.               * 
 *             This function generates 8 bytes of Random Data or a     * 
 *             single length DES key                                   * 
 *                                                                     * 
 ***********************************************************************/

#include <stdlib.h>   /* for malloc et al */
#include <string.h>   /* for memset et al */
#include <pthread.h>  /* for pthread_self */

#include "xc_api.h"   /* for xCrypto api calls */
#include "xc_types.h" /* for xCrypto types     */

#include "skelcmn.h"  /* common skeleton functions */
#include "rngservi.h" /* this file's header file   */

/*
* Implementation of random number server
*/
void 
randomNumberServer( xcVirtualPacket_t * pVPkt, 
                    responseStruct    * pResponse )
{
  long                 rc;     /* holds return codes                      */
  xcRNG_RB_t           rngRB;  /* random number request block             */
  rngHdr_t             *rngReqHdrPtr, rngRepHdr;/* request, reply headers */
  unsigned char        randomBuffer[DEFAULT_RNG_BUF_LEN];/* rng buffer    */
  int                  dataLen = 0;  /* length of random data to create   */

  /* initialize buffer, so we can see that rng worked */
  memset( randomBuffer, 0x00, sizeof( randomBuffer ) );
  memset( &rngRepHdr, 0x00, sizeof( rngHdr_t ) );

  /* extract relevant data */
  rngReqHdrPtr = (rngHdr_t *) &(pVPkt->data_start);
  dataLen = rngReqHdrPtr->rngBufLen;

  /* truncate if buffer doesn't fit */
  if( dataLen  > DEFAULT_RNG_BUF_LEN )
  {
    dataLen = DEFAULT_RNG_BUF_LEN;
    pResponse->status = RNG_BUFFER_TRUNCATED;
  }

  rngRB.lenRng = dataLen;/* up to 8 bytes for this example */
  rngRB.pBufferRng = randomBuffer;/* holds random number */
  rngRB.optionsRng = rngReqHdrPtr->options;

  /* invoke xCrypto's rng service */
  rc =  xcRandomNumberGenerate( getFileDescriptor(FD_HWRNG), &rngRB );

  if( rc )
  {
    memset( randomBuffer, 0x00, sizeof( randomBuffer ) );
    pResponse->status = RNG_GEN_FAILED;
  }
  else
    pResponse->status = RNG_OK;

  /* set up response structure */
  pResponse->headerLength = sizeof( rngHdr_t );
  memcpy( pResponse->header, &rngRepHdr, sizeof( rngHdr_t ) );
  pResponse->dataLength   = dataLen;
  memcpy( pResponse->data, randomBuffer, DEFAULT_RNG_BUF_LEN );
  pResponse->userDef      = 0;

  return;
}

