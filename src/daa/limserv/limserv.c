/*********************************************************************** 
 * limserv.c - Skeleton Large Integer Math server.                     * 
 *             This function shows how to do xcModMath calls using     * 
 *             the yCrypto api in the skeleton server                  * 
 *                                                                     * 
 ***********************************************************************/

#include <stdlib.h>    /* for malloc et al           */
#include <string.h>    /* for memset et al           */
#include <pthread.h>   /* for pthread_self           */ 

#include "xc_types.h"  /* for xCrypto types          */
#include "xc_api.h"    /* for xCrypto function calls */

#include "skelcmn.h"   /* skeleton common functions  */
#include "limservi.h"  /* this file's header file    */

void  
limServer( xcVirtualPacket_t * pVPkt, 
           responseStruct    * pResponse )
{
  /* return code for various function calls */
  int             rc = 0;
  /* holds information about our large ints to work with */
  xcModMath_Int_t ints[MODM_MAXBUFS];
  /* pointer to lim request header sent from host */
  limReqHdr_t    *pLimReqHdr =NULL;
  /* information about reply, which is C */
  limReply_t      replyHeader;
  /* number of integers to work with, default to maximum allowed */
  int             numInts = MODM_MAXBUFS;
  /* command to issue */
  int             cmd = 0;
  /* result buffer */
  unsigned char  *C_buffer = NULL;
  /* process id for this function when called */
  pthread_t       pid = pthread_self( );

  /* initialization section */
  memset( &replyHeader, 0x00, sizeof( limReply_t ) );
  replyHeader.pid = pid;

  /* allocate buffer, send back dummy response on malloc error */
  C_buffer = (unsigned char *)malloc(MODM_MAXBYTES);

  if( C_buffer == NULL )
  {
    createDummyResponse( pResponse, LIMSERV_BAD_MALLOC, pid );
    return;//hopefully we'll be able to malloc next time
  }

  /* initialize buffers, etc */
  memset( &ints, 0x00, sizeof( ints ) );
  memset( C_buffer, 0x00, MODM_MAXBYTES );

  /* C is result */
  ints[MODM_C].bytesize = MODM_MAXBYTES;
  ints[MODM_C].bitsize = MODM_MAXBITS;
  ints[MODM_C].buffer  = C_buffer;

  /* grab pointer to request header from host */
  pLimReqHdr = (limReqHdr_t *)&(pVPkt->data_start);

  /* find out what user wants to do */
  cmd = pLimReqHdr->cmd;

  /* if operation = C = A MOD N, we only have 3 ints */
  if( cmd == MODM_MOD )
    numInts = 3;/*don't need B*/

  cmd |= MODM_BIG;/*numbers come from host as big endian numbers*/

  /* Calculate sizes and buffer location for A */
  ints[MODM_A].bytesize = pLimReqHdr->aBytes;
  ints[MODM_A].bitsize = pLimReqHdr->aBits;
  ints[MODM_A].buffer = (unsigned char*)(&pLimReqHdr->aBuff);

  /* Calculate sizes and buffer location for B */
  /* if cmd == MODM_MOD, B is sent as an empty buffer, and never used */
  ints[MODM_B].bytesize = pLimReqHdr->bBytes;
  ints[MODM_B].bitsize = pLimReqHdr->bBits;
  ints[MODM_B].buffer = (unsigned char *)(&pLimReqHdr->bBuff);

  /* Calculate sizes and buffer location for N */
  ints[MODM_N].bytesize = pLimReqHdr->nBytes;
  ints[MODM_N].bitsize = pLimReqHdr->nBits;
  ints[MODM_N].buffer = (unsigned char *)(&pLimReqHdr->nBuff);

  /* call the xCrypto modular math PKA service */
  rc = xcModMath( getFileDescriptor(FD_PKA),
                  cmd,
                  numInts,
                  ints);

  /* see if command completed successfully */
  if( rc )
    pResponse->status = LIMSERV_MODMATH_FAILED;
  else
    pResponse->status = LIMSERV_OK;

  /* result ( which is always C ), goes back to host */
  if( pResponse->status == LIMSERV_OK )
  {
    replyHeader.cBytes = ints[MODM_C].bytesize;
    replyHeader.cBits = ints[MODM_C].bitsize;

    pResponse->headerLength = sizeof(limReply_t);
    memcpy(pResponse->header, &replyHeader, pResponse->headerLength );
    pResponse->dataLength = replyHeader.cBytes;//should be a multiple of 8
    memcpy( pResponse->data, ints[MODM_C].buffer, pResponse->dataLength );
    pResponse->userDef = 0;
  }
  else
  {
    createDummyResponse( pResponse, pResponse->status, pid );
  }

  /* free buffer allocated by this function */
  if( C_buffer )
    free( C_buffer );

  return;
}
