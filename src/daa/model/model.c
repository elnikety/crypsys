/*********************************************************************** 
 * model.c - Skeleton threaded example, based on reverse then echo.    * 
 *           This sample runs as a service that is callable in a       * 
 *           threaded manner                                           * 
 *                                                                     * 
 ***********************************************************************/

#include <stdlib.h>   /* for malloc et al          */
#include <string.h>   /* for memset et al          */
#include <pthread.h>  /* for pthread_self          */

#include "xc_types.h" /* for xCrypto types         */
#include "xc_api.h"   /* for xCrypto api calls     */

#include "modeli.h"   /* header file for this file */


void  
threadModelServer( xcVirtualPacket_t * pVPkt, 
                   responseStruct    * pResponse )
{
  int                  i = 0;                /*loop control variable         */
  unsigned long        replyLength =0;       /*length to pass back to host   */
  char *               inBufPtr = NULL;      /*pointer to text to reverse    */
  char *               inBuffer;             /*used if length too large      */
  char *               outBuffer;            /*reversed text                 */
  int                  datalen = 0;          /*length of data                */
  modelHdr_t          *modelHdrPtr = NULL;   /*pointer to modelHdr from host */
  modelHdr_t           modelRplyHdr;         /*modelHdr for reply            */
  pthread_t            pid = pthread_self(); /* process id                   */
 
  /* clear out model header */
  memset( &modelRplyHdr, 0x00, sizeof( modelHdr_t ) );

  /* allocate data, return if error */
  inBuffer = (char*) malloc(REQUEST_BUFFER_LENGTH);
  outBuffer = (char*) malloc(REPLY_BUFFER_LENGTH);

  if( inBuffer == NULL || outBuffer == NULL )
  {
    /* set up quick and dirty dummy response */
    pResponse->status = MODEL_MALLOC_FAILURE;
    pResponse->headerLength = sizeof( modelHdr_t );
    modelRplyHdr.pid = (int) pid;
    memcpy( pResponse->header, &modelRplyHdr, sizeof( modelHdr_t ) );
    /*rest of fields are already null or 0*/

    if( inBuffer )
      free( inBuffer );

    if( outBuffer )
      free( outBuffer );

    return;
  }

  /* extract data from pVPkt */
  modelHdrPtr = (modelHdr_t*) &(pVPkt->data_start);
  /* must reverse modelBufLen before using it, since it came from the host */
  datalen = modelHdrPtr->bufLen;
  /* input buffer starts immediately after the model header */
  inBufPtr = (char*)modelHdrPtr + sizeof(modelHdr_t);

  /* make sure datalen is reasonable before trying to reverse */
  if (datalen > REQUEST_BUFFER_LENGTH)
  {
    /* note: should never get here, but check nonetheless */
    strcpy(inBuffer,"\ngnol oot eniL");
    datalen = strlen("Line too long\n");
    inBufPtr = (char*) inBuffer;
  }

  /* Reverse the text and return it */
  /* text will always be a multiple of 8 bytes, as setup by host code */
  replyLength = datalen;
  modelRplyHdr.bufLen = (replyLength);
  modelRplyHdr.pid = (int) pid;

  /* clear out output buffer, and reverse text */
  memset( outBuffer, 0x00, sizeof( outBuffer ) );
  for (i = 0; i < replyLength; i++)
    outBuffer[i] = * ( inBufPtr + (replyLength - i - 1));


  /* set up response structure */

  pResponse->headerLength = sizeof( modelHdr_t );
  memcpy( pResponse->header, &modelRplyHdr, sizeof( modelHdr_t ) );
  pResponse->dataLength   = datalen;
  memcpy( pResponse->data, outBuffer, REPLY_BUFFER_LENGTH );
  pResponse->status       = MODEL_REVERSE_REPLY;
  pResponse->userDef      = 0;

  /* clean up after ourselves */
  if( inBuffer )
    free( inBuffer );
  if( outBuffer )
    free( outBuffer );

  return;
}

