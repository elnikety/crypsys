/***********************************************************************
 * modHost.c - Host Skeleton sample program.                           *
 *             This program is an example of model services as part of *
 *             a menu of options (skelhost.c is the main server)       *
 *                                                                     *
 ***********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef NT_ON_I386
  #include <windows.h>
#endif

#include "xc_types.h"
#include "skelServers.h"
#include "model.h"
#include "skelcmn.h"
#include "../../rte/shared/util.h"

void
do_model( xcAdapterHandle_t * pAdapterHandle )
{

  /* this is simply a reverse then echo call */
  int                rc = 0;
  xcRB_t             requestBlock;  //request block to be sent to card
  char               inBuffer[REPLY_BUFFER_LENGTH + 1];    //input buffer
  char               outBuffer[REQUEST_BUFFER_LENGTH + 1]; //output buffer
  int                outLen;        //output length in bytes
  int                inLen;         //input length in bytes
  modelHdr_t         modelReqHdr;     //rte request header
  modelHdr_t         modelRplyHdr;    //rte reply header
  char               dummyBuffer[80];

  printf( "Enter text to reverse.\n" );

  //actually get the buffer data
  //
  memset( outBuffer, 0x00, sizeof( outBuffer ) );

  //fflush acted oddly, just grab and discard what is in stdin
  fgets( dummyBuffer, sizeof(dummyBuffer) -1, stdin );
  fgets( outBuffer, sizeof(outBuffer) -1, stdin );

  outLen = strlen( outBuffer ) -1;//-1 removes \n

  /* set up  request block    */

  /**********************************************************************/
  /* NOTE: byte reversal issues are handled in the following manner:    */
  /* the party receiving data is responsible for reversing it b/c host  */
  /* device driver passes the request block as is, and if you reverse   */
  /* a length for example, the result will not be what is intended      */
  /**********************************************************************/
  memset( &requestBlock, 0x00, sizeof( requestBlock ) );

  /* request header */
  memset( &modelReqHdr, 0x00, sizeof( modelHdr_t ) );
  modelReqHdr.bufLen                     = HTOAL( outLen );
  modelReqHdr.pid                        = HTOAL( 0 );

  /* reply header */
  memset( &modelRplyHdr, 0x00, sizeof( modelHdr_t ) );
  modelRplyHdr.bufLen                    = HTOAL( REPLY_BUFFER_LENGTH );
  modelRplyHdr.pid                       = HTOAL( 0 );

  /* request block info */
  requestBlock.AgentID                   = HTOAS( skeletonAgentID );
  requestBlock.UserDefined               = HTOAL( MODEL_REVERSE_REQUEST );

  /* request control block should hold our rteHDR which contains a length and ptr */
  requestBlock.RequestControlBlkLength   = sizeof( modelHdr_t );
  requestBlock.RequestControlBlkAddr     = (unsigned char*)&modelReqHdr;

  /* request data info */
  requestBlock.RequestDataLength         = outLen;
  requestBlock.RequestDataAddress        = (unsigned char*)outBuffer;

  /* reply control block */
  requestBlock.ReplyControlBlkLength     = sizeof( modelHdr_t );
  requestBlock.ReplyControlBlkAddr       = (unsigned char*)&modelRplyHdr;

  /* reply data */
  requestBlock.ReplyDataLength           = REPLY_BUFFER_LENGTH;
  requestBlock.ReplyDataAddr             = (unsigned char*)inBuffer;

  /**********************************************/
  /* issue the request, wait for it to complete */
  /**********************************************/
  if( ( rc = xcRequest( *pAdapterHandle,&requestBlock ) ) != 0 )
  {
    printf( "xcRequest failed rc = 0x%x\n", rc );
    xcCloseAdapter( *pAdapterHandle );
    exit( 1 );
  }

  printf( "back from card\n" );
  /* process the returned data */

  /* reverse length, as it came from card */
  inLen = ATOHL( modelRplyHdr.bufLen );

  if( inLen > REPLY_BUFFER_LENGTH )
    printf( "Error. reply too large\n" );
  else
    inBuffer[inLen] = '\0';

  printf( "Status is 0x%x. Returned length is %x,  returned text is '%s'\n",
          (unsigned int)(ATOHL(requestBlock.Status)),
          (unsigned int)inLen,
          inBuffer );

  printf( "processID of thread which processed the request = %ld\n",
          ATOHL( modelRplyHdr.pid ) );

  return;
}
