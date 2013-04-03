/***********************************************************************
 * limHost.c - Host Skeleton sample program.                           *
 *             This program is an example of LIM services as part of   *
 *             a menu of options (skelhost.c is the main server)       *
 *             LIM - Large Integer Math                                *
 *                                                                     *
 ***********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef NT_ON_I386
  #include <windows.h>
  #include <sys\types.h>      /* for off_t */
#endif

#include "xc_types.h"
#include "xc_api.h"

#include "skelServers.h"
#include "limserv.h"
#include "skelcmn.h"
#include "skelmenu.h"
#include "../../rte/shared/util.h"

void
do_limserv( xcAdapterHandle_t * pAdapterHandle )
{
  char *aBuf, *bBuf, *cBuf, *nBuf;
  int   aBufLen, bBufLen, cBufLen, nBufLen;
  char  *inputBuf;
  int   inputBufLen;
  int   i = 0;
  int   rc = 0;/* return code for xcRequest et al */
  unsigned char dummyData[8];
  int   request = 0;

  limReqHdr_t limReqHdr;
  limReply_t  limRepHdr;

  xcRB_t       xcRequestBlock;
  char         dummyBuf[8];

  aBufLen = bBufLen = cBufLen = nBufLen = inputBufLen = 1024;

  /* malloc buffers */
  aBuf = (char *)malloc( aBufLen );
  bBuf = (char *)malloc( bBufLen );
  cBuf = (char *)malloc( cBufLen );
  nBuf = (char *)malloc( nBufLen );

  inputBuf = (char*)malloc( inputBufLen );

  if( aBuf == NULL || bBuf == NULL ||  nBuf == NULL ||
      inputBuf == NULL || cBuf == NULL)
  {
    printf( "Malloc Failure in do_limserv\n" );

    if( aBuf )
      free( aBuf );
    if( bBuf )
      free( bBuf );
    if( nBuf )
      free( nBuf );
    if( cBuf )
      free( cBuf );
    if( inputBuf )
      free( inputBuf );

    return;
  }

  /* clear out all variables */
  memset( aBuf, 0x00, aBufLen );
  memset( bBuf, 0x00, bBufLen );
  memset( cBuf, 0x00, cBufLen );
  memset( nBuf, 0x00, nBufLen );
  memset( inputBuf, 0x00, inputBufLen );
  memset( &limReqHdr, 0x00, sizeof( limReqHdr_t ) );
  memset( &limRepHdr, 0x00, sizeof( limReply_t ) );
  memset( &xcRequestBlock, 0x00, sizeof( xcRB_t ) );

  printf( "\n-------------------------------------------------------\n" );
  printf( "\t\tLarge Integer Math Server" ) ;
  printf( "\n-------------------------------------------------------\n" );
  request = -1;

  while( request < 0 || request > 2 )
  {
    printf( "Choose one of the following options:\n"
            "  0 -->  Compute C = A *  B mod N \n"
            "  1 -->  Compute C = A ** B mod N \n"
            "  2 -->  Compute C = A mod N \n" );
    request= read_safe_integer( );
  }

  /* eat  \n sitting on stdin */
  fgets( dummyBuf, sizeof( dummyBuf ), stdin );
  /* grab a and n, then conditionally grab b */

  printf( "Enter Numbers as hex strings padded with leading 0's--> \n" );
  printf( "Inputs must be padded to be the same length (in bytes) as the modulus\n" );
  printf( "Each Input must be a multiple of 8 bytes.\n" );
  printf( "Each byte must contain 2 characters ( do not use 0 for 1 byte of 0, use 00 )\n" );
  printf( "Ex. -- Decimal 25 (must be padded to 8 bytes) = 00 00 00 00 00 00 00 19\n" );
  printf( "Ex. -- Decimal 1025  (must be padded to 8 bytes) = 00 00 00 00 00 00 04 01\n" );
  printf( "\nEnter Value for A\n" );
  /* a */
  fgets( inputBuf, inputBufLen, stdin );
  aBufLen = textStringToHexArray( inputBuf,
                                  inputBufLen,
                                  aBuf,
                                  aBufLen );

  /* n */
  printf( "Enter Value for N\n" );
  memset(inputBuf, 0x00, inputBufLen );
  fgets( inputBuf, inputBufLen, stdin );

  nBufLen = textStringToHexArray( inputBuf,
                                  inputBufLen,
                                  nBuf,
                                  nBufLen );
  /* b */
  if( request != 2 )
  {
    printf( "Enter Value for B\n" );
    memset(inputBuf, 0x00, inputBufLen );
    fgets( inputBuf, inputBufLen, stdin );

    bBufLen = textStringToHexArray( inputBuf,
                                    inputBufLen,
                                    bBuf,
                                    bBufLen );
  }
  else
  {
    bBufLen = 0;
  }

  /* Check that all buf lens are the same.  This makes sure the user
   * has padded the data to the length of the modulus 
   */

  if( request == 2 )
  {
    /* if request is 2, this means the user wants to calculate 
     * C = A mod N
     */
    if( nBufLen != cBufLen )
    {
      printf( "Error: A and N must be padded to the same byte length\n" );

      if( aBuf )
        free( aBuf );
      if( bBuf )
        free( bBuf );
      if( nBuf )
        free( nBuf );
      if( inputBuf )
        free( inputBuf );
      if( cBuf )
        free( cBuf );

      return;
    }
  }
  else if( nBufLen != cBufLen && nBufLen != aBufLen )
  {
    printf( "Error: A, B, and N must be padded to the same byte length\n" );

    if( aBuf )
      free( aBuf );
    if( bBuf )
      free( bBuf );
    if( nBuf )
      free( nBuf );
    if( inputBuf )
      free( inputBuf );
    if( cBuf )
      free( cBuf );

    return;

  }

  if( aBufLen <= 0 || nBufLen <= 0 || ( request != 2 && bBufLen <= 0 ) )
  {
    printf( "Error reading input in limHost \n" );
    if( aBuf )
      free( aBuf );
    if( bBuf )
      free( bBuf );
    if( nBuf )
      free( nBuf );
    if( inputBuf )
      free( inputBuf );
    if( cBuf )
      free( cBuf );
    return;
  }

  printf( "All inputs received...sending request to card...\n" );

  /* set up request header */
  if( request == 0 )
    limReqHdr.cmd = HTOAL( MODM_MULT );
  else if( request == 1 )
    limReqHdr.cmd = HTOAL( MODM_EXP );
  else
    limReqHdr.cmd = HTOAL( MODM_MOD );

  limReqHdr.aBytes = HTOAL( aBufLen );
  limReqHdr.aBits =  HTOAL( aBufLen * 8 );/* convert to bits */
  memcpy( limReqHdr.aBuff, aBuf, aBufLen );

  limReqHdr.bBytes = HTOAL( bBufLen );
  limReqHdr.bBits = HTOAL( bBufLen * 8 );

  if( bBufLen != 0 )
    memcpy( limReqHdr.bBuff, bBuf, bBufLen );

  limReqHdr.nBytes = HTOAL( nBufLen );
  limReqHdr.nBits = HTOAL( nBufLen * 8 );
  memcpy( limReqHdr.nBuff, nBuf, nBufLen );

  xcRequestBlock.AgentID =  HTOAS( skeletonAgentID );
  xcRequestBlock.UserDefined = HTOAL( LIMSERV_LIM );

  xcRequestBlock.RequestControlBlkLength = sizeof( limReqHdr_t );
  xcRequestBlock.RequestControlBlkAddr = (unsigned char*) &limReqHdr;

  xcRequestBlock.RequestDataLength = 8;
  xcRequestBlock.RequestDataAddress = dummyData;/* everything sent in header */

  xcRequestBlock.ReplyControlBlkLength = sizeof( limReply_t );
  xcRequestBlock.ReplyControlBlkAddr = (unsigned char*) &limRepHdr;

  xcRequestBlock.ReplyDataLength = cBufLen;
  xcRequestBlock.ReplyDataAddr = (unsigned char *)cBuf;

  if( ( rc = xcRequest( *pAdapterHandle, &xcRequestBlock ) ) != 0 )
    printf( "xcRequest failed rc = 0x%x\n", rc );

  printf( "xcRequest for LIM Server returned\n" );
  printf( "pid of thread which serviced request = %ld\n",
           ATOHL( limRepHdr.pid ) );

  /* print A */
  printf( "A ==> \n" );
  for( i = 0; i < aBufLen; i ++ )
  {
    printf( " %02x", (unsigned char)aBuf[i] );
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );
  }

  printf( "\n" );

  /* print B if we use it */
  if( request != 2 )
  {
    printf( "B ==> \n" );
    for( i = 0; i < bBufLen; i ++ )
    {
      printf( " %02x", (unsigned char)bBuf[i] );
      if( i != 0 && i % MAX_LINE_WIDTH == 0 )
        printf( "\n" );
    }
    printf( "\n" );
  }

  printf( "N ==> \n" );

  for( i = 0; i < nBufLen; i ++ )
  {
    printf( " %02x", (unsigned char)nBuf[i] );
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );
  }
  printf( "\n" );

  /*  remind user what operation they chose */
  if( request == 0 )
    printf( "C = (A * B) MOD N\n" );
  else if( request == 1 )
    printf( "C = (A ^ B) MOD N\n" );
  else
    printf( "C = A MOD N\n" );

  cBufLen = ATOHL( limRepHdr.cBits ) / 8;//integer math rounds off properly
  /* if result is 0, print out at least 1 byte of 0's */
  if( cBufLen == 0 )
    cBufLen = 1;
  for( i = 0; i < cBufLen; i++ )
  {
    printf( " %02x", (unsigned char) cBuf[i] );
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );
  }

  printf( "\n" );

  if( aBuf )
    free( aBuf );
  if( bBuf )
    free( bBuf );
  if( nBuf )
    free( nBuf );
  if( inputBuf )
    free( inputBuf );
}
