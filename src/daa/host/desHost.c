/***********************************************************************
 * desHost.c - Host Skeleton sample program.                           *
 *             This program is an example of DES services as part of   *
 *             a menu of options (skelhost.c is the main server)       *
 *                                                                     *
 ***********************************************************************/

/* DES Server Host side driver code */

#include <stdio.h>       /* printf et al                */
#include <stdlib.h>      /* for std library functions   */
#include <string.h>      /* for memset et al            */
 
#ifdef NT_ON_I386
  #include <windows.h>   /* required for handle         */
#endif

#include "xc_types.h"    /* xCrypto types               */
#include "xc_host.h"     /* xCrypto host side functions */

#include "skelServers.h" /* skeleton server headers     */
#include "desserv.h"     /* headers for desserv         */
#include "skelcmn.h"     /* common skeleton headers     */
#include "skelmenu.h"    /* read_safe_integer           */

#include "../../rte/shared/util.h"

void
do_desserv( xcAdapterHandle_t * pAdapterHandle )
{

  int    i = 0;
  int    rc = 0;
  int    choice = -1;
  unsigned char desInputKey[24];

  unsigned char inputData[8];
  int           inputDataLength = sizeof( inputData );
  unsigned char dummyData[8];

  unsigned char outputData[64];/* 64 bytes, only 8 used */
  unsigned char inputBuffer[80];
  int           inputBufferLength = sizeof( inputBuffer );
  int           desInputKeyLength = 24;
  desReqHdr_t   desReqHdr;
  desRepHdr_t   desRepHdr;
  xcRB_t        xcRequestBlock;

  memset( &xcRequestBlock, 0x00, sizeof( xcRB_t ) );
  memset( desInputKey, 0x00, sizeof( desInputKey ) );
  memset( inputBuffer, 0x00, sizeof( inputBuffer ) );
  memset( inputData, 0x00, sizeof( inputData ) );
  memset( outputData, 0x00, sizeof( outputData ) );
  memset( &desReqHdr, 0x00, sizeof( desReqHdr_t ) );
  memset( &desRepHdr, 0x00, sizeof( desRepHdr_t ) );

  printf( "\n-------------------------------------------------------\n" );
  printf( "This thread performs various DES related functions.\n" );
  printf( "-------------------------------------------------------\n" );

  while( choice < 0 || choice> 5 )
  {
    printf( "Choose one of the following options\n" );
    printf( "  0 --> Encrypt 8 bytes of data using DES\n" );
    printf( "  1 --> Decrypt 8 bytes of data using DES\n" );
    printf( "  2 --> Triple Encrypt 8 bytes of data using DES\n" );
    printf( "  3 --> Triple Decrypt 8 bytes of data using DES\n" );
    printf( "  4 --> Generate a MAC using DES\n" );
    printf( "  5 --> Return to Main Menu\n" );

    choice = read_safe_integer( );
  }

  /* immediately return to main menu if choice is 5 */
  if( choice == 5 )
    return;

  /* eat newline sitting on stdin */
  fgets( (char *)dummyData, sizeof( dummyData ), stdin );

  if( choice == DES_ENC8 || choice == DES3_ENC8 )
    printf( "Enter 8 bytes of data to encrypt.\n" );
  else if( choice == DES_DEC8 || choice == DES3_DEC8 )
    printf( "Enter 8 bytes of data to decrypt.\n" );
  else if( choice == DES_MAC )
    printf( "Enter 8 bytes of data for MAC Generation\n" );

  /* grab and parse input data */
  fgets( (char *)inputBuffer, sizeof( inputBuffer ), stdin );
  inputDataLength = textStringToHexArray( (char *)inputBuffer,
                                          inputBufferLength,
                                          (char *)inputData,
                                          inputDataLength );

  if( inputDataLength <= 0 )
    printf( "Warning! Input data not read correctly\n" );

  inputDataLength = 80;

  if( choice == DES_ENC8 || choice == DES_DEC8 || choice == DES_MACGEN )
    printf( "Enter Single Length DES key\n" );
  else // triple length op
    printf( "Enter Triple Length DES key\n" );

  memset( inputBuffer, 0x00, sizeof(inputBuffer) );
  fgets( (char *)inputBuffer, inputBufferLength, stdin );

  desInputKeyLength = textStringToHexArray( (char *)inputBuffer,
                                            inputBufferLength,
                                            (char *)desInputKey,
                                            desInputKeyLength );

  printf( "Input(s) received...sending request to card.\n" );

  desReqHdr.options = HTOAL( choice );
  memcpy( desReqHdr.data, inputData, sizeof( inputData ) );
  memcpy( desReqHdr.key, desInputKey, sizeof( desInputKey ) );

  xcRequestBlock.AgentID = HTOAS( skeletonAgentID );
  xcRequestBlock.UserDefined = HTOAL( DESSERV_DES );

  xcRequestBlock.RequestControlBlkLength = sizeof( desReqHdr_t );
  xcRequestBlock.RequestControlBlkAddr = (unsigned char*) &desReqHdr;

  xcRequestBlock.RequestDataLength = 8;
  xcRequestBlock.RequestDataAddress = dummyData;//everything sent in header again

  xcRequestBlock.ReplyControlBlkLength = sizeof( desRepHdr_t );
  xcRequestBlock.ReplyControlBlkAddr = (unsigned char*) &desRepHdr;

  /* reply data must be at least 64 bytes */
  xcRequestBlock.ReplyDataLength = sizeof( outputData );
  xcRequestBlock.ReplyDataAddr = outputData;

  if( ( rc = xcRequest( *pAdapterHandle, &xcRequestBlock ) ) != 0 )
    printf( "xcRequest failed, rc = 0x%x\n", rc );

  if( choice == DES_ENC8 || choice == DES3_ENC8 )
    printf( "encrypted data = \n" );
  else if( choice == DES_DEC8 || choice == DES3_DEC8 )
    printf( "decrypted data = \n" );
  else
    printf( "generated mac = \n" );

  for( i = 0; i < sizeof( outputData ); i++ )
    printf( " %02x", outputData[i] );

  printf( "\n" );

}/* end get_desserv_input() */
