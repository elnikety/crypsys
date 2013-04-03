/***********************************************************************
 * aesHost.c - Host Skeleton sample program.                           *
 *             This program is an example of AES services as part of   *
 *             a menu of options (skelhost.c is the main server)       *
 *                                                                     *
 ***********************************************************************/

#include <stdio.h>       /* printf et al                */
#include <stdlib.h>      /* std library functions       */
#include <string.h>      /* memset et al                */
#ifdef NT_ON_I386
  #include <windows.h>   /* required for handle         */
  #include <sys\types.h> /* for off_t                   */
#endif

#include "xc_types.h"    /* xCrypto types               */
#include "xc_host.h"     /* xCrypto host side functions */
#include "xc_api.h"      /* for AES constants           */

#include "skelServers.h" /* skeleton server headers     */
#include "aesserv.h"     /* headers for aesserv         */
#include "skelcmn.h"     /* common skeleton headers     */
#include "skelmenu.h"    /* skeleton menu headers       */

#include "../../rte/shared/util.h"

void
do_aesserv( xcAdapterHandle_t * pAdapterHandle )
{
  int             rc;
  int             choice;
  xcAES_key_t     aesKey;
  xcAES_vector_t  init_v;
  unsigned char   dummyData[64];
  unsigned char   prePadding[16];
  unsigned char   postPadding[32];
  unsigned char   output[256];
  unsigned char   inputBuffer[256];
  unsigned char   source[16];
  aesReqHdr_t     aesReqHdr;
  aesRepHdr_t     aesRepHdr;
  xcRB_t          xcRequestBlock;
  int             options = 0;
  int             i;
 
  /* initialize buffers */
  memset( dummyData, 0x00, sizeof( dummyData ) );
  memset( aesKey, 0x00, sizeof( aesKey ) );
  memset( prePadding, 0x00, sizeof( prePadding ) );
  memset( postPadding, 0x00, sizeof( postPadding ) );
  memset( output, 0x00, sizeof( output ) );
  memset( inputBuffer, 0x00, sizeof( inputBuffer ) );
  memset( &aesReqHdr, 0x00, sizeof( aesReqHdr_t ) );
  memset( &aesRepHdr, 0x00, sizeof( aesRepHdr_t ) );
  memset( &xcRequestBlock, 0x00, sizeof( xcRB_t ) );
  memset( source, 0x00, sizeof( source ) );

  /* print informational welcome message */
  printf( "\n-------------------------------------------------------\n" );
  printf( "This thread performs various AES related functions.\n" );
  printf( "-------------------------------------------------------\n" );

  choice = -1;

  /* grab encrypt/decrypt/mac/exit choice */
  while( choice < 0 || choice> 3 )
  {
    printf( "Choose one of the following options\n" );
    printf( "  0 --> Encrypt 16 bytes of data using AES\n" );
    printf( "  1 --> Decrypt 16 bytes of data using AES\n" );
    printf( "  2 --> Generate a MAC using AES\n" );
    printf( "  3 --> Return to Main Menu\n" );

    choice = read_safe_integer( );
  }

  /* immediately return to main menu if choice is 5 */
  if( choice == 3 )
    return;
  
  /* add operation to options */
  if( choice == 0 )
    options |= AES_ENCRYPT;
  else if( choice == 1 )
    options |= AES_DECRYPT;
  else
    options |= AES_MAC;

  /* choose ECB / CBC cipher mode */
  choice = -1;

  while( choice < 0 || choice > 1 )
  {
    printf( "Choose Cipher Mode\n" );
    printf( "  0 --> CBC Mode\n" );
    printf( "  1 --> ECB Mode\n" );

    choice = read_safe_integer( );
  }

  /* add cipher mode to options */
  if( choice == 0 )
    options |= AES_CBC_MODE;
  else
    options |= AES_ECB_MODE;

  /* get key length */
  choice = -1;

  while( choice < 0 || choice > 2 )
  {
    printf( "Choose Key Length\n" );
    printf( "  0 --> 128 Bit Key\n" );
    printf( "  1 --> 192 Bit Key\n" );
    printf( "  2 --> 256 Bit Key\n" );

    choice = read_safe_integer( );   
  }

  /* add key length to options */
  if( choice == 0 )
    options |= AES_128BIT_KEY;
  else if( choice == 1 )
    options |= AES_192BIT_KEY;
  else
    options |= AES_256BIT_KEY;

  /* Read key bits 0 - 63 */
  printf( "Enter first 8 bytes of key as a hex string: Ex: deadbeef deadbeef\n" );

  fgets( (char *)inputBuffer, sizeof( inputBuffer ), stdin );
  memset( inputBuffer, 0x00, sizeof( inputBuffer ) );

  fgets( (char *)inputBuffer, sizeof( inputBuffer ), stdin );

  textStringToHexArray( (char *)inputBuffer,
                        sizeof( inputBuffer ),
                        (char *)aesKey,
                        sizeof( aesKey ) );

  /* Read key bits 64 - 127 */
  printf( "Enter the next 8 bytes of key as a hex string: Ex: deadbeef deadbeef\n" );
  
  memset( inputBuffer, 0x00, sizeof( inputBuffer ) );

  fgets( (char *)inputBuffer, sizeof( inputBuffer ), stdin );

  textStringToHexArray( (char *)inputBuffer,
                        sizeof( inputBuffer ),
                        (char *)&aesKey[8],
                        sizeof( aesKey ) - 8 );

  /* Read the rest of the key depending on key length */
  if( (options & AES_192BIT_KEY) != 0 || (options & AES_256BIT_KEY) )
  {
    /* Read key bits 128 - 191 */
    printf( "Enter the next 8 bytes of key as a hex string: Ex: deadbeef deadbeef\n" );
    
    memset( inputBuffer, 0x00, sizeof( inputBuffer ) );

    fgets( (char *)inputBuffer, sizeof( inputBuffer ), stdin );

    textStringToHexArray( (char *)inputBuffer,
                          sizeof( inputBuffer ),
                          (char *)&aesKey[16],
                          sizeof( aesKey ) -16 );

    /* If we have a 256 bit key, read in bits 192 - 255 */ 
    if( (options & AES_256BIT_KEY) != 0 )
    {
      /* Read key bits 192 - 255 */
      printf( "Enter the next 8 bytes of key as a hex string: Ex: deadbeef deadbeef\n" );

      memset( inputBuffer, 0x00, sizeof( inputBuffer ) );

      fgets( (char *)inputBuffer, sizeof( inputBuffer ), stdin );

      textStringToHexArray( (char *)inputBuffer,
                            sizeof( inputBuffer ),
                            (char *)&aesKey[24],
                            sizeof( aesKey ) - 24 );
    }
  }

  /* if CBC mode is specified, enter IV */
  if( (options & AES_CBC_MODE) != 0 )
  {
    /* Read IV */
    printf( "Enter the 16 byte initialization vector as a hex string: " );
    printf( "Ex: deadbeef deadbeef deadbeef deadbeef\n" );

    memset( inputBuffer, 0x00, sizeof( inputBuffer ) );
   
    fgets( (char *)inputBuffer, sizeof( inputBuffer ), stdin ); 

    textStringToHexArray( (char *)inputBuffer,
                          sizeof( inputBuffer ),
                          (char *)init_v,
                          sizeof( init_v ) );
  }

  /* Read Data */
  printf( "Enter 16 bytes of data to encrypt/decrypt/mac as a hex string:\n" );
  printf( "Ex: deadbeef deadbeef deadbeef deadbeef\n" );

  memset( inputBuffer, 0x00, sizeof( inputBuffer ) );

  fgets( (char *)inputBuffer, sizeof( inputBuffer ), stdin );

  textStringToHexArray( (char *)inputBuffer,
                        sizeof( inputBuffer ),
                        (char *)source,
                        sizeof( source ) );

  /* Inquire if user wants to prepad data */
  choice = -1;

  while( choice < 0 || choice > 1 )
  {
    printf( "Choose PrePadding Options\n" );
    printf( "  0 --> No PrePadding\n" );
    printf( "  1 --> PrePad with 16 bytes of data\n" );

    choice = read_safe_integer( );
  }

  if( choice == 1 )
  {
    /* Read prepadding */
    options |= AES_PREPAD;

    printf( "Enter 16 bytes of prepadding as a hex string:\n" );
    printf( "Ex: deadbeef deadbeef deadbeef deadbeef\n" );

    memset( inputBuffer, 0x00, sizeof( inputBuffer ) );

    fgets( (char *)inputBuffer, sizeof( inputBuffer ), stdin );

    textStringToHexArray( (char *)inputBuffer,
                          sizeof( inputBuffer ),
                          (char *)prePadding,
                          sizeof( prePadding ) );
  }

  /* Inquire about post padding */
  choice = -1;

  while( choice < 0 || choice > 2 )
  {
    printf( "Choose Padding Options\n" );
    printf( "  0 --> No Padding\n" );
    printf( "  1 --> 16 Bytes Padding\n" );
    printf( "  2 --> 32 Bytes Padding\n" );
   
    choice = read_safe_integer( );
  }

  if( choice == 1 )
  {
    options |= AES_PAD_WITH_16;

    /* Read 16 bytes padding */ 
    printf( "Enter 16 bytes of postpadding as a hex string:\n" );
    printf( "Ex: deadbeef deadbeef deadbeef deadbeef\n" );
    memset( inputBuffer, 0x00, sizeof( inputBuffer ) );

    fgets( (char *)inputBuffer, sizeof( inputBuffer ), stdin );

    textStringToHexArray( (char *)inputBuffer,
                          sizeof( inputBuffer ),
                          (char *)postPadding,
                          sizeof( postPadding ) );

  }
  else if( choice == 2 )
  {
    options |= AES_PAD_WITH_32;

    /* Read 32 bytes padding */
    printf( "Enter first 16 bytes of postpadding as a hex string:\n" );
    printf( "Ex: deadbeef deadbeef deadbeef deadbeef\n" );

    memset( inputBuffer, 0x00, sizeof( inputBuffer ) );

    fgets( (char *)inputBuffer, sizeof( inputBuffer ), stdin );

    textStringToHexArray( (char *)inputBuffer,
                          sizeof( inputBuffer ),
                          (char *)postPadding,
                          sizeof( postPadding ) );

   
    printf( "Enter second 16 bytes of postpadding as a hex string:\n" );
    printf( "Ex: deadbeef deadbeef deadbeef deadbeef\n" );
    memset( inputBuffer, 0x00, sizeof( inputBuffer ) );

    fgets( (char *)inputBuffer, sizeof( inputBuffer ), stdin );

    textStringToHexArray( (char *)inputBuffer,
                          sizeof( inputBuffer ),
                          (char *)&prePadding[16],
                          sizeof( prePadding ) -16 );

  }

  /* Set up AES request block */
  memcpy( &(aesReqHdr.key), aesKey, sizeof( aesKey ) );
  memcpy( &(aesReqHdr.init_v), init_v, sizeof( init_v ) );
  memcpy( &(aesReqHdr.source), source, sizeof( source ) );
  memcpy( &(aesReqHdr.prePadding), prePadding, sizeof( prePadding ) );
  memcpy( &(aesReqHdr.postPadding), postPadding, sizeof( postPadding ) );
  aesReqHdr.options = HTOAL( options );
   
  /* Set up xcRequest Block */ 
  xcRequestBlock.AgentID = HTOAS( skeletonAgentID );
  xcRequestBlock.UserDefined = HTOAL( AESSERV_AES );

  xcRequestBlock.RequestControlBlkLength = sizeof( aesReqHdr_t );
  xcRequestBlock.RequestControlBlkAddr = (unsigned char*) &aesReqHdr;

  xcRequestBlock.RequestDataLength = sizeof( dummyData );
  xcRequestBlock.RequestDataAddress = dummyData;

  xcRequestBlock.ReplyControlBlkLength = sizeof( aesRepHdr_t );
  xcRequestBlock.ReplyControlBlkAddr = (unsigned char*) &aesRepHdr;

  /* reply data must be at least 64 bytes */
  xcRequestBlock.ReplyDataLength = sizeof( output );
  xcRequestBlock.ReplyDataAddr = output;

  if( ( rc = xcRequest( *pAdapterHandle, &xcRequestBlock ) ) != 0 )
    printf( "xcRequest failed, rc = 0x%x\n", rc );

  printf( "\n" );

  /* Print results */
  printf( "output = " );

  for( i = 0; i < ATOHL( aesRepHdr.reply_length ); i++ )
  {
    if( i % 16 == 0 )
      printf( "\n" );

    printf( "%02x ", output[i] );
  }

  return;
}

