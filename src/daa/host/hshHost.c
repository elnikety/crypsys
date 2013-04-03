/***********************************************************************
 * hshHost.c - Host Skeleton sample program.                           *
 *             This program is an example of hash services as part of  *
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
#include "xc_host.h"

#include "skelServers.h"
#include "hshserv.h"
#include "skelcmn.h"
#include "../../rte/shared/util.h"

void
do_hshserv( xcAdapterHandle_t * pAdapterHandle )
{
  int            i = 0;
  int            rc = 0;
  xcRB_t         requestBlock;

  unsigned char  text[256];
  int            textLen = 0;
  hashHdr_t      requestHdr, replyHdr;
  /* since hash is used as a reply buffer, it must be at least 64 bytes */
  unsigned char  hash[64];
  int            replyLength = 0;
  char           dummy[80];

  memset( text, 0x00, sizeof( text ) );
  memset( &requestBlock, 0x00, sizeof( xcRB_t ) );
  memset( hash, 0x00, sizeof( hash ) );
  memset( &requestHdr, 0x00, sizeof( hashHdr_t ) );
  memset( &replyHdr, 0x00, sizeof( hashHdr_t ) );

  printf( "\n-------------------------------------------------------\n" );
  printf( "This thread computes the hash of a block of data using\n" );
  printf( "the Secure Hash Algorithm (SHA-1)" );
  printf( "\n-------------------------------------------------------\n" );
  /* eat newline */
  fgets( dummy, sizeof(dummy), stdin );
  /* note, we can hash text or hex data, it doesn't matter, but for this
   * example, it is just as well to hash some arbitrary text
   */
  printf( "Enter a line of text to be hashed\n" );
  fgets( (char *)text, sizeof(text), stdin );

  textLen = strlen( (char *) text );
  text[textLen--] = 0x00;/* erase \n...note textLen decremented AFTER set */

  /* make sure we are a multiple of 8 */
  if( (textLen % 8 ) != 0 )
  {
    //text already padded with 0x00's
    textLen += 8 - ( textLen & 0x7 );
  }

  requestHdr.dataLen = HTOAL( textLen );
  /* pid already set to 0 from memset */

  requestBlock.AgentID = HTOAS( skeletonAgentID );
  requestBlock.UserDefined = HTOAL( HSHSERV_HSH_SHA1 );

  requestBlock.RequestControlBlkLength = sizeof( hashHdr_t );
  requestBlock.RequestControlBlkAddr   = ( unsigned char*)&requestHdr;

  requestBlock.RequestDataLength  = textLen;
  requestBlock.RequestDataAddress = text;

  requestBlock.ReplyControlBlkLength = sizeof( hashHdr_t );
  requestBlock.ReplyControlBlkAddr   = (unsigned char*)&replyHdr;

  requestBlock.ReplyDataLength = sizeof( hash );
  requestBlock.ReplyDataAddr   = hash;

  if( ( rc = xcRequest( *pAdapterHandle, &requestBlock ) ) != 0 )
  {
    printf( "xcRequest failed rc = 0x%x\n", rc );
    xcCloseAdapter( *pAdapterHandle );
    exit( 1 );
  }

  /* request completed, process result */
  replyLength = ATOHL( replyHdr.dataLen );

  if( replyLength != SHA1_PADDED_LEN )
  {
    printf( "Error! replyLength must be SHA1_HASH_SIZE\n" );
    return;
  }

  if( ATOHL( requestBlock.Status ) != 0 )
  {
    printf( "Request status nonzero, error!\n" );
    printf( "Request Block Status = 0x%x\n", requestBlock.Status );
    return;
  }

  printf( "Hash of Data:\n" );
  for( i = 0; i < 20; i++ )
  {
    printf( "%02x ", hash[i] );
  }

  printf( "\n" );
  return;
}
