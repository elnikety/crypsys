/***********************************************************************
 * aesHost.c - Host Skeleton sample program.                           *
 *             This program is an example of RNG services as part of   *
 *             a menu of options (skelhost.c is the main server)       *
 *                                                                     *
 ***********************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef NT_ON_I386
  #include <windows.h>
  #include <sys\types.h>        /* for off_t */
#endif

#include "xc_types.h"
#ifndef _XC_HOST_H_
  #include "xc_host.h"
#endif

#include "xc_api.h"  /* for random constants */

#include "skelServers.h"
#include "skelcmn.h"
#include "skelmenu.h"
#include "rngserv.h"
#include "../../rte/shared/util.h"

void
do_rngserv( xcAdapterHandle_t * pAdapterHandle )
{
  int            rc = 0;
  int            i = 0;
  int            choice = 0;
  rngHdr_t       reqHdr, repHdr;
  /* buffer must be a multiple of 8, at least 64 bytes */
  unsigned char  randomBuffer[64];
  xcRB_t         requestBlock;

  printf( "----------------------------------------------------------\n" );
  printf( "            Random Number Generation Server\n                " );
  printf( "----------------------------------------------------------\n" );

  choice = -1;

  memset( &requestBlock, 0x00, sizeof( xcRB_t ) );
  memset( randomBuffer, 0x00, sizeof( randomBuffer ) );
  memset( &reqHdr, 0x00, sizeof( rngHdr_t ) );
  memset( &repHdr, 0x00, sizeof( rngHdr_t ) );

  while( ( choice < 0 ) || ( choice > 4 ) )
  {
    printf( "MENU:\n"
            "0.) No Parity\n" //random_random
            "1.) Odd Parity\n"
            "2.) Even Parity\n"
            "3.) DES Key (not weak)\n\n"
            "Choice ===> " );
    choice = read_safe_integer( );
  }

  reqHdr.options = RANDOM_HW; /* don't reverse until all options are added */
  reqHdr.rngBufLen  = HTOAL( 8 );

  switch( choice )
  {
    case 0:
      reqHdr.options |= RANDOM_RANDOM;
    break;

    case 1:
      reqHdr.options |= RANDOM_ODD_PARITY;
    break;

    case 2:
      reqHdr.options |= RANDOM_EVEN_PARITY;
    break;

    case 3:
      reqHdr.options |= RANDOM_NOT_WEAK;
    break;

    default:
      reqHdr.options |= RANDOM_RANDOM;
    break;
  }

  reqHdr.options = HTOAL( reqHdr.options );

  requestBlock.AgentID       = HTOAS( skeletonAgentID );
  requestBlock.UserDefined   = HTOAL( RNGSERV_RNG );

  requestBlock.RequestControlBlkLength = sizeof( rngHdr_t );
  requestBlock.RequestControlBlkAddr   = (unsigned char*)&reqHdr;

  requestBlock.RequestDataLength   = 0;
  requestBlock.RequestDataAddress  = NULL;

  requestBlock.ReplyControlBlkLength = sizeof( rngHdr_t );
  requestBlock.ReplyControlBlkAddr   = (unsigned char*)&repHdr;

  requestBlock.ReplyDataLength = sizeof( randomBuffer );
  requestBlock.ReplyDataAddr   = randomBuffer;

  if( ( rc = xcRequest( *pAdapterHandle, &requestBlock ) ) != 0 )
  {
    printf( "xcRequest failed rc = 0x%x\n", rc );
    xcCloseAdapter( *pAdapterHandle );
    exit( 1 );
  }

  printf( "Random Data Generated from Card -->\n" );

  for( i = 0; i < DEFAULT_RNG_BUF_LEN; i++ )
  {
    printf( "%x ", randomBuffer[i] );
  }

  printf( "\n" );

  return;

}

