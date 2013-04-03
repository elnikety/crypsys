/***********************************************************************
 * skelHost.c - Host Skeleton sample program.                          *
 *              This program is an example of how to provide a menu    *
 *              of adapter functions                                   *
 *                                                                     *
 *              Usage: sampleHostApp <adapter_number>                  *
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

#include "skelmenu.h" //for a few constants


#ifndef _XC_HOST_H_
  #include "xc_host.h"
#endif

#include "../../rte/shared/util.h"

int
main( int argc , char *argv[] )
{
  long                rc = 0;
  xcAdapterNumber_t   adapterCount;     /*number of adapters in system   */
  xcAdapterNumber_t   adapterNumber;    /* adapter to target command to  */
  xcAdapterHandle_t   adapterHandle;    /* handle to targeted adapter    */
  int                 moreRequests;     /* does user want to keep going? */
  int                 serverID = 0;     /* which server to test          */

  /* turn off output buffering */
  /* NOTE: this should be the first line of our program */
  setbuf( stdout, NULL );

  /* check arguments */
  if( argc == 1 )
  {
    /* default to adapter 0 */
    adapterNumber = 0;
  }
  else if( argc != 2 )
  {
    printf( "usage - skelhost adapternumber\n" );
    exit( 1 );
  }
  else
  {
    /* use adapter number specified on command line */
    adapterNumber = (xcAdapterNumber_t) atoi( argv[1] );
  }

  /* find out how many adapters we have in our system */
  if( ( rc = xcAdapterCount( &adapterCount ) ) != 0 )
  {
    printf( "xcAdapterCount failed rc = 0x%lx\n" , rc );
    exit( 1 );
  }

  /* make sure command is targeted to a valid adapter */
  if( adapterCount < adapterNumber +1 )
  {
    printf( "Found %d adapters in the system; adapter number specified (%d)\n"
            "requires %d\n",
            adapterCount ,
            adapterNumber ,
            adapterNumber + 1 );

    exit( 1 );
  }

  /* open the adapter */
  if( ( rc = xcOpenAdapter( adapterNumber, &adapterHandle ) ) != 0 )
  {
    printf( "xcOpenAdapter failed rc = 0x%lx\n" , rc );
    exit( 1 );
  }

  printf( "adapter %d opened!\n", adapterNumber );

  /* spin loop for host side requests */
  for( ; ; )
  {
    serverID = -1;

    while(  serverID < 0 || serverID > SERVERS )
    {
      printMenu( );
      serverID = read_safe_integer( );
    }

    if( serverID == EXITPROGRAM )
    {
      printf( "Goodbye!\n" );
      break;
    }
    else
    {
      do_request( serverID, &adapterHandle );
    }

    printf( "*****Enter c to  Continue*****\n" );
    moreRequests = read_safe_integer( );

  }/* end host side request spin loop */

  /* we're done with the adapter, so close it */
  if( ( rc = xcCloseAdapter( adapterHandle ) ) != 0 )
  {
    printf( "xcCloseAdapter failed rc = 0x%lx\n", rc );
    exit( 1 );
  }

  return 0;
}

