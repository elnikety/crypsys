/***********************************************************************
 * skelmenu.c - Host Skeleton sample menu program.                     *
 *              This program is an example of how to provide a menu    *
 *              of adapter functions (skelhost.c is the main server)   *
 *                                                                     *
 ***********************************************************************/

#include <stdio.h>
#include <stdlib.h>

#ifdef NT_ON_I386
#include <windows.h>
#include <sys\types.h>     // for off_t
#endif

#include "xc_api.h"
#include "xc_types.h"
#include "xc_api.h"
#include "skelServers.h"

#ifndef _XC_HOST_H_
  #include "xc_host.h"
#endif

#include "skelmenu.h"

#include "../../rte/shared/util.h"

void do_request(int serverID, xcAdapterHandle_t *pAdapterHandle )
{
  /* obscure way to clear the screen */
  printf("\033\133\062\112");

  switch( serverID )
  {
   case adptserv:
     do_adptserv( pAdapterHandle );
   break;

   case desserv:
     do_desserv( pAdapterHandle );
   break;

   case hshserv:
     do_hshserv( pAdapterHandle );
   break;

   case limserv:
     do_limserv( pAdapterHandle );
   break;

   case pkaserv:
     do_pkaserv( pAdapterHandle );
   break;

   case rngserv:
     do_rngserv( pAdapterHandle );
   break;

   case model:
     do_model( pAdapterHandle );
   break;

   case aesserv:
     do_aesserv( pAdapterHandle );
   break;

   default:
     printf( "ERROR! Invalid value %d for get_input\n", serverID );
   break;
  }
}

void
printMenu( void )
{
  /* Clear the screen for OS/2, Linux, Unix?? */
  printf("\033\133\062\112");

  printf( "\n\n" );
  printf( "-------------------------------------------------------\n" );
  printf( "\tPlease choose from the following options:\n" );
  printf( "-------------------------------------------------------\n" );
  printf( "   0  -->    4765 Adapter Information Server\n" );
  printf( "   1  -->    DES Encryption, Decryption, and MAC Server\n" );
  printf( "   2  -->    SHA-1 Hash Server\n" );
  printf( "   3  -->    Large Integer Math Server\n" );
  printf( "   4  -->    PKA Server\n" );
  printf( "   5  -->    Random Number Generator Server\n" );
  printf( "   6  -->    Reverse Then Echo Server\n" );
  printf( "   7  -->    AES Encryption, Decryption, and MAC Server\n" );
  printf( "   8  -->    Exit program\n" );
  printf( "-------------------------------------------------------\n" );
  printf( "   Choice ===>    " );
}

int
read_safe_integer( void )
{
  /* this function reads an integer from the terminal
   * in a safe manner, if scanf("%d",&someVariable); is
   * used, and the user is a moron who enters a character,
   * (when he/she should have entered an integer)
   * the program will behave in a not so desirable manner
   *  inputs -  none
   *  outputs - returns the integer value entered from the keyboard
   *            if an int was entered, otherwise returns 0
   */

  char input[80];
  scanf( "%s", input);
  return atoi( input );
}
