/*************************************************/
/* Header for Skeleton functions                 */
/*************************************************/

#ifndef _SKEL_SERVERS_H_
#define _SKEL_SERVERS_H_

#ifdef NT_ON_I386
  #include <windows.h> /* required for HANDLE */
#endif

#ifndef _XC_HOST_H_
  #include "xc_host.h"
#endif

/* this file contains a list of all host side processing functions */
/* for card side servers                                           */
void 
do_model( xcAdapterHandle_t * pAdapterHandle );

void 
do_adptserv( xcAdapterHandle_t * pAdapterHandle );

void 
do_rngserv( xcAdapterHandle_t * pAdapterHandle );

void 
do_ppdserv( xcAdapterHandle_t * pAdapterHandle );

void 
do_pkaserv( xcAdapterHandle_t * pAdapterHandle );

void 
do_limserv( xcAdapterHandle_t * pAdapterHandle );

void 
do_hshserv( xcAdapterHandle_t * pAdapterHandle );

void 
do_desserv( xcAdapterHandle_t * pAdapterHandle );

void
do_aesserv( xcAdapterHandle_t * pAdapterHandle );

#endif
