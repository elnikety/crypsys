/* Shared (host and card) adapter info service declarations */
#if !defined(_adptserv_h_)
#define _adptserv_h_

#pragma pack(1)
typedef struct adptrHdr_t
{
  int  pid;
  char dummy[64 - sizeof( int )]; /* pad structure to 64 bytes */
}adptHdr_t;
#pragma pack()

/* get some info about the card */
#define ADAPTER_ID_REQUEST  0x3
/* adapter server returned ok */
#define ADPTSERV_OK  0
/* call to xcGetConfig failed */
#define GETCONFIG_FAILED -1
/* there is a bad parameter passed */
#define ADPTSERV_BAD_PARM -2
/* could not malloc in adptserv */
#define ADPTSERV_MALLOC_ERR -3
/* maximum number of threads to spawn */
#define MAX_THREADS  4

#endif
