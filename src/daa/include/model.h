/* shared header for model server */
#if !defined(_model_h_)
#define _model_h_

/* length of request buffer in bytes */
#define REQUEST_BUFFER_LENGTH 80
/* length of reply buffer in bytes */
#define REPLY_BUFFER_LENGTH 80

/* id for reverse request */
#define MODEL_REVERSE_REQUEST  0x0
/* id for reverse reply */
#define MODEL_REVERSE_REPLY    0x1
/* return code for malloc failure */
#define MODEL_MALLOC_FAILURE -1

#pragma pack(1)
typedef struct 
{
  int  bufLen;       /* length of buffer in bytes */
  int  pid;          /* process id for thread that services request */
  char dummy[ 64 - ( 2 * sizeof( int ) ) ]; /* pad to 64 bytes */
} modelHdr_t;
#pragma pack()

#endif
