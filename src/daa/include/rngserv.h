/* shared headers for rng server */
#if !defined(_rngserv_h_)
#define _rngserv_h_

#define DEFAULT_RNG_BUF_LEN 8

#pragma pack(1)
typedef struct 
{
  int  rngBufLen;/* length of buffer to create, default to 8 */
  int  options;  /* rng options */
  int  pid;      /* pid of thread servicing request */
  char reserved[64 - ( 3 * sizeof(int) )]; /* make struct at least 64 bytes */
}rngHdr_t;
#pragma pack()

/* user defined, skeleton random number generate */
#define  RNGSERV_RNG 0x2

/* everything's ok */
#define RNG_OK  0
/* uknown value for user defined */
#define RNG_BAD_USER_DEFINED -1
/* warning that buffer was truncated to 8 bytes */
#define RNG_BUFFER_TRUNCATED -2
/* generation failed */
#define RNG_GEN_FAILED       -3

#endif

