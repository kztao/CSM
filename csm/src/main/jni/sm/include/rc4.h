#ifndef _RC4_H_DE188941a3375d3a
#define _RC4_H_DE188941a3375d3a
  

#include "mm_types.h"

#ifdef  __cplusplus
extern "C" {
#endif
 
typedef struct rc4_key_st
{
	u32_t x,y;
	u32_t data[256];
} RC4_KEY;
	
	 
void RC4_set_key(RC4_KEY *key, int len, const BYTE *data);
void RC4(RC4_KEY *key, u32_t len, const BYTE *indata, BYTE *outdata);


	
#ifdef  __cplusplus
}
#endif
 

#endif/* #ifndef _RC4_H_DE188941a3375d3a */
