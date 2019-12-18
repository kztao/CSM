/* DO NOT EDIT THIS FILE - it is machine generated */
/* Header for class com_bairuitech_util_CryptoTools */

#ifndef _Included_com_bairuitech_util_CryptoTools
#define _Included_com_bairuitech_util_CryptoTools

#include "types.h"

#define SM4_ENCRYPT     1
#define SM4_DECRYPT     0

/**
 * \brief          SM4 context structure
 */
typedef struct
{
    int mode;                   /*!<  encrypt/decrypt   */
    unsigned int sk[32];       /*!<  SM4 subkeys       */
}
sm4_context;


#ifdef __cplusplus
extern "C" {
#endif


void SEA_Random(u8 *seedData, u32 seedLength, u8 *outputData, u32 dataLength);
int SEA_Encrypt(u8 *wk, u32 wk_len, u8 *mk, u32 mk_len, u8 *input, u32 input_len, u8 *output, u32 *output_len);
int SEA_Decrypt(u8 *wk, u32 wk_len, u8 *mk, u32 mk_len, u8 *input, u32 input_len, u8 *output, u32 *output_len);

void SM4_Crypt_ECB( sm4_context *ctx, u16 mode, u8 *input, u32 input_len, u8 *output, u8 * output_len);


#ifdef __cplusplus
}
#endif

#endif