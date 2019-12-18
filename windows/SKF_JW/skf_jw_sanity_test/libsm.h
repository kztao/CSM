/******************************************************************************************
*zhouzhe
*2013.5.3
*******************************************************************************************/

#ifndef __BN_H__
#define __BN_H__

//#define USE_MALLOC

//macro for common bn
#define WordLen						32
#define LSBOfWord					0x00000001
#define MSBOfWord					0x80000000
#define Plus						0x00000000
#define Minus						0x00000001

//macro for RSA
#define RSABNBitLen					1024
#define RSABNWordLen				32
#define RSAPrimeWordLen				16
#define MAXPrimeWordLen				32
/*#define RSABNBitLen					2048
#define RSABNWordLen				64
#define RSAPrimeWordLen				32
#define MAXPrimeWordLen				64*/
#define Ext_RSABNWordLen			RSABNWordLen + 2
#define BNMAXWordLen				2 * RSABNWordLen + 2

//macro for ECC
#define ECCBNBitLen					256
#define ECCBNWordLen				8
#define NAF_W						4
#define ECCPreTableSize				1 << (NAF_W - 2)
#define NAF_Flag					(0xffffffff << (WordLen - NAF_W)) >> (WordLen - NAF_W)
#define WordByteLen					4
#define MAXBNWordLen				8
#define MAXBNByteLen				MAXBNWordLen*WordByteLen
#define MAXBNBitLen					MAXBNByteLen*8

typedef struct  _NAF
{
	unsigned int	count;					//count : the number of SWord occupied by NAF(k)		
	int	k[ECCBNBitLen + 1];		// every ki of NAF(k) store in this array 
} NAF, *pNAF;

typedef struct _A_Point
{
	unsigned int X[ECCBNWordLen];				
	unsigned int Y[ECCBNWordLen];				
}A_Point, *pA_Point;					// struct of affine coordinate

typedef	struct _J_Point
{
	unsigned int X[ECCBNWordLen];				
	unsigned int Y[ECCBNWordLen];				
	unsigned int Z[ECCBNWordLen];				
}J_Point, *pJ_Point;					// struct of projective coordinate

typedef struct _Jm_Point
{
	unsigned int X[ECCBNWordLen];			
	unsigned int Y[ECCBNWordLen];			
	unsigned int Z[ECCBNWordLen];			
	unsigned int aZ4[ECCBNWordLen];		
}Jm_Point, *pJm_Point;					// struct of modified projective coordinate

typedef struct _EC
{
	int BNWordLen;						
	unsigned int EC_P[ECCBNWordLen];		
	unsigned int EC_N[ECCBNWordLen];			
	unsigned int EC_a[ECCBNWordLen];			
	unsigned int EC_b[ECCBNWordLen];			
	A_Point EC_G;						
	A_Point GArray[ECCPreTableSize];	
}EC, *pEC;	

typedef struct _SCH_CTX
{
	unsigned int state[8];
	unsigned int count[2];
	unsigned char buffer[64];
} SCH_CTX;


#ifdef  __cplusplus
extern "C" {
#endif
	unsigned char SM2_ENC(unsigned char* pucPlainHex,unsigned int uiPlainLen,unsigned char* strPub,unsigned char*pucEncipher);
	unsigned char SM2_DEC(unsigned char* cipher, unsigned int cipherLen, unsigned char* strPri,unsigned char *pucPlainHex);
	int SM2_Sign(unsigned char* pucData,unsigned int uiDataLen,unsigned char* strPri,unsigned char *strSign);
	int  SM2_Verify(unsigned char* pucData,unsigned int uiInLen,unsigned char* Signature,unsigned char* strPub);
int PBOC_SMHash(unsigned char *pucPub,unsigned int uiPubicKeyLen,unsigned char *pucInData,unsigned int uiInLen,unsigned char *pucDigest);
	void SM3_Hash(unsigned char *pucInMessage,unsigned int uiInMessageLen,unsigned char *pucDigest);
	int SM3_Compute(unsigned char* InMessage,unsigned int uiInLen,unsigned char*strDigest);
	void SM4_Encrypt(unsigned char *pKey, unsigned char *pDataIn, unsigned char *pDataOut);
	void SM4_Decrypt(unsigned char *pKey, unsigned char *pDataIn, unsigned char *pDataOut);
#ifdef  __cplusplus
}
#endif


#endif

