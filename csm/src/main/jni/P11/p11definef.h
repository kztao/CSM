#ifndef _P11DEFINEF_H_
#define _P11DEFINEF_H_


#include "cryptoki.h"
#include "p11definet.h"

#ifdef __cplusplus
extern "C"{
#endif

CK_RV C_CryptoExtend(
	CK_SESSION_HANDLE hSession, 
	CK_EXTEND_IN_PTR pExtendIn, 
	CK_EXTEND_OUT_PTR pExtendOut, 
	CK_VOID_PTR pReserved 
);

CK_RV C_GenerateExchangeKeypair
(
	CK_SESSION_HANDLE hSession,             /* the session's handle */
	CK_MECHANISM_PTR pMechanism, 			/* key deriv. mech. */
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,	/* template for pub. key */
	CK_ULONG ulPublicKeyAttributeCount,		/* # pub. attrs. */
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,	/* template for pri. key */
	CK_ULONG ulPrivateKeyAttributeCount,	/* # pri. attrs. */
	CK_OBJECT_HANDLE_PTR phPublicKey,		/* gets pub. key handle */
	CK_OBJECT_HANDLE_PTR phPrivateKey		/* gets pri. key handle */
	
);

CK_RV C_GenerateLocalSessKey
(
	CK_SESSION_HANDLE hSession,		/* the session's handle */
	CK_MECHANISM_PTR pMechanism, 	/* key deriv. mech. */
	CK_ATTRIBUTE_PTR pTemplate,		/* template for new key */
	CK_ULONG ulCount,				/* # of attrs in template */
	CK_OBJECT_HANDLE_PTR phKey		/* gets new key handle */
);

CK_RV C_WrapLocalSessKey
(
	CK_SESSION_HANDLE hSession,		/* the session's handle */
	CK_MECHANISM_PTR pMechanism, 	/* wrap mech. */
	CK_OBJECT_HANDLE hKey,			/* key to be wrapped */
	CK_BYTE_PTR pWrappedKey,		/* gets wrapped key */
	CK_ULONG_PTR pulWrappedKeyLen	/* gets wrapped key size*/
);

CK_RV C_UnwrapRemoteSessKey
(
	CK_SESSION_HANDLE hSession,		/* the session's handle */
	CK_MECHANISM_PTR pMechanism,	/* unwrap mech. */
	CK_OBJECT_HANDLE hUnwrappingKey, /*private key handle*/
	CK_BYTE_PTR pWrappedKey,		/* the wrapped key */
	CK_ULONG ulWrappedKeyLen,		/* the wrapped key size*/
	CK_ATTRIBUTE_PTR pTemplate,		/* template for new key */
	CK_ULONG ulAttributeCount,		/* # of attrs in template */
	CK_OBJECT_HANDLE_PTR phKey		/* gets new key handle */

);

CK_RV C_DeriveSessKey
(
	CK_SESSION_HANDLE hSession,		/* the session's handle */
	CK_MECHANISM_PTR pMechanism,	/* key deriv. mech. */
	CK_OBJECT_HANDLE hLocalKey,		/* local key handle */
	CK_OBJECT_HANDLE hRemoteKey,	/* remote key handle */
	CK_ATTRIBUTE_PTR pTemplate,		/* template for new key */
	CK_ULONG ulAttributeCount,		/* # of attrs in template */
	CK_OBJECT_HANDLE_PTR phKey,		/* gets new key handle */
	CK_BYTE_PTR pExchangeIV,		/* gets iv */
	CK_ULONG_PTR pExchangeIVLen		/* gets iv size */
);

CK_RV C_PointMultiply
(
	CK_SESSION_HANDLE hSession,		/* the session's handle */
	CK_MECHANISM_PTR pMechanism, 	/* the point multiply mechanism with public key value*/
	CK_OBJECT_HANDLE hKey, 			/* private key handle */
	CK_BYTE_PTR pOutData, 			/* gets result */
	CK_ULONG_PTR pOutLen 			/* gets result size*/
);

CK_RV C_EncryptUpdate_Extend
(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart,
	CK_ULONG ulPartLen,
	CK_BYTE_PTR pEncryptedPart,
	CK_ULONG_PTR pulEncryptedPartLen
);

CK_RV C_DecryptUpdate_Extend
(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pEncryptedPart,
	CK_ULONG ulEncryptedPartLen,
	CK_BYTE_PTR pPart,
	CK_ULONG_PTR pulPartLen
);

int cc_SetTransmitDelay(unsigned int nDelay1, unsigned int nDelay2);
int cc_GetTransmitDelay(unsigned int *pnDelay1, unsigned int *pnDelay2);




#ifdef __cplusplus
};
#endif

#endif

