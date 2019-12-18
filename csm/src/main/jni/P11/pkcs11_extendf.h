
/*************************************************
 Copyright (C),卫士通移动互联网事业部
 Author: wangjunren Version: V1.0.0 Date: 20180108
 Description: 
	本文件为P11的扩展函数定义文件
	本文件的函数定义符合C语言的编译和连接规约

*************************************************/

typedef void* (*NotifyFunc)(unsigned int); //If SCS is crash, this function will be called to notify the proxy to reconnect

CK_PKCS11_FUNCTION_INFO(Register_Exception_Notify_Callback)
#ifdef CK_NEED_ARG_LIST
(
	NotifyFunc notifyfunc
);
#endif


/* C_Extend_GetPinRemainCount gets remain try time of userpin. */
CK_PKCS11_FUNCTION_INFO(C_Extend_GetPinRemainCount)
#ifdef CK_NEED_ARG_LIST
(
	CK_SESSION_HANDLE hSession, /* session's handle */
	CK_ULONG_PTR pUiRemainCount /* gets userpin's remain time */
);
#endif

/* C_Extend_GetStatus gets card's status. */
CK_PKCS11_FUNCTION_INFO(C_Extend_GetStatus)
#ifdef CK_NEED_ARG_LIST
(
	CK_SLOT_ID slotID,          /* the ID of the slot */
	CK_STATUS_ENUM_PTR pStatus  /* gets card's status */
);
#endif


/* C_Extend_Register_Callback registers callback function 
when card's status changes. */
CK_PKCS11_FUNCTION_INFO(C_Extend_Register_Callback)
#ifdef CK_NEED_ARG_LIST
(
	register_status_callback_func func   /* the call back function to be registered*/
);
#endif

/* C_Extend_Unregister_Callback unregisters callback function 
when card's status changes. */
CK_PKCS11_FUNCTION_INFO(C_Extend_Unregister_Callback)
#ifdef CK_NEED_ARG_LIST
(
	register_status_callback_func func   /* the call back function to be unregistered */
);
#endif


/* C_Extend_GetExchangeSessionKey exports the session key in key exchange process*/
CK_PKCS11_FUNCTION_INFO(C_Extend_GetExchangeSessionKey)
#ifdef CK_NEED_ARG_LIST
(
	CK_SESSION_HANDLE hSession,        /* session's handle */
	CK_OBJECT_HANDLE hKey,             /* key handle to be exported*/
	CK_BYTE_PTR pEncryptedData,        /* gets ciphertext */
	CK_ULONG_PTR pulEncryptedDataLen   /* gets c-text size */
);
#endif

/* C_Extend_Destroy destroy objects with certain label*/
CK_PKCS11_FUNCTION_INFO(C_Extend_Destroy)
#ifdef CK_NEED_ARG_LIST
(
	CK_SLOT_ID slotID,                 /* the ID of the slot */
	CK_BYTE_PTR containerName          /* the label of objects to be destoryed */
);
#endif

/* C_Extend_Reset_Pin_With_OTP resets userpin with OTP pin*/
CK_PKCS11_FUNCTION_INFO(C_Extend_Reset_Pin_With_OTP)
#ifdef CK_NEED_ARG_LIST
(
	CK_SESSION_HANDLE hSession,        /* session's handle */
	CK_BYTE_PTR pbOTPPIN,              /* OTP PIN */
	CK_ULONG ulOTPPINLen,              /* the length of OTP PIN */
	CK_BYTE_PTR pbNewUserPIN,          /* new userpin */
	CK_ULONG ulNewUserPINLen           /* the length of new userpin */
);
#endif

/* C_Extend_Reset_OTP updates OTP PIN*/
CK_PKCS11_FUNCTION_INFO(C_Extend_Reset_OTP)
#ifdef CK_NEED_ARG_LIST
(
	CK_SESSION_HANDLE hSession,   /* session's handle */
	CK_BYTE_PTR pbOTPMpk,         /* the ciphertext used to update otp pin */
	CK_ULONG ulMpkLen,            /* the length of the ciphertext */
	CK_BYTE_PTR pbMpkIV,          /* the iv used to decrypt the ciphertext */
	CK_ULONG ulMpkIVLen           /* the length of iv*/
);
#endif


/* C_Extend_Get_OTP_Unlock_Count gets remain try time of OTP pin*/
CK_PKCS11_FUNCTION_INFO(C_Extend_Get_OTP_Unlock_Count)
#ifdef CK_NEED_ARG_LIST
(
	CK_SESSION_HANDLE hSession,   /* session's handle */
	CK_ULONG_PTR pulCount         /* gets the remain try time of OTP pin*/
);
#endif

/* C_Extend_Get_OTP_Remain_Count gets remain usable time of OTP pin*/
CK_PKCS11_FUNCTION_INFO(C_Extend_Get_OTP_Remain_Count)
#ifdef CK_NEED_ARG_LIST
(
	CK_SESSION_HANDLE hSession,   /* session's handle */
	CK_ULONG_PTR pulCount         /* gets the remain usable time of OTP pin*/
);
#endif

/* C_Extend_DeriveSessionKey derives session key in key exchange process*/
CK_PKCS11_FUNCTION_INFO(C_Extend_DeriveSessionKey)
#ifdef CK_NEED_ARG_LIST
(
   CK_SESSION_HANDLE hSession,   /* session's handle */
   CK_MECHANISM_PTR pMechanism,  /* the encryption mechanism */
   CK_OBJECT_HANDLE hLocalKey,   /* local key handle */
   CK_OBJECT_HANDLE hRemoteKey,  /* remote key handle */
   CK_ATTRIBUTE_PTR pTemplate,   /* the session key's template */
   CK_ULONG ulAttributeCount,    /* attributes in template */
   CK_OBJECT_HANDLE_PTR phKey,   /* gets the derived session key's handle. */
   CK_BYTE_PTR pExchangeIV,      /* gets derived iv */
   CK_ULONG_PTR pExchangeIVLen   /* gets the length of iv */
);
#endif

/* C_Extend_EncryptInit initialize encryption with a key's template*/
CK_PKCS11_FUNCTION_INFO(C_Extend_EncryptInit)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_ATTRIBUTE_PTR  pTemplate,	 /* template of encryption key */
  CK_ULONG ulAttributeCount		 /* template of encryption key count*/	
);
#endif

/* C_Extend_DecryptInit initialize decryption with a key's template*/
CK_PKCS11_FUNCTION_INFO(C_Extend_DecryptInit)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_ATTRIBUTE_PTR  pTemplate,   /* template of decryption key */
  CK_ULONG ulAttributeCount		/* template of decryption key count*/
);
#endif

/* C_Extend_EncryptUpdate continues a multiple-part encryption
 * operation after C_Extend_EncryptInit
 */
CK_PKCS11_FUNCTION_INFO(C_Extend_EncryptUpdate)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pIv,                /* encrypted iv */
  CK_ULONG          ulIvLen,            /* encrypted iv len */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
);
#endif

/* C_Extend_DecryptUpdate continues a multiple-part encryption
 * operation after C_Extend_DecryptInit
 */
CK_PKCS11_FUNCTION_INFO(C_Extend_DecryptUpdate)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pIv,                /* decrypted iv */
  CK_ULONG          ulIvLen,            /* decrypted iv len */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
);
#endif

/* C_Extend_EncryptFinalize finishes a multiple-part encryption
 * operation.of C_Extend_EncryptInit
 */
CK_PKCS11_FUNCTION_INFO(C_Extend_EncryptFinalize)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
);
#endif

/* C_Extend_DecryptFinalize finishes a multiple-part encryption
 * operation.of C_Extend_DecryptInit
 */
CK_PKCS11_FUNCTION_INFO(C_Extend_DecryptFinalize)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
);
#endif

/* C_Extend_PointMultiply initialize encryption with a key's template*/
CK_PKCS11_FUNCTION_INFO(C_Extend_PointMultiply)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,   /* session's handle */
  CK_MECHANISM_PTR pMechanism,  /* the point multiply mechanism, including public key in parameter*/
  CK_OBJECT_HANDLE hKey,        /* privatekey handle */
  CK_BYTE_PTR pOutData,         /* gets result of point multiply */
  CK_ULONG_PTR pOutLen           /* gets length of result */
);
#endif

/* C_Extend_Reset_TT resets TT*/
CK_PKCS11_FUNCTION_INFO(C_Extend_Reset_TT)
#ifdef CK_NEED_ARG_LIST
(
		CK_SESSION_HANDLE hSession,   /* session's handle */
		CK_BYTE_PTR pbTTMpk,          /* the ciphertext used to update TT*/
		CK_ULONG ulMpkLen,            /* the length of ciphertext*/
		CK_BYTE_PTR pbMpkIV,          /* the iv used to decrypt the ciphertext */
		CK_ULONG ulMpkIVLen           /* the length of iv */
);
#endif

/* C_Extend_Reset_BK resets BK*/
CK_PKCS11_FUNCTION_INFO(C_Extend_Reset_BK)
#ifdef CK_NEED_ARG_LIST
(
		CK_SESSION_HANDLE hSession,   /* session's handle */
		CK_BYTE_PTR pbBKMpk,          /* the ciphertext used to update BK*/
		CK_ULONG ulMpkLen,            /* the length of ciphertext*/
		CK_BYTE_PTR pbMpkIV,          /* the iv used to decrypt the ciphertext */
		CK_ULONG ulMpkIVLen           /* the length of iv */
);
#endif

/* C_Extend_Get_Special_Object_Version gets version of special object*/
CK_PKCS11_FUNCTION_INFO(C_Extend_Get_Special_Object_Version)
#ifdef CK_NEED_ARG_LIST
(
		CK_SESSION_HANDLE            hSession,   /* session's handle */
		CK_OBJECT_CLASS 	  objectClass,       /* Object class*/
		CK_BYTE_PTR pVersion,                    /* gets version of the object*/
		CK_ULONG_PTR pUlLen                      /* gets length of the version*/

);
#endif

/* C_Extend_DestroyCard destroy the card. The card cannot be used after this interface succeeds.*/
CK_PKCS11_FUNCTION_INFO(C_Extend_DestroyCard)
#ifdef CK_NEED_ARG_LIST
(
		CK_SLOT_ID slotID,                   /* session's handle */
		CK_BYTE_PTR prandomIn,               /* random number used to destroy the card*/
		CK_ULONG randomInLen,                /* the length of random number*/
		CK_BYTE_PTR prandomOut,              /* gets a random number*/
		CK_ULONG_PTR prandomOutLen           /* gets the length of the output random number*/
);
#endif


/* C_Extend_MonopolizeEnable monopolize the card. Other application cannot use the card.until
 * monopolize ends*/
CK_PKCS11_FUNCTION_INFO(C_Extend_MonopolizeEnable)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID            slotID        /* the slot's ID */
);
#endif

/* C_Extend_MonopolizeDisable ends the monopolization of the card.*/
CK_PKCS11_FUNCTION_INFO(C_Extend_MonopolizeDisable)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID            slotID        /* the slot's ID */
);

#endif

/* C_Extend_GetDevInfo gets device information of westone softcard.*/
CK_PKCS11_FUNCTION_INFO(C_Extend_GetDevInfo)
#ifdef CK_NEED_ARG_LIST
(
 CK_SLOT_ID slotID,            /* the slot's ID */
 const char *userName,         /* the username of the softcard */
 CK_IP_PARAMS_PTR ipparam,       /* cspp of the softcard */
 CK_BYTE_PTR pDevInfo,         /* gets device info */
 CK_ULONG_PTR pUlDevInfoLen    /* gets the length device info */
);
#endif

/* C_Extend_DevSign gets signature from westone softcard*/
CK_PKCS11_FUNCTION_INFO(C_Extend_DevSign)
#ifdef CK_NEED_ARG_LIST
(
 CK_SLOT_ID slotID,                 /* the slot's ID */
 CK_BYTE_PTR       pData,           /* the data to sign */
 CK_ULONG          ulDataLen,       /* count of bytes to sign */
 CK_BYTE_PTR       pSignature,      /* gets the signature */
 CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
);
#endif

/* C_Extend_Set_DestroyKey set destroy key on westone softcard*/
CK_PKCS11_FUNCTION_INFO(C_Extend_Set_DestroyKey)
#ifdef CK_NEED_ARG_LIST
(
	CK_SESSION_HANDLE hSession,   /* session's handle */
	CK_BYTE_PTR pDestroyKeyMpk,   /* the ciphertext used to set destroy key*/
	CK_ULONG ulMpkLen,            /* the length of ciphertext*/
	CK_BYTE_PTR pbMpkIV,          /* the iv used to decrypt the ciphertext */
	CK_ULONG ulMpkIVLen           /* the length of iv*/

);
#endif

/* C_Extend_Get_ExchangePubKey gets public key used in key exchange process*/
CK_PKCS11_FUNCTION_INFO(C_Extend_Get_ExchangePubKey)
#ifdef CK_NEED_ARG_LIST
(
	CK_SESSION_HANDLE hSession,                /* session's handle */
	CK_BYTE_PTR 	  pExchangePubKeyValue,	   /* get public key value */
	CK_ULONG_PTR	  pulKeyLen                /* get the length of public key */
);
#endif







