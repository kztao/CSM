
#include "cryptoki.h"
#include <string>
#include "CommunicationServer.h"


using std::string;

void setMountCardFlg(bool flg);
/* Copyright (c) OASIS Open 2016. All Rights Reserved./
 * /Distributed under the terms of the OASIS IPR Policy,
 * [http://www.oasis-open.org/policies-guidelines/ipr], AS-IS, WITHOUT ANY
 * IMPLIED OR EXPRESS WARRANTY; there is no warranty of MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE or NONINFRINGEMENT of the rights of others.
 */
        
/* Latest version of the specification:
 * http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html
 */

/* This header file contains pretty much everything about all the
 * Cryptoki function prototypes.  Because this information is
 * used for more than just declaring function prototypes, the
 * order of the functions appearing herein is important, and
 * should not be altered.
 */

/* General-purpose */

/* Adapter_C_Initialize initializes the Cryptoki library. */

CK_RV Adapter_C_Initialize(CK_VOID_PTR   pInitArgs);



/* Adapter_C_Finalize indicates that an application is done with the
 * Cryptoki library.
 */
CK_RV Adapter_C_Finalize(CK_VOID_PTR   pReserved);



/* Adapter_C_GetInfo returns general information about Cryptoki. */
CK_RV Adapter_C_GetInfo(CK_INFO_PTR   pInfo);



/* Adapter_C_GetFunctionList returns the function list. */
CK_RV Adapter_C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);




/* Slot and token management */

/* Adapter_C_GetSlotList obtains a list of slots in the system. */
CK_RV Adapter_C_GetSlotList(CK_BBOOL       tokenPresent,  /* only slots with tokens */
  CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
  CK_ULONG_PTR   pulCount       /* receives number of slots */
);



/* Adapter_C_GetSlotInfo obtains information about a particular slot in
 * the system.
 */
CK_RV Adapter_C_GetSlotInfo(
  CK_SLOT_ID       slotID,  /* the ID of the slot */
  CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
);



/* Adapter_C_GetTokenInfo obtains information about a particular token
 * in the system.
 */
CK_RV Adapter_C_GetTokenInfo(
  CK_SLOT_ID        slotID,  /* ID of the token's slot */
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
);



/* Adapter_C_GetMechanismList obtains a list of mechanism types
 * supported by a token.
 */
CK_RV Adapter_C_GetMechanismList(
  CK_SLOT_ID            slotID,          /* ID of token's slot */
  CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
  CK_ULONG_PTR          pulCount         /* gets # of mechs. */
);



/* Adapter_C_GetMechanismInfo obtains information about a particular
 * mechanism possibly supported by a token.
 */
CK_RV Adapter_C_GetMechanismInfo(
  CK_SLOT_ID            slotID,  /* ID of the token's slot */
  CK_MECHANISM_TYPE     type,    /* type of mechanism */
  CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
);



/* Adapter_C_InitToken initializes a token. */
CK_RV Adapter_C_InitToken(
  CK_SLOT_ID      slotID,    /* ID of the token's slot */
  CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
  CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
  CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
);



/* Adapter_C_InitPIN initializes the normal user's PIN. */
CK_RV Adapter_C_InitPIN(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
);



/* Adapter_C_SetPIN modifies the PIN of the user who is logged in. */
CK_RV Adapter_C_SetPIN(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_UTF8CHAR_PTR   pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
);




/* Session management */

/* Adapter_C_OpenSession opens a session between an application and a
 * token.
 */
CK_RV Adapter_C_OpenSession(
  CK_SLOT_ID            slotID,        /* the slot's ID */
  CK_FLAGS              flags,         /* from CK_SESSION_INFO */
  CK_VOID_PTR           pApplication,  /* passed to callback */
  CK_NOTIFY             Notify,        /* callback function */
  CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
);



/* Adapter_C_CloseSession closes a session between an application and a
 * token.
 */
CK_RV Adapter_C_CloseSession(
  CK_SESSION_HANDLE hSession  /* the session's handle */
);



/* Adapter_C_CloseAllSessions closes all sessions with a token. */
CK_RV Adapter_C_CloseAllSessions(
  CK_SLOT_ID     slotID  /* the token's slot */
);



/* Adapter_C_GetSessionInfo obtains information about the session. */
CK_RV Adapter_C_GetSessionInfo(
  CK_SESSION_HANDLE   hSession,  /* the session's handle */
  CK_SESSION_INFO_PTR pInfo      /* receives session info */
);



/* Adapter_C_GetOperationState obtains the state of the cryptographic operation
 * in a session.
 */
CK_RV Adapter_C_GetOperationState(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
);



/* Adapter_C_SetOperationState restores the state of the cryptographic
 * operation in a session.
 */
CK_RV Adapter_C_SetOperationState(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR      pOperationState,      /* holds state */
  CK_ULONG         ulOperationStateLen,  /* holds state length */
  CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
  CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
);



/* Adapter_C_Login logs a user into a token. */
CK_RV Adapter_C_Login(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
);



/* Adapter_C_Logout logs a user out from a token. */
CK_RV Adapter_C_Logout(
  CK_SESSION_HANDLE hSession  /* the session's handle */
);




/* Object management */

/* Adapter_C_CreateObject creates a new object. */
CK_RV Adapter_C_CreateObject(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
  CK_ULONG          ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
);



/* Adapter_C_CopyObject copies an object, creating a new object for the
 * copy.
 */
CK_RV Adapter_C_CopyObject(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_OBJECT_HANDLE     hObject,     /* the object's handle */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
  CK_ULONG             ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
);



/* Adapter_C_DestroyObject destroys an object. */
CK_RV Adapter_C_DestroyObject(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject    /* the object's handle */
);



/* Adapter_C_GetObjectSize gets the size of an object in bytes. */
CK_RV Adapter_C_GetObjectSize(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
);



/* Adapter_C_GetAttributeValue obtains the value of one or more object
 * attributes.
 */
CK_RV Adapter_C_GetAttributeValue(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
  CK_ULONG          ulCount     /* attributes in template */
);



/* Adapter_C_SetAttributeValue modifies the value of one or more object
 * attributes.
 */
CK_RV Adapter_C_SetAttributeValue(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
  CK_ULONG          ulCount     /* attributes in template */
);



/* Adapter_C_FindObjectsInit initializes a search for token and session
 * objects that match a template.
 */
CK_RV Adapter_C_FindObjectsInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
  CK_ULONG          ulCount     /* attrs in search template */
);



/* Adapter_C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles.
 */
CK_RV Adapter_C_FindObjects(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
);



/* Adapter_C_FindObjectsFinal finishes a search for token and session
 * objects.
 */
CK_RV Adapter_C_FindObjectsFinal(
  CK_SESSION_HANDLE hSession  /* the session's handle */
);




/* Encryption and decryption */

/* Adapter_C_EncryptInit initializes an encryption operation. */
CK_RV Adapter_C_EncryptInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
);



/* Adapter_C_Encrypt encrypts single-part data. */
CK_RV Adapter_C_Encrypt(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pData,               /* the plaintext data */
  CK_ULONG          ulDataLen,           /* bytes of plaintext */
  CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
);



/* Adapter_C_EncryptUpdate continues a multiple-part encryption
 * operation.
 */
CK_RV Adapter_C_EncryptUpdate(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
);



/* Adapter_C_EncryptFinal finishes a multiple-part encryption
 * operation.
 */
CK_RV Adapter_C_EncryptFinal(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
);



/* Adapter_C_DecryptInit initializes a decryption operation. */
CK_RV Adapter_C_DecryptInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
);



/* Adapter_C_Decrypt decrypts encrypted data in a single part. */
CK_RV Adapter_C_Decrypt(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
  CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
  CK_BYTE_PTR       pData,              /* gets plaintext */
  CK_ULONG_PTR      pulDataLen          /* gets p-text size */
);



/* Adapter_C_DecryptUpdate continues a multiple-part decryption
 * operation.
 */
CK_RV Adapter_C_DecryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
);



/* Adapter_C_DecryptFinal finishes a multiple-part decryption
 * operation.
 */
CK_RV Adapter_C_DecryptFinal(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
);




/* Message digesting */

/* Adapter_C_DigestInit initializes a message-digesting operation. */
CK_RV Adapter_C_DigestInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
);



/* Adapter_C_Digest digests data in a single part. */
CK_RV Adapter_C_Digest(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets digest length */
);



/* Adapter_C_DigestUpdate continues a multiple-part message-digesting
 * operation.
 */
CK_RV Adapter_C_DigestUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
);



/* Adapter_C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested.
 */
CK_RV Adapter_C_DigestKey(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey       /* secret key to digest */
);



/* Adapter_C_DigestFinal finishes a multiple-part message-digesting
 * operation.
 */
CK_RV Adapter_C_DigestFinal(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
);




/* Signing and MACing */

/* Adapter_C_SignInit initializes a signature (private key encryption)
 * operation, where the signature is (will be) an appendix to
 * the data, and plaintext cannot be recovered from the
 * signature.
 */
CK_RV Adapter_C_SignInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of signature key */
);



/* Adapter_C_Sign signs (encrypts with private key) data in a single
 * part, where the signature is (will be) an appendix to the
 * data, and plaintext cannot be recovered from the signature.
 */
CK_RV Adapter_C_Sign(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
);



/* Adapter_C_SignUpdate continues a multiple-part signature operation,
 * where the signature is (will be) an appendix to the data,
 * and plaintext cannot be recovered from the signature.
 */
CK_RV Adapter_C_SignUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* the data to sign */
  CK_ULONG          ulPartLen  /* count of bytes to sign */
);



/* Adapter_C_SignFinal finishes a multiple-part signature operation,
 * returning the signature.
 */
CK_RV Adapter_C_SignFinal(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
);



/* Adapter_C_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature.
 */
CK_RV Adapter_C_SignRecoverInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
);



/* Adapter_C_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature.
 */
CK_RV Adapter_C_SignRecover(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
);




/* Verifying signatures and MACs */

/* Adapter_C_VerifyInit initializes a verification operation, where the
 * signature is an appendix to the data, and plaintext cannot
 * cannot be recovered from the signature (e.g. DSA).
 */
CK_RV Adapter_C_VerifyInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
);



/* Adapter_C_Verify verifies a signature in a single-part operation,
 * where the signature is an appendix to the data, and plaintext
 * cannot be recovered from the signature.
 */
CK_RV Adapter_C_Verify(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pData,          /* signed data */
  CK_ULONG          ulDataLen,      /* length of signed data */
  CK_BYTE_PTR       pSignature,     /* signature */
  CK_ULONG          ulSignatureLen  /* signature length*/
);



/* Adapter_C_VerifyUpdate continues a multiple-part verification
 * operation, where the signature is an appendix to the data,
 * and plaintext cannot be recovered from the signature.
 */
CK_RV Adapter_C_VerifyUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* signed data */
  CK_ULONG          ulPartLen  /* length of signed data */
);



/* Adapter_C_VerifyFinal finishes a multiple-part verification
 * operation, checking the signature.
 */
CK_RV Adapter_C_VerifyFinal(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pSignature,     /* signature to verify */
  CK_ULONG          ulSignatureLen  /* signature length */
);



/* Adapter_C_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature.
 */
CK_RV Adapter_C_VerifyRecoverInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
);



/* Adapter_C_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature.
 */
CK_RV Adapter_C_VerifyRecover(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
);




/* Dual-function cryptographic operations */

/* Adapter_C_DigestEncryptUpdate continues a multiple-part digesting
 * and encryption operation.
 */
CK_RV Adapter_C_DigestEncryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
);



/* Adapter_C_DecryptDigestUpdate continues a multiple-part decryption and
 * digesting operation.
 */
CK_RV Adapter_C_DecryptDigestUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
);



/* Adapter_C_SignEncryptUpdate continues a multiple-part signing and
 * encryption operation.
 */
CK_RV Adapter_C_SignEncryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
);



/* Adapter_C_DecryptVerifyUpdate continues a multiple-part decryption and
 * verify operation.
 */
CK_RV Adapter_C_DecryptVerifyUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
);




/* Key management */

/* Adapter_C_GenerateKey generates a secret key, creating a new key
 * object.
 */
CK_RV Adapter_C_GenerateKey(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
  CK_ULONG             ulCount,     /* # of attrs in template */
  CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
);



/* Adapter_C_GenerateKeyPair generates a public-key/private-key pair,
 * creating new key objects.
 */
CK_RV Adapter_C_GenerateKeyPair(
  CK_SESSION_HANDLE    hSession,                    /* session handle */
  CK_MECHANISM_PTR     pMechanism,                  /* key-gen mech. */
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template for pub. key */
  CK_ULONG             ulPublicKeyAttributeCount,   /* # pub. attrs. */
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template for priv. key */
  CK_ULONG             ulPrivateKeyAttributeCount,  /* # priv.  attrs. */
  CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub. key handle */
  CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets priv. key handle */
);



/* Adapter_C_WrapKey wraps (i.e., encrypts) a key. */
CK_RV Adapter_C_WrapKey(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
  CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
);



/* Adapter_C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object.
 */
CK_RV Adapter_C_UnwrapKey(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
  CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
  CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
);



/* Adapter_C_DeriveKey derives a key from a base key, creating a new key
 * object.
 */
CK_RV Adapter_C_DeriveKey(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
  CK_OBJECT_HANDLE     hBaseKey,          /* base key */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
);




/* Random number generation */

/* Adapter_C_SeedRandom mixes additional seed material into the token's
 * random number generator.
 */
CK_RV Adapter_C_SeedRandom(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pSeed,     /* the seed material */
  CK_ULONG          ulSeedLen  /* length of seed material */
);



/* Adapter_C_GenerateRandom generates random data. */
CK_RV Adapter_C_GenerateRandom(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_BYTE_PTR       RandomData,  /* receives the random data */
  CK_ULONG          ulRandomLen  /* # of bytes to generate */
);




/* Parallel function management */

/* Adapter_C_GetFunctionStatus is a legacy function; it obtains an
 * updated status of a function running in parallel with an
 * application.
 */
CK_RV Adapter_C_GetFunctionStatus(
  CK_SESSION_HANDLE hSession  /* the session's handle */
);



/* Adapter_C_CancelFunction is a legacy function; it cancels a function
 * running in parallel.
 */
CK_RV Adapter_C_CancelFunction(
  CK_SESSION_HANDLE hSession  /* the session's handle */
);



/* Adapter_C_WaitForSlotEvent waits for a slot event (token insertion,
 * removal, etc.) to occur.
 */
CK_RV Adapter_C_WaitForSlotEvent(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
);


/********************************
 *剩余口令剩余尝试次数
*/
CK_RV Adapter_C_Extend_GetPinRemainCount
(
  CK_SESSION_HANDLE hSession,
  CK_ULONG_PTR pUiRemainCount
);

/********************************
 *获取密码卡状态
*/
CK_RV Adapter_C_Extend_GetStatus
(
  CK_SLOT_ID slotID,
  CK_STATUS_ENUM_PTR pStatus
);

/********************************
 *注册密码卡状态回调函数
*/

typedef CK_RV (*register_status_callback_func)(CK_SLOT_ID slotID,CK_STATUS_ENUM status);

CK_RV Adapter_C_Extend_Register_Callback
(
  register_status_callback_func func
);

/********************************
 *注销密码卡状态回调函数
*/
CK_RV Adapter_C_Extend_Unregister_Callback
(
  register_status_callback_func func
);

/********************************
 *使用监听公钥导出协商密钥
*/
CK_RV Adapter_C_Extend_GetExchangeSessionKey
(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hSessionKey,
  CK_BYTE_PTR pEncryptedData,
  CK_ULONG_PTR pulEncryptedDataLen
);


/********************************
 *参数注销
*/
CK_RV Adapter_C_Extend_Destroy
(
  CK_SLOT_ID slotID,
  CK_BYTE_PTR containerName
);

/********************************
 *重设用户口令
*/
CK_RV Adapter_C_Extend_Reset_Pin_With_OTP
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pbOTPPIN,
  CK_ULONG ulOTPPINLen,
  CK_BYTE_PTR pbNewUserPIN,
  CK_ULONG ulNewUserPINLen
);

/********************************
 *重设OTP口令
*/
CK_RV Adapter_C_Extend_Reset_OTP
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pbOTPMpk,
  CK_ULONG ulMpkLen,
  CK_BYTE_PTR pbMpkIV,
  CK_ULONG ulMpkIVLen
);

/********************************
 *获取剩余OTP解锁次数
*/
CK_RV Adapter_C_Extend_Get_OTP_Unlock_Count
(
  CK_SESSION_HANDLE hSession,
  CK_ULONG_PTR pulCount
);

/********************************
 *获取剩余OTP尝试次数
*/
CK_RV Adapter_C_Extend_Get_OTP_Remain_Count
(
  CK_SESSION_HANDLE hSession,
  CK_ULONG_PTR pulCount
);

/********************************
 *协商会话密钥加密初始化
*/
CK_RV Adapter_C_Extend_DeriveSessionKey
(
   CK_SESSION_HANDLE hSession,

   CK_MECHANISM_PTR pMechanism,

   CK_OBJECT_HANDLE hLocalKey,

   CK_OBJECT_HANDLE hRemoteKey,

   CK_ATTRIBUTE_PTR pTemplate,

   CK_ULONG ulAttributeCount,

   CK_OBJECT_HANDLE_PTR phKey,

   CK_BYTE_PTR pExchangeIV,

   CK_ULONG_PTR pExchangeIVLen
);


/********************************
 *协商会话密钥加密初始化
*/
CK_RV Adapter_C_Extend_EncryptInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_ATTRIBUTE_PTR  pTemplate,   /* template of enyption key */
  CK_ULONG ulAttributeCount      /* template of enyption key count*/

);

/******************************
 *协商会话密钥解密初始化
*/
CK_RV Adapter_C_Extend_DecryptInit
(
    CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,   /* the decryption mechanism */
  CK_ATTRIBUTE_PTR  pTemplate,   /* template of decryption key */
  CK_ULONG ulAttributeCount     /* template of decryption key count*/
);


/********************************
 *协商会话密钥分步加密
*/
CK_RV Adapter_C_Extend_EncryptUpdate
(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pIv,                /* encrypted iv */
  CK_ULONG          ulIvLen,            /* encrypted iv len */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
);


/********************************
 *协商会话密钥分步解密
*/
CK_RV Adapter_C_Extend_DecryptUpdate
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pIv,                /* decrypted iv */
  CK_ULONG          ulIvLen,            /* decrypted iv len */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
);


/********************************
 *协商会话密钥分步加密结束
*/
CK_RV Adapter_C_Extend_EncryptFinalize
(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
);


/********************************
 *协商会话密钥分步解密结束
*/
CK_RV Adapter_C_Extend_DecryptFinalize
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
);


/********************************
 *SM2点乘
*/
CK_RV Adapter_C_Extend_PointMultiply
(

  CK_SESSION_HANDLE hSession,

  CK_MECHANISM_PTR pMechanism,

  CK_OBJECT_HANDLE hKey,

  CK_BYTE_PTR pOutData,

  CK_ULONG_PTR pOutLen
);

/********************************
 *重设TT口令
*/
CK_RV Adapter_C_Extend_Reset_TT
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pbTTMpk,
  CK_ULONG ulMpkLen,
  CK_BYTE_PTR pbMpkIV,
  CK_ULONG ulMpkIVLen
);

/********************************
 *重设BK口令
*/
CK_RV Adapter_C_Extend_Reset_BK
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pbBKMpk,
  CK_ULONG ulMpkLen,
  CK_BYTE_PTR pbMpkIV,
  CK_ULONG ulMpkIVLen
);


CK_RV Adapter_C_Extend_Get_Special_Object_Version
(
	CK_SESSION_HANDLE            hSession,
	CK_OBJECT_CLASS 	  objectClass,
	CK_BYTE_PTR pVersion,
	CK_ULONG_PTR pUlLen

);

CK_RV Adapter_C_Extend_DestroyCard
(
	CK_SLOT_ID slotID,
	CK_BYTE_PTR prandomIn,
	CK_ULONG randomInLen,
	CK_BYTE_PTR prandomOut,
	CK_ULONG_PTR prandomOutLen
);


CK_RV Adapter_C_Extend_DestroyCard
(
	CK_SLOT_ID slotID,
	CK_BYTE_PTR prandomIn,
	CK_ULONG randomInLen,
	CK_BYTE_PTR prandomOut,
	CK_ULONG_PTR prandomOutLen
);


/******************************
 *独占
*/

CK_RV Adapter_C_Extend_MonopolizeEnable
(
  CK_SLOT_ID            slotID        /* the slot's ID */
);


/******************************
 *取消独占
*/
CK_RV Adapter_C_Extend_MonopolizeDisable
(
  CK_SLOT_ID            slotID        /* the slot's ID */
);


CK_RV Adapter_C_Extend_GetDevInfo
(
 CK_SLOT_ID slotID,
 const char *userName,         
 CK_IP_PARAMS_PTR cspp,   
 CK_BYTE_PTR pDevInfo,
 CK_ULONG_PTR pUlDevInfoLen
);


CK_RV Adapter_C_Extend_DevSign
(
	CK_SLOT_ID slotID,
	CK_BYTE_PTR       pData,           /* the data to sign */
	CK_ULONG          ulDataLen,       /* count of bytes to sign */
	CK_BYTE_PTR       pSignature,      /* gets the signature */
	CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
);

CK_RV Adapter_C_Extend_Set_DestroyKey
(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pDestroyKeyMpk,
	CK_ULONG ulMpkLen,
	CK_BYTE_PTR pbMpkIV,
	CK_ULONG ulMpkIVLen
);



CK_RV Adapter_C_Extend_Get_ExchangePubKey
(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR 	  pExchangePubKeyValue,	  
	CK_ULONG_PTR	  pulKeyLen  
);

void getclientname(string name);

void add_clienttable(CommunicationServer::Communication *client,string appname);
void close_clientsession(CommunicationServer::Communication *client);
void close_appsession(string appname);


void closeTFCard();
void GetTFcardStatus();

CK_RV Adapter_SC_CREATESC(string token, string userName, string licSesrverAddr, string csppAddr);
CK_RV Adapter_SC_C_Destroy_Extend();



