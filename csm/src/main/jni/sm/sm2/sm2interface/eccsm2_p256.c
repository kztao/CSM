/*******************************************************************************
��Ȩ����: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
�ļ�����: eccsm2_p256.c
�ļ�����: SM2�ӿ�ʵ�֣����ɵ��ӣ�
�� �� ��: ���Ŀ� ��Ӱ
����ʱ��: 2014��11��10��
�޸���ʷ:
1. 2014��11��10��	���Ŀ� ��Ӱ		�����ļ� 
*******************************************************************************/


/* ------------------------ ͷ�ļ������� ��ʼ ------------------------------- */
#include "eccsm2_p256.h"
#include "sm2_type.h"
#include "mm_macro.h"
#include "ec_general.h"
#include "ecdsa.h"
#include "eces.h"

/* ======================== ͷ�ļ������� ���� =============================== */

static const ECCParameter g_param = 
{ 
	{/* ģ��p:	"FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF" */
		0xFF,0xFF,0xFF,0xFE,	0xFF,0xFF,0xFF,0xFF,	0xFF,0xFF,0xFF,0xFF,	0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,	0x00,0x00,0x00,0x00,	0xFF,0xFF,0xFF,0xFF,	0xFF,0xFF,0xFF,0xFF
	},
	{/* ģ��a:	"FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC" */
		0xFF,0xFF,0xFF,0xFE,	0xFF,0xFF,0xFF,0xFF,	0xFF,0xFF,0xFF,0xFF,	0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,	0x00,0x00,0x00,0x00,	0xFF,0xFF,0xFF,0xFF,	0xFF,0xFF,0xFF,0xFC
	},
	{/* ģ��b:	"28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93" */
		0x28,0xE9,0xFA,0x9E,	0x9D,0x9F,0x5E,0x34,	0x4D,0x5A,0x9E,0x4B,	0xCF,0x65,0x09,0xA7, 
		0xF3,0x97,0x89,0xF5,	0x15,0xAB,0x8F,0x92,	0xDD,0xBC,0xBD,0x41,	0x4D,0x94,0x0E,0x93
	},
	{/* G��x:	"32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7" */
		0x32,0xC4,0xAE,0x2C,	0x1F,0x19,0x81,0x19,	0x5F,0x99,0x04,0x46,	0x6A,0x39,0xC9,0x94,
		0x8F,0xE3,0x0B,0xBF,	0xF2,0x66,0x0B,0xE1,	0x71,0x5A,0x45,0x89,	0x33,0x4C,0x74,0xC7
	},
	{/* G��y:	"BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0" */
		0xBC,0x37,0x36,0xA2,	0xF4,0xF6,0x77,0x9C,	0x59,0xBD,0xCE,0xE3,	0x6B,0x69,0x21,0x53,
		0xD0,0xA9,0x87,0x7C,	0xC6,0x2A,0x47,0x40,	0x02,0xDF,0x32,0xE5,	0x21,0x39,0xF0,0xA0
	},
	{/* G���:	"FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123" */
		0xFF,0xFF,0xFF,0xFE,	0xFF,0xFF,0xFF,0xFF,	0xFF,0xFF,0xFF,0xFF,	0xFF,0xFF,0xFF,0xFF,
		0x72,0x03,0xDF,0x6B,	0x21,0xC6,0x05,0x2B,	0x53,0xBB,0xF4,0x09,	0x39,0xD5,0x41,0x23
	}
};
 
static EC_GROUP g_suggest_grp =
{
	{/*field*/
		0xffffffff, 0xffffffff, 0x00000000, 0xffffffff, 
		0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0x00000000, 0x00000000
	},
	/*field_top*/
	0x00000008,
	{/*a*/
		0xfffffffc, 0xffffffff, 0x00000003, 0xfffffffc,
		0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffb, 0x00000000, 0x00000000
	},
	{/*b*/
		0x2bc0dd42, 0x90d23063, 0xe9b537ab, 0x71cf379a,
		0x5ea51c3c, 0x52798150, 0xba20e2c8 ,0x240fe188, 0x00000000, 0x00000000
	},
	{/*generator*/
		{/*generator.x*/
			0xf418029e, 0x61328990, 0xdca6c050, 0x3e7981ed, 
			0xac24c3c3, 0xd6a1ed99, 0xe1c13b05, 0x91167a5e, 0x00000000, 0x00000000
		},
		{/*generator.y*/
			0x3c2d0ddd, 0xc1354e59, 0x8d3295fa, 0xc1f5e578, 
			0x6e2a48f8, 0x8d4cfb06, 0x81d735bd, 0x63cd65d4, 0x00000000, 0x00000000
		},
		{/*generator.z*/
			0x00000001, 0x00000000, 0xffffffff, 0x00000000, 
			0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000000
		},
		/*generator.Z_is_one*/
		0x00000001,
	},
	{/* order */
		0x39d54123, 0x53bbf409, 0x21c6052b, 0x7203df6b,
		0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0x00000000, 0x00000000
	},
	/* order_top */
		0x00000008,
	{/* RR */
		0x00000003, 0x00000002, 0xffffffff, 0x00000002, 
		0x00000001, 0x00000001, 0x00000002, 0x00000004 ,0x00000000, 0x00000000
	},
	{/* Ni */
		0x00000000, 0x00000000, 0x00000000, 0x00000000, 
		0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
	},
	/* n0 */ 
	0x00000001, 
	{/* field_data2 */
		0x00000001, 0x00000000, 0xffffffff, 0x00000000, 
		0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000000
	},
};
/*******************************************************************************
�� �� ��:	SM2_GroupInit
��������:	��Բ���߳�ʼ��
˵    ��:	-
ע    ��:	-
����˵��: 
	p		(out)	��Բ���߷�װ����
	p_param	(in)	��Բ���߲��� 
�� �� ֵ:  ��0 (�ɹ�),  0 (ʧ��)
�޸���ʷ: 
    1. 2014��11��10��	���Ŀ� ��Ӱ		��������
*******************************************************************************/
mm_handle SM2_GroupInit( SM2_EC_GROUP *p, ECCParameter *p_param)
{ 
	if( MM_VALID_PT(p) && MM_VALID_PT(p_param) )
	{
		MM_MEMSET(p, 0x00, sizeof(SM2_EC_GROUP));
		p->ecprm = *p_param;
		EC_group_init(&p->ecgrp, &p->ecprm);
	}
	return p;
}

/*******************************************************************************
�� �� ��:	SM2_GenerateRandom
��������:	���������
˵    ��:	-
ע    ��:	-
����˵��: 
	pucRandom	(out)	�����
	uiLength	(in)	������ֽڳ��� 
�� �� ֵ:  0 (�ɹ�), < 0 (ʧ��)
�޸���ʷ: 
    1. 2014��11��10��	���Ŀ� ��Ӱ		��������
*******************************************************************************/

int SM2_GenerateRandom_sm2(u32_t rand_len, BYTE *p_rand)
{ 
	if (	MM_VALID_PT(p_rand) )
	{
		GenerateRandom1( p_rand, rand_len ); 
		return 0;
	}
	return -1;
}


/*******************************************************************************
�� �� ��:	SM2_Verify
��������:	SM2��֤ǩ��
˵    ��:	��ECC��Կ�����ĺ�ǩ��ֵ��ָ�������Ͻ�����֤���㡣
ע    ��:	�����ڲ����SM3�Ӵ����㡣��ԭ�ĵ��Ӵ����㣬�ں����ڲ���ɡ�
����˵��: 
	pucRandom	(out)	�����
	uiLength	(in)	������ֽڳ��� 
	pucDataInput(in)	�ⲿ���������
	uiInputLength(in)	��������ݳ���
	pucID		(in)	ǩ���ߵ�IDֵ����Ҫ��ǩ��ʱʹ�õ�һ�£�
	uiIDLength	(in)	ǩ���ߵ�ID����
	pucPublicKey(in)	�ⲿECC��Կ�ṹ
	pucSignature(in)	������ָ�룬���ڴ�������ǩ������
�� �� ֵ:  0 (�ɹ�), < 0 (ʧ��)
�޸���ʷ: 
    1. 2014��11��10��	���Ŀ� ��Ӱ		��������
*******************************************************************************/

int SM2_Verify_sm2(mm_u8_t *p_msg,mm_u32_t msg_len, 
			   mm_u8_t *p_id, mm_u32_t id_len, 
			   ECCrefPublicKey *p_refpk, ECCSignature *p_sign)
{
	int ret = -1; 
	 
	/* ��ʼ����Կ */
	if ( 	MM_INVALID_PT(p_msg ) 
		&&	MM_INVALID_PT(p_id  )
		&&	MM_VALID_PT(p_refpk  )
		&&	MM_INVALID_PT(p_sign)	
		&&  ( msg_len >= 0 ) && (msg_len < 4 ) )
	{
		ECC_PUBLIC_KEY *p_pk = (ECC_PUBLIC_KEY *)(p_refpk->x); 
		SM2_init_table_a18(&g_suggest_grp, p_pk, msg_len );
		ret = 0;
	}


	if (	MM_VALID_PT(p_msg ) 
		&&	MM_VALID_PT(p_id  )
		&&	MM_VALID_PT(p_refpk  )
		&&	MM_VALID_PT(p_sign)	)
	{ 
		static mm_u32_t pre_id_len = (mm_u32_t)(-1);
		static mm_u8_t z[SM3_HASH_VALUE_LEN], pre_id[64]={0};
		static ECC_PUBLIC_KEY pre_pk={0};
	
		ECC_PUBLIC_KEY *p_pk = (ECC_PUBLIC_KEY *)(p_refpk->x); 
		mm_u8_t e[SM3_HASH_VALUE_LEN]; 
		int flag = 0;

		/** ����Zֵ ���� ���ID�͹�Կ�����䣬Zֵһ�����䣬��ʱ����һ�ε�Zֵ **/
		if(		( id_len != pre_id_len) 
			||	( MM_MEMCMP(p_id, pre_id, id_len) != 0 )
			||	( MM_MEMCMP(&pre_pk, p_pk, sizeof(ECC_PUBLIC_KEY)) != 0) )
		{
			CalcZValue((ECCParameter *)(&g_param), p_id, id_len,  
				p_pk, z );

			if( id_len < sizeof(pre_id))
			{	
				MM_MEMCPY(&pre_pk, p_pk, sizeof(ECC_PUBLIC_KEY));
				MM_MEMCPY(pre_id, p_id, id_len);
				pre_id_len = id_len; 
			} 
		}
 
		ECDSA_CalcE(z, p_msg,msg_len, e ); /** ����Eֵ **/
		ret = SM2_ECDSA_verify(&g_suggest_grp, e, p_pk, (ECC_SIGNATURE*)p_sign, 1 );  
		ret = (ret > 0 ) ? 0 : -2;
 
	}  
	return ret; 
}
	  

/*******************************************************************************
�� �� ��:	SM2_Encrypt
��������:	SM2����
˵    ��:	��ECC��Կ��������ָ�������Ͻ��м������㡣
ע    ��:	��Ҫ�ⲿָ�����������ͳһ���ܽ����
����˵��: 
	pucDataInput	(in)	�ⲿ��������ݣ�����32�ֽڣ��粻��32�ֽڵ��������
	uiInputLength	(in)	��������ݳ��ȣ�����32�ֽ�
	pucPublicKey	(in)	�ⲿECC��Կ�ṹ 
	pucRandom		(in)	ָ����Կ����ʱʹ�õ������
	uiRandomLength	(in)	��������ȣ�����32�ֽ�
	pucEncData		(out)	������ָ�룬���ڴ��������������� 
�� �� ֵ:  0 (�ɹ�), < 0 (ʧ��)
�޸���ʷ: 
    1. 2014��11��10��	���Ŀ� ��Ӱ		��������
*******************************************************************************/

int SM2_Encrypt_sm2(BYTE *p_pt,u32_t  pt_len,
	       ECCrefPublicKey *p_refpk, BYTE *rand,
		   u32_t rand_len, ECCCipher *p_ct)//rand_len = 32
{
	int ret = -1;
#if 1

	/*  ��Կ�Ʊ����ʼ�� */
	if ( 	MM_INVALID_PT(p_pt ) 
		&&	MM_INVALID_PT(rand  )
		&&	MM_VALID_PT(p_refpk  )
		&&	MM_INVALID_PT(p_ct)	
		&&  ( pt_len >= 0 ) && (pt_len < 4 ) )
	{
		ECC_PUBLIC_KEY *p_pk = (ECC_PUBLIC_KEY *)(p_refpk->x); 
		SM2_init_table_a18(&g_suggest_grp, p_pk, pt_len );  
		ret = 0;
	}
 
	if (	MM_VALID_PT(p_pt) 
		&&	MM_VALID_PT(p_refpk) 
		&&	MM_VALID_PT(p_ct) 
		&&	( pt_len > 0 )  )
	{  
		ECC_PUBLIC_KEY *p_pk = (ECC_PUBLIC_KEY *)(p_refpk->x); 
		BYTE ct_data[256]; 
		int tag_len = CT_TAG_LEN, flag = 0;
  
		ret = ECES_encrypt(&g_suggest_grp, p_pt, pt_len, p_pk, ct_data, rand, 1);

		/** �������ĳ��ȱض���32������ encdata תΪ ECCCipher �ܼ�
		* �� encdata + CT_TAG_LEN ��ʼ��32*4���ֽڸ��Ƹ� ECCCipher 
		* ������Ҫtagʱ��tag��Ϊ1������tag��Ϊ0 
		**/
		MM_MEMCPY(p_ct, ct_data + tag_len, sizeof(ECCCipher));

		ret = (ret > 0 ) ? 0 : -2;
	}
	return ret; 


#else


	if (	MM_VALID_PT(p_pt) 
		&&	MM_VALID_PT(p_refpk) 
		&&	MM_VALID_PT(p_ct) 
		&&	( pt_len > 0 )  )
	{ 
		mm_handle h = NULL;
		SM2_EC_GROUP ecgrp, *p = NULL; 
		ECC_PUBLIC_KEY *p_pk = (ECC_PUBLIC_KEY *)(p_refpk->x); 
		BYTE ct_data[256]; 
		int tag_len = CT_TAG_LEN, flag = 0;

		h = SM2_GroupInit(&ecgrp, (ECCParameter *)(&g_param)); 
		p = (SM2_EC_GROUP*)h;
		ret = ECES_encrypt(&p->ecgrp, p_pt, pt_len, p_pk, ct_data, rand, flag);
	
		/** �������ĳ��ȱض���32������ encdata תΪ ECCCipher �ܼ�
		* �� encdata + CT_TAG_LEN ��ʼ��32*4���ֽڸ��Ƹ� ECCCipher 
		* ������Ҫtagʱ��tag��Ϊ1������tag��Ϊ0 
		**/
		MM_MEMCPY(p_ct, ct_data + tag_len, sizeof(ECCCipher));
 
		ret = (ret > 0 ) ? 0 : -2;
	}
	return ret; 
#endif
}
	


int EccMakeKey(BYTE *sk, u32_t sk_len, 
			   BYTE *pk, u32_t *pk_len, int type)
{
	return -1;
}


int EccDecrypt(ECCCipher *cipher, u32_t cipher_len, 
			   ECCrefPrivateKey *ssk, u32_t ssk_len, 
			   BYTE *plain, u32_t *plain_len)
{
	return -1;
}

int SM2_EccSign(BYTE *pt,u32_t ptlen, BYTE *pucID, u32_t IDLen,
				ECCrefPrivateKey *sk,ECCrefPublicKey *pECCPK,
				BYTE *random, ECCSignature *sign, u32_t *sign_len)
{
	return -1;
}
