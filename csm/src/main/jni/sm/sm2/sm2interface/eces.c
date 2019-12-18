#include "mm_basic_fun.h"
#include "eces.h"
#include "ec.h"
#include "ec_lcl.h" 
#include "ec_general.h"
#include "sm2.h"
#include "sm3_core.h"
#include "kdf.h" 
#include "mm_sm_cfg.h"

/**
// //ECC����ֵ�ṹ
// typedef struct EncDataFmt_st
// {  
// 	BYTE tag;//04 
// 	BYTE c1[ECC_BLOCK_LEN*2];
//  BYTE c2[0];//C2����Ϊ���ĳ���
//  BYTE C3[SM3_HASH_VALUE_LEN];//C2���������C3, C3����Ϊ SM3_HASH_VALUE_LEN
// }EncDataFmt;
**/

/*�������л�ȡ�����Ϣ*/

#ifdef MM_SM2_CIPHPER_HAS_TAG
#define CIPHER_TAG_LEN	1	/*   ��TAG����� */
#else
#define CIPHER_TAG_LEN	0	/* û��TAG����� */
#endif

#define GET_TAG_FRM_CIPHER(p_cipher)	(p_cipher)
#define GET_C1_FRM_CIPHER(p_cipher)		((p_cipher)+CIPHER_TAG_LEN)
#define GET_C3_FRM_CIPHER(p_cipher)		(GET_C1_FRM_CIPHER(p_cipher) + ECC_BLOCK_LEN*2)
#define GET_C2_FRM_CIPHER(p_cipher)     (GET_C3_FRM_CIPHER(p_cipher) + ECC_BLOCK_LEN)
 
#if 0
void error_log(void *p1, int len1, void *p2, int len2 )
{
	static int err_counter = 0;//debug
	int i;
	char name[256];
	FILE *fp = NULL;
	sprintf(name, "d:\\zdbg\\enc_%04d.txt", err_counter++);
	fp = fopen(name, "wt");

	for (i = 0; i<len1;i++)
	{
		if(i%32 == 0)fprintf(fp, "\n");
		if(i%4 == 0)fprintf(fp, " "); 
		fprintf(fp, "%02x", ((mm_u8_t*)p1)[i]);
	}

	fprintf(fp, "\n@@@@@@@@\n");
	for (i = 0; i<len2;i++)
	{
		if(i%32 == 0)fprintf(fp, "\n");
		if(i%4 == 0)fprintf(fp, " "); 
		fprintf(fp, "%02x", ((mm_u8_t*)p2)[i]);
	}
	 
	fclose(fp);
}
#endif

/**
//	��������:  ������hΪ 1						       //
//      ECES��������(p��)                  //
//	��������:						       //
//      group:in,���߲���                  //
//		plain:in,����					       //
//		p_pk:in,ECC��Կ
//   int plain_len  ���ĳ���	               //							
//		���ܽ��
//  ECC_ENCRYPTION *p_enc_res   ����ֵ
//    BYTE *c1, ������32+32
//     BYTE *c2, �����ĵȳ�
//      BYTE *c3  ���Ӵ��㷨����ȳ����˴�ѡ��32

//
//	��������:							   //
//		0, 1       						   //
**/
//result_len	= ECC_BLOCK_LEN * 2 + 1 + SM3_HASH_VALUE_LEN + plain_len
//				= plain_len + 97
 

/*
�����㷨
���룺	M ����Ϣ��
		klen ��ϢM�ı��س��� 
�����	C�����ģ�
���裺
A1������������������������k��[1,n-1]��
A2�������C1=[k]G=(x1,y1)����C1ת��Ϊ���ش���
A3�������S=[h]PB����S������Զ�㣬�򱨴��˳���
A4�������[k]PB=(x2,y2)��������x2��y2 ת��Ϊ���ش���
A5������t=KDF(x2 �� y2, klen)����tΪȫ0���ش����򷵻�A1��
A6������C2 = M �� t��
A7������C3 = Hash(x2 �� M �� y2)��
A8���������C = C1 �� C2 �� C3��
*/

/* �౶��ļ���������·�ʽ��
	(1) ������ MM_SM2_USE_ALG18_TABLE, �����ALG18�㷨
	(2) δ���� MM_SM2_USE_ALG18_TABLE, �����ԭ�����㷨��������WNAF��ALG16
	flag = 1��ʾʹ��ALG18�㷨��flag = 0��ʾ��ʹ��ALG18�㷨 
*/
 
int ECES_encrypt(EC_GROUP *group, BYTE *plain, int plain_len, ECC_PUBLIC_KEY *p_pk, 	
					BYTE *enc_data, BYTE rand_num[ECC_BLOCK_LEN], int flag )
{
	  
	int ret, fail_time = 0, table_id;
	EC_POINT R, Q;
	BIGNUM x1, y1, x2, y2;
	BIGNUM k={ /** tmp debug �̶���kֵ  **/
		0x3736A2F4, 0xF6779C59, 0xBDCEE36B, 0x692153D0, 
		0xA9877CC6,	0x2A474002,	0xDF32E521,	0x39F0A0BC, 0x0, 0x0};
	mm_sm3_ctx x;
	BYTE kdf_in[ECC_BLOCK_LEN*2], x2_byte[ECC_BLOCK_LEN], y2_byte[ECC_BLOCK_LEN];
	BYTE *p = NULL, *kdf_out = NULL, kdf_out0[64]; 
 


	kdf_out = ( plain_len < sizeof(kdf_out0) ) ? kdf_out0 : (BYTE*)MM_MALLOC(plain_len);
	if( kdf_out == NULL )
	{
		return -2;
	}

#ifdef MM_SM2_CIPHPER_HAS_TAG
	p = GET_TAG_FRM_CIPHER(enc_data);
	*p = 0x04;/*δѹ����������ʶ��*/ 
#endif

	/** ��ʼ����Կ **/
	EC_load_pt(&Q, p_pk);
	
	EcPointMapToMontgomery(&Q, group);
    Q.Z_is_one = 1;//luoying add
	table_id = ec_load_tables_a18(group, &Q);

again:
	/** A1������������������������k��[1,n-1]�� **/
	if( (rand_num != NULL ) && (fail_time > 0 ) )
	{
		MM_FREE(kdf_out);
		return -3;/** �ⲿ���������ʱ����������쳣��ֱ���˳� **/
	}

//    SM2_BN_load_bn(&k, rand_num);  
	if( rand_num != NULL ) 
	{
		SM2_BN_load_bn(&k, rand_num); 	 
	}
	else
	{	/** tmp debug �̶���kֵ **/
		//SM2_BN_init(&k); 
		//GenerateRandom1((BYTE*)k.d, ECC_BLOCK_LEN);/** tmp debug �̶���kֵ **/
		SM2_BN_init(&k); 
		GenerateRandom1((BYTE*)k.d, ECC_BLOCK_LEN);
		if( (flag) && (table_id >= 0 )) /** ���� MM_SM2_USE_ALG18_TABLE ʱ, ��ALG18��������� **/
		{
			ec_trim_rand_a18(&k);/**  ��ALG18��������� **/
		} 
		else
		{
			ec_trim_rand(&k);	/**  �� SM2_EC_POINTs_mul ���������  **/
		}		 
	}

	if( SM2_BN_is_zero(k.d, ECC_BLOCK_LEN_DWORD) )
	{
		fail_time++;
		goto again;
	}		 
 
	if ( SM2_BN_ucmp(k.d, ECC_BLOCK_LEN_DWORD, group->order.d, ECC_BLOCK_LEN_DWORD) > 0 )/** ��ֹk̫�� **/
	{
		fail_time++;
		goto again;
	}	
		
	/** A2�������C1=[k]G=(x1,y1)����C1ת��Ϊ���ش��� **/
 
 
//	if( ( flag ) ) 
	if( 0 ) 
	{/* ʹ�ò��������ǩ������ʹ��ALG18�㷨����౶�� */
		ec_GFp_pt_mul_a18(group, &R, &group->generator, &k, POINT_IS_GENERATOR); 
	} 
	else
	{
		SM2_EC_POINTs_mul(group, &R, &group->generator, &k, NULL, NULL); 
	}

	ret = ec_GFp_get_aff_coords(group, &R, &x1, &y1); 
	if(ret<0)
	{
		fail_time++;
		goto again;
		//error_log(&k, sizeof(BIGNUM), &R, sizeof(EC_POINT) ); 
	}


	PrintData(&x1, 32,		"x1:  ", 0);
	PrintData(&y1, 32,		"y1:  ", 0); 
	
	/** ��C1ת��Ϊ���ش���C1=[k]G=(x1,y1)��  **/
	p = GET_C1_FRM_CIPHER(enc_data);
	SM2_BN_store_bn(&x1, p);
	SM2_BN_store_bn(&y1, p + ECC_BLOCK_LEN);

	/** A3�������S=[h]PB����S������Զ�㣬�򱨴��˳��� **/
	/** �������õĲ����� h = 1,����A3������Ժ��� **/

	/** A4�������[k]PB=(x2,y2)��������x2��y2 ת��Ϊ���ش��� **/

	ret = 0;
	if( ( flag ) && (table_id >= 0 ) )
	{/* ʹ�ò��������ǩ������ʹ��ALG18�㷨����౶�� */
		ec_GFp_pt_mul_a18(group, &R, &Q, &k, POINT_IS_PUBLIC_KEY); 
		ret = 1;
	}
	if( !ret )
	{
		SM2_EC_POINTs_mul(group, &R, &Q, &k, NULL, NULL); 
	}  

	ret = ec_GFp_get_aff_coords(group, &R, &x2, &y2); 
	if(ret<0)
	{
		fail_time++;
		goto again;
		//error_log(&k, sizeof(BIGNUM), &R, sizeof(EC_POINT) ); 
	}
	PrintData(&x2, 32,		"x2:  ", 0);
	PrintData(&y2, 32,		"y2:  ", 0);  
	
	/** A5������t=KDF(x2 �� y2, klen)����tΪȫ0���ش����򷵻�A1�� **/
	SM2_BN_store_bn(&x2, kdf_in + 0);
	SM2_BN_store_bn(&y2, kdf_in + ECC_BLOCK_LEN);  
	kdf(kdf_in, ECC_BLOCK_LEN*2, plain_len, kdf_out);	 
	if(  data_is_zero( kdf_out, plain_len)  )
	{
		fail_time++;
		goto again;
	}

	/** A6������C2 = M XOR t�� **/
	p = GET_C2_FRM_CIPHER(enc_data); 
	data_xor(p, plain, kdf_out, plain_len);	

	/** A7������C3 = Hash(x2 || M || y2)�� **/
	SM2_BN_store_bn(&x2, x2_byte);
	SM2_BN_store_bn(&y2, y2_byte);
	p = GET_C3_FRM_CIPHER(enc_data);
	

	sm3_init_core(   &x);
	sm3_process_core(&x, x2_byte,	ECC_BLOCK_LEN);
	sm3_process_core(&x, plain,		plain_len);	 
	sm3_process_core(&x, y2_byte,	ECC_BLOCK_LEN);	
	sm3_unit_core(   &x, p);  //p=&C3[0]



//	MM_FREE(kdf_out); //20150528 luoying del
	if( kdf_out != kdf_out0 )//20150528 luoying add
	{
		MM_FREE(kdf_out); 
	}

	/** A8���������C = C1 || C3 || C2 **/
	/** �� p_fmt **/
	return 1;
}

/**
//	��������:							   //
//      ECES��������(p��)                  //
//	��������:							   //
//      group:in,���߲���                  //
//		BYTE *c1, BYTE *c2,BYTE *c3,����ֵ	           //
//         ECCParameter   eccpa ���߲����������ж�C1�Ƿ��������ϡ�
//  ECC_ENCRYPTION *pEncryption,
//    BYTE *c1, ������32+32 ��
//     BYTE *c2, �����ĵȳ�
//      c2_len C2�ĳ���
//      BYTE *c3  ���Ӵ��㷨����ȳ����˴�ѡ��32
//		pECCSK:in,ECC˽Կ                  //							
//		msg:out,����				           //
//	��������:							   //
//		0 ���ɹ���
//      1  �ɹ�     					   //
**/

/*
�����㷨
���룺	C�����ģ�C=C1 �� C2 �� C3��
		klen��������C2�ı��س��ȣ�
���裺
B1����C��ȡ�����ش�C1����C1ת��Ϊ�㣬��֤C1�Ƿ��������߷��̣����������򱨴��˳���
B2��������Բ���ߵ�S=[h]C1����S������Զ�㣬�򱨴��˳���
B3������[dB]C1=(x2,y2)��������x2��y2ת��Ϊ���ش���
B4������t=KDF(x2 �� y2, klen)����tΪȫ0���ش����򱨴��˳���
B5����C��ȡ�����ش�C2������M�� = C2 �� t��
B6������u = Hash(x2 �� M�� �� y2)����C��ȡ�����ش�C3����u .= C3���򱨴��˳���
B7���������M�䡣
*/

// enc_data_len	= ECC_BLOCK_LEN * 2 + 1 + SM3_HASH_VALUE_LEN + plain_len = plain_len + 97
// msg_len = enc_data_len - 97
int  ECES_decrypt(EC_GROUP *group, BYTE *enc_data, int enc_data_len,
					 ECC_PRIVATE_KEY *pECCSK, BYTE *msg, 
					 ECCParameter *pECCPara)
{ 
	const int pad_len = ECC_BLOCK_LEN * 2 + CIPHER_TAG_LEN + SM3_HASH_VALUE_LEN; 
	int c2_len = enc_data_len - pad_len,  ret = 0;
	EC_POINT pt_r, pt_q;
	BIGNUM sm2_bn_x2,  sm2_bn_y2, sm2_bn_sk; 
	BYTE  *p = NULL, *p_c2_kdf = NULL, x2_y2[ECC_BLOCK_LEN*2], u[ECC_BLOCK_LEN];
	ECC_PUBLIC_KEY pt_c1;   
	mm_sm3_ctx x; 
	BYTE c2_kdf0[256+16];//20150528 luoying add

	/** 0. �������� **/
	//20150528 luoying change from
// 	if((p_c2_kdf =(BYTE*)MM_MALLOC(c2_len)) == NULL)
// 	{
// 		ret = -2;//_err_sm2_new_mem_failture; 
// 		goto _err_ECES_Decryption;
// 	}
	//20150528 luoying change to	
	p_c2_kdf =( c2_len < sizeof(c2_kdf0) ) ? c2_kdf0 : (BYTE*)MM_MALLOC(c2_len);
	if( p_c2_kdf == NULL)
	{
		ret = -2;//_err_sm2_new_mem_failture; 
		goto _err_ECES_Decryption;
	}
	//20150528 luoying change end


#ifdef MM_SM2_CIPHPER_HAS_TAG
	/** B1����C��ȡ�����ش�C1����C1ת��Ϊ�㣬��֤C1�Ƿ��������߷��̣����������򱨴��˳��� **/
	p = GET_TAG_FRM_CIPHER(enc_data);
	if ( *p != 0x04 )/** ��������ʾ **/
	{
		ret = -3;//_err_sm2_c1_tag_error;
		goto _err_ECES_Decryption;
	}
#else /*#ifdef CIPHER_HAS_NOT_TAG*/
	/** ��ʱ�����tag  **/
#endif

	p = GET_C1_FRM_CIPHER(enc_data);
	MM_MEMCPY(pt_c1.Qx, p, ECC_BLOCK_LEN);	  
	MM_MEMCPY(pt_c1.Qy, p+ECC_BLOCK_LEN, ECC_BLOCK_LEN); 

	if(		( MM_VALID_PT(pECCPara) )/* ���߲�����Ч��ʱ��ż�� */
		&&	( !EC_point_is_on_curve(pECCPara, &pt_c1) ) )
	{
		ret = -4;//_err_sm2_point_not_on_curve;
		goto _err_ECES_Decryption;
	} 
 
	/** B2��������Բ���ߵ�S=[h]C1����S������Զ�㣬�򱨴��˳��� 
	* ��,��Ϊѡȡ��h = 1
	**/
	 
	/** B3������[dB]C1=(x2,y2)��������x2��y2ת��Ϊ���ش��� **/
	/**  3.1 ��ʼ��˽Կ **/
	SM2_BN_load_bn(&sm2_bn_sk, pECCSK->Ka); 

	p = GET_C1_FRM_CIPHER(enc_data);
	EC_POINT_init(&pt_q); 
	SM2_BN_load_bn(&pt_q.X, p );
	SM2_BN_load_bn(&pt_q.Y, p + ECC_BLOCK_LEN ); 
	EcPointMapToMontgomery(&pt_q, group);
	pt_q.Z_is_one=1;	
	   
	/**  3.2 ����(x2,y2 )=[dB]C1 **/
	SM2_EC_POINTs_mul(group, &pt_r, &pt_q, &sm2_bn_sk, NULL,NULL); 
	ec_GFp_get_aff_coords(group, &pt_r, &sm2_bn_x2, &sm2_bn_y2);
	PrintData(&sm2_bn_x2, 32, "[dec] x2:", 0);
	PrintData(&sm2_bn_y2, 32, "[dec] y2:", 0);   
	
	/** B4������t=KDF(x2 �� y2, klen)����tΪȫ0���ش����򱨴��˳��� **/ 
	// 4.1	t = KDF(x2||y2, klen) 
	SM2_BN_store_bn(&sm2_bn_x2, x2_y2);
	SM2_BN_store_bn(&sm2_bn_y2, x2_y2+ECC_BLOCK_LEN);  
	kdf(x2_y2,ECC_BLOCK_LEN*2, c2_len, p_c2_kdf);
	PrintData(p_c2_kdf, c2_len, "[dec] kdf:", 0); 

	if ( data_is_zero(p_c2_kdf, c2_len) )/** ��tΪȫ0���ش����򱨴��˳��� **/
	{
		ret = -5;//_err_sm2_kdf_output_is_zero;
		goto _err_ECES_Decryption;
	}
		
	/** B5����C��ȡ�����ش�C2������M�� = C2 �� t�� **/
	p = GET_C2_FRM_CIPHER(enc_data);
	data_xor(msg, p, p_c2_kdf, c2_len);
	PrintData(msg, c2_len, "[dec] msg:", 0);   
			    
	/** B6������u = Hash(x2 �� M�� �� y2)����C��ȡ�����ش�C3����u != C3���򱨴��˳��� **/
	sm3_init_core( &x );
	sm3_process_core(&x, x2_y2, ECC_BLOCK_LEN);
	sm3_process_core(&x, msg, c2_len); 
	sm3_process_core(&x, x2_y2+ECC_BLOCK_LEN, ECC_BLOCK_LEN);
	sm3_unit_core( &x, u); 
	PrintData(u, 32, "[dec] hash_out:", 0);   

	p = GET_C3_FRM_CIPHER(enc_data);
	if(MM_MEMCMP(u, p, ECC_BLOCK_LEN) != 0 )/** ��u != C3���򱨴��˳��� **/
	{
		ret = -6;//_err_sm2_hash_output_not_match;
		goto _err_ECES_Decryption;
	}
		   
	ret = 1;

	/** B7���������M�� ( B5������� ) **/
	
_err_ECES_Decryption:	
//	MM_FREE(p_c2_kdf);			//20150528 luoying del
	if( p_c2_kdf != c2_kdf0 )	//20150528 luoying add
	{
		MM_FREE(p_c2_kdf);
	}

	return ret;
} 


