#ifndef _TEST_VECTOR_WDT_H
#define _TEST_VECTOR_WDT_H

#define	NO_TEST				0	/* ������ */
#define	USE_STANDARD_DATA	1	/* ʹ�ñ�׼���ݲ��ԣ� �� g_sm2_standard_ec_p ����*/
#define	USE_SUGGEST_DATA	2	/* ʹ���Ƽ����ݲ��ԣ� �� g_sm2_suggest_ec_p  ����*/
#define	TEST_STABILITY		3	/* ʹ�ñ�׼���ݽ����ȶ��Բ��� */


//#define TEST_JCDZ		/* ���Ի��ɵ��ӽӿڣ����Խӿ�Ϊ ��������ɡ���֤ǩ���ͼ���*/
#undef TEST_JCDZ

/**
//////////// ���߲���
// SM2��Բ���߹�Կ�����㷨�Ƽ����߲���
// �Ƽ�ʹ��������256λ��Բ���ߡ�
// ��Բ���߷��̣�y2 = x3 + ax + b��
// ���߲�����suggest
**/
static char g_sm2_suggest_ec_p[]	= "FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF";
static char g_sm2_suggest_ec_a[]	= "FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC";
static char g_sm2_suggest_ec_b[]	= "28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93";
static char g_sm2_suggest_ec_gn[]	= "FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123";
static char g_sm2_suggest_ec_gx[]	= "32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7";
static char g_sm2_suggest_ec_gy[]	= "BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0";



/** ��������������׼�ĵ� **/
static char g_sm2_standard_ec_p[ ]	= "8542D69E 4C044F18 E8B92435 BF6FF7DE 45728391 5C45517D 722EDB8B 08F1DFC3"; 
static char g_sm2_standard_ec_a[ ]	= "787968B4 FA32C3FD 2417842E 73BBFEFF 2F3C848B 6831D7E0 EC65228B 3937E498";
static char g_sm2_standard_ec_b[ ]	= "63E4C6D3 B23B0C84 9CF84241 484BFE48 F61D59A5 B16BA06E 6E12D1DA 27C5249A";
static char g_sm2_standard_ec_gx[]	= "421DEBD6 1B62EAB6 746434EB C3CC315E 32220B3B ADD50BDC 4C4E6C14 7FEDD43D"; 
static char g_sm2_standard_ec_gy[]	= "0680512B CBB42C07 D47349D2 153B70C4 E5D7FDFC BFA36EA1 A85841B9 E46E09A2"; 
static char g_sm2_standard_ec_gn[]	= "8542D69E 4C044F18 E8B92435 BF6FF7DD 29772063 0485628D 5AE74EE7 C32E79B7"; 

#endif