#ifndef _TEST_VECTOR_WDT_H
#define _TEST_VECTOR_WDT_H

#define	NO_TEST				0	/* 不测试 */
#define	USE_STANDARD_DATA	1	/* 使用标准数据测试， 即 g_sm2_standard_ec_p 那套*/
#define	USE_SUGGEST_DATA	2	/* 使用推荐数据测试， 即 g_sm2_suggest_ec_p  那套*/
#define	TEST_STABILITY		3	/* 使用标准数据进行稳定性测试 */


//#define TEST_JCDZ		/* 测试积成电子接口，测试接口为 随机数生成、验证签名和加密*/
#undef TEST_JCDZ

/**
//////////// 曲线参数
// SM2椭圆曲线公钥密码算法推荐曲线参数
// 推荐使用素数域256位椭圆曲线。
// 椭圆曲线方程：y2 = x3 + ax + b。
// 曲线参数：suggest
**/
static char g_sm2_suggest_ec_p[]	= "FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF";
static char g_sm2_suggest_ec_a[]	= "FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC";
static char g_sm2_suggest_ec_b[]	= "28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93";
static char g_sm2_suggest_ec_gn[]	= "FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123";
static char g_sm2_suggest_ec_gx[]	= "32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7";
static char g_sm2_suggest_ec_gy[]	= "BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0";



/** 测试数据来至标准文档 **/
static char g_sm2_standard_ec_p[ ]	= "8542D69E 4C044F18 E8B92435 BF6FF7DE 45728391 5C45517D 722EDB8B 08F1DFC3"; 
static char g_sm2_standard_ec_a[ ]	= "787968B4 FA32C3FD 2417842E 73BBFEFF 2F3C848B 6831D7E0 EC65228B 3937E498";
static char g_sm2_standard_ec_b[ ]	= "63E4C6D3 B23B0C84 9CF84241 484BFE48 F61D59A5 B16BA06E 6E12D1DA 27C5249A";
static char g_sm2_standard_ec_gx[]	= "421DEBD6 1B62EAB6 746434EB C3CC315E 32220B3B ADD50BDC 4C4E6C14 7FEDD43D"; 
static char g_sm2_standard_ec_gy[]	= "0680512B CBB42C07 D47349D2 153B70C4 E5D7FDFC BFA36EA1 A85841B9 E46E09A2"; 
static char g_sm2_standard_ec_gn[]	= "8542D69E 4C044F18 E8B92435 BF6FF7DD 29772063 0485628D 5AE74EE7 C32E79B7"; 

#endif