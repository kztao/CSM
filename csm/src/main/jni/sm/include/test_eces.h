#ifndef _ECES_Test_H
#define _ECES_Test_H
//#include "test_sm2_vector.h"




/** SM2 test vector Fp-256	以下数据直接使用文档提供数据，采用大端表示  **/

/** 输入参数 **/

/**	素数p  **/
static   char g_eces_ec_p[ ] = "8542D69E 4C044F18 E8B92435 BF6FF7DE 45728391 5C45517D 722EDB8B 08F1DFC3"; 

/**	系数a  **/
static   char g_eces_ec_a[ ] = "787968B4 FA32C3FD 2417842E 73BBFEFF 2F3C848B 6831D7E0 EC65228B 3937E498";

/**	系数b  **/
static   char g_eces_ec_b[ ] = "63E4C6D3 B23B0C84 9CF84241 484BFE48 F61D59A5 B16BA06E 6E12D1DA 27C5249A";

/** 	坐标xG  **/
static   char g_eces_ec_gx[] = "421DEBD6 1B62EAB6 746434EB C3CC315E 32220B3B ADD50BDC 4C4E6C14 7FEDD43D"; 

/** 	坐标yG  **/
static   char g_eces_ec_gy[] = "0680512B CBB42C07 D47349D2 153B70C4 E5D7FDFC BFA36EA1 A85841B9 E46E09A2"; 

/** 	阶n  **/
static   char g_eces_ec_gn[] = "8542D69E 4C044F18 E8B92435 BF6FF7DD 29772063 0485628D 5AE74EE7 C32E79B7";  

/** 待加密的消息M："encryption standard", 十六进制表示： 656E63 72797074 696F6E20 7374616E 64617264 **/
/** 注意 消息只有19个字节  **/
static   char g_eces_msg[]	 = "656E63 72797074 696F6E20 7374616E 64617264";   
static   int  g_eces_msg_len = 19;  

/** 私钥dB： **/
static   char g_eces_sk[]	 = "1649AB77 A00637BD 5E2EFE28 3FBF3535 34AA7F7C B89463F2 08DDBC29 20BB0DA0";

/** 公钥PB=(xB,yB)： **/
/** 坐标xB： **/
static   char g_eces_pkx[]	 = "435B39CC A8F3B508 C1488AFC 67BE491A 0F7BA07E 581A0E48 49A5CF70 628A7E0A";

/** 坐标yB： **/
static   char g_eces_pky[]	 = "75DDBA78 F15FEECB 4C7895E2 C1CDF5FE 01DEBB2C DBADF453 99CCF77B BA076A42";

/** 随机数k： **/
static   char g_eces_rand_k[]= "4C62EEFD 6ECFC2B9 5B92FD6C 3D957514 8AFA1742 5546D490 18E5388D 49DD7B4F";
	
/**
//计算中间值和结果

// 计算椭圆曲线点C1=[k]G=(x1,y1)：
// 坐标x1和坐标y1如下。
//注意：在此C1选用未压缩的表示形式，点转换成字节串的形式为PC || x1 || y1，其中PC为单一字节且PC=04，仍记为C1。
**/
static   char g_eces_c1x[]	= "245C26FB 68B1DDDD B12C4B6B F9F2B6D5 FE60A383 B0D18D1C 4144ABF1 7F6252E7";
static   char g_eces_c1y[]	= "76CB9264 C2A7E88E 52B19903 FDC47378 F605E368 11F5C074 23A24B84 400F01B8";

/** 计算C2=M⊕t：19个字节   **/
static   char g_eces_c2[]	= "650053 A89B41C4 18B0C3AA D00D886C 00286467"; 

/** HASH结果C3  **/
static   char g_eces_c3[]	= "9C3D7360 C30156FA B7C80A02 76712DA9 D8094A63 4B766D3A 285E0748 0653426D"; 

/**
// 输出密文C = C1∥C2∥C3：
// 04245C26 FB68B1DD DDB12C4B 6BF9F2B6 D5FE60A3 83B0D18D 1C4144AB F17F6252
// E776CB92 64C2A7E8 8E52B199 03FDC473 78F605E3 6811F5C0 7423A24B 84400F01
// B8650053 A89B41C4 18B0C3AA D00D886C 00286467 9C3D7360 C30156FA B7C80A02
// 76712DA9 D8094A63 4B766D3A 285E0748 0653426D	
// 注意：首个字节0x04是点的特殊标志符，验证时可能不需要
**/
static   char g_eces_c[]	= "04245C26 FB68B1DD DDB12C4B 6BF9F2B6 D5FE60A3 83B0D18D 1C4144AB F17F6252"
							  "E776CB92 64C2A7E8 8E52B199 03FDC473 78F605E3 6811F5C0 7423A24B 84400F01"
							  "B8650053 A89B41C4 18B0C3AA D00D886C 00286467 9C3D7360 C30156FA B7C80A02"
							  "76712DA9 D8094A63 4B766D3A 285E0748 0653426D"; 
static   int  g_eces_c_len	= 116;

								
//SM2 test vector Fp-256 end
//////////////////////////////////////////////////////////////////////////
								
int ECES_Test_enc_jcdz_example( );
int ECES_Test(int test_flag);
int ECES_Test_Speed(int test_flag);

#endif 