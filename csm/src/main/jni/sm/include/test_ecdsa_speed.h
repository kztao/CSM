#ifndef _ECDSA_SPEED_Test_H
#define _ECDSA_SPEED_Test_H 
#include "timers.h"
//#include "test_sm2_vector.h"
// 
// //测试数据来至标准文档
// 
// //	素数p 
// static char g_ecdsa_ec_p[ ]	= "8542D69E 4C044F18 E8B92435 BF6FF7DE 45728391 5C45517D 722EDB8B 08F1DFC3"; 
// //	系数a 
// static char g_ecdsa_ec_a[ ] = "787968B4 FA32C3FD 2417842E 73BBFEFF 2F3C848B 6831D7E0 EC65228B 3937E498";
// //	系数b 
// static char g_ecdsa_ec_b[ ] = "63E4C6D3 B23B0C84 9CF84241 484BFE48 F61D59A5 B16BA06E 6E12D1DA 27C5249A";
// // 	坐标xG 
// static char g_ecdsa_ec_gx[] = "421DEBD6 1B62EAB6 746434EB C3CC315E 32220B3B ADD50BDC 4C4E6C14 7FEDD43D"; 
// // 	坐标yG 
// static char g_ecdsa_ec_gy[] = "0680512B CBB42C07 D47349D2 153B70C4 E5D7FDFC BFA36EA1 A85841B9 E46E09A2"; 
// // 	阶n 
// static char g_ecdsa_ec_gn[] = "8542D69E 4C044F18 E8B92435 BF6FF7DD 29772063 0485628D 5AE74EE7 C32E79B7"; 
// 
// 
// // 	A私钥dA 
// static char g_ecdsa_sk[ ] = "128B2FA8 BD433C6C 068C8D80 3DFF7979 2A519A55 171B1B65 0C23661D 15897263"; 
// // 	A的公钥PA = (xA,yA)：
// // 	坐标xA 
// static char g_ecdsa_pkx[] = "0AE4C779 8AA0F119 471BEE11 825BE462 02BB79E2 A5844495 E97C04FF 4DF2548A"; 
// // 	坐标yA 
// static char g_ecdsa_pky[] = "7C0240F8 8F1CD4E1 6352A73C 17B7F16F 07353E53 A176D684 A9FE0C6B B798E857"; 
// 
// //待签名的消息M："message digest"
// static char g_ecdsa_msg[]	= "6D657373 61676520 64696765 7374"; 
// static int  g_ecdsa_msg_len	= 14;  
// 
// //	A的身份是：ALICE123@YAHOO.COM。用ASCII编码记IDA: 
// static char g_ecdsa_id[]	= "414C 49434531 32334059 41484F4F 2E434F4D"; 
// static int  g_ecdsa_id_len	= 18;
// static char g_ecdsa_entla[]	= "0090";
// 
// // 杂凑值ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
// static char g_ecdsa_valuez[]= "F4A38489 E32B45B6 F876E3AC 2168CA39 2362DC8F 23459C1D 1146FC3D BFB7BC9A"; 
// //杂凑函数值e=H256(ZA || M)：
// static char g_ecdsa_e[]		= "B524F552 CD82B8B0 28476E00 5C377FB1 9A87E6FC 682D48BB 5D42E3D9 B9EFFE76"; 
// 
// //	产生随机数k 
// static char g_ecdsa_rand_k[]= "6CB28D99 385C175C 94F94E93 4817663F C176D925 DD72B727 260DBAAE 1FB2F96F";
//  
// //消息M的签名为(r,s)：
// //值r：
// static char g_ecdsa_sign_r[]= "40F1EC59 F793D9F4 9E09DCEF 49130D41 94F79FB1 EED2CAA5 5BACDB49 C4E755D1";
// //值s：
// static char g_ecdsa_sign_s[]= "6FC6DAC3 2C5D5CF1 0C77DFB2 0F7C2EB6 67A45787 2FB09EC5 6327A67E C7DEEBE7";
// 

int ECDSA_Speed_Test(int flag);


 
#endif 