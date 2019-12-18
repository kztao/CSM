#ifndef _KEY_EXCHANGE_Test_h
#define _KEY_EXCHANGE_Test_h


//#include "test_sm2_vector.h"


/** ��������������׼�ĵ� **/
/**	����p  **/
static   char g_ka_ec_p[ ] = "8542D69E 4C044F18 E8B92435 BF6FF7DE 45728391 5C45517D 722EDB8B 08F1DFC3"; 
/**	ϵ��a  **/
static   char g_ka_ec_a[ ] = "787968B4 FA32C3FD 2417842E 73BBFEFF 2F3C848B 6831D7E0 EC65228B 3937E498";
/**	ϵ��b  **/
static   char g_ka_ec_b[ ] = "63E4C6D3 B23B0C84 9CF84241 484BFE48 F61D59A5 B16BA06E 6E12D1DA 27C5249A";
/** 	����xG  **/
static   char g_ka_ec_gx[] = "421DEBD6 1B62EAB6 746434EB C3CC315E 32220B3B ADD50BDC 4C4E6C14 7FEDD43D"; 
/** 	����yG  **/
static   char g_ka_ec_gy[] = "0680512B CBB42C07 D47349D2 153B70C4 E5D7FDFC BFA36EA1 A85841B9 E46E09A2"; 
/** 	��n  **/
static   char g_ka_ec_gn[] = "8542D69E 4C044F18 E8B92435 BF6FF7DD 29772063 0485628D 5AE74EE7 C32E79B7"; 


/** 	A˽ԿdA  **/
static   char g_ka_a_sk[ ] = "6FCBA2EF 9AE0AB90 2BC3BDE3 FF915D44 BA4CC78F 88E2F8E7 F8996D3B 8CCEEDEE"; 
/** 	A�Ĺ�ԿPA = (xA,yA)�� **/
/** 	����xA  **/
static   char g_ka_a_pkx[] = "3099093B F3C137D8 FCBBCDF4 A2AE50F3 B0F216C3 122D7942 5FE03A45 DBFE1655"; 
/** 	����yA  **/
static   char g_ka_a_pky[] = "3DF79E8D AC1CF0EC BAA2F2B4 9D51A4B3 87F2EFAF 48233908 6A27A8E0 5BAED98B"; 

/** 	B˽ԿdB  **/
static   char g_ka_b_sk[ ] = "5E35D7D3 F3C54DBA C72E6181 9E730B01 9A84208C A3A35E4C 2E353DFC CB2A3B53"; 
/** 	B�Ĺ�ԿPB=(xB,yB)�� **/
/** 	����xB  **/
static   char g_ka_b_pkx[] = "245493D4 46C38D8C C0F11837 4690E7DF 633A8A4B FB3329B5 ECE604B2 B4F37F43"; 
/** ����yB  **/
static   char g_ka_b_pky[] = "53C0869F 4B9E1777 3DE68FEC 45E14904 E0DEA45B F6CECF99 18C85EA0 47C60A4C"; 

/**
//	�Ӵ�ֵZA=		E4D1D0C3 CA4C7F11 BC8FF8CB 3F4C02A7 8F108FA0 98E51A66 8487240F 75E20F31
//	�Ӵ�ֵZB=		6B4B6D0E 276691BD 4A11BF72 F4FB501A E309FDAC B72FA6CC 336E6656 119ABD67 
//	A������ǣ�ALICE123@YAHOO.COM����ASCII�����IDA: 
**/
static   char g_ka_a_id[] =  "414C 49434531 32334059 41484F4F 2E434F4D"; 
static   int  g_ka_a_id_byte_len = 18;//18*8 = 0x90
/**	B������ǣ�BILL456@YAHOO.COM����ASCII�����IDB  **/
static   char g_ka_b_id[] =  "42 494C4C34 35364059 41484F4F 2E434F4D"; 
static   int  g_ka_b_id_byte_len = 17;//17*8 = 0x88


/**	���������rA  **/
static   char g_ka_a_rdnm[]= "83A2C9C8 B96E5AF7 0BD480B4 72409A9A 327257F1 EBB73F5B 073354B2 48668563";
/** 	������Բ���ߵ�RA=[rA]G=(x1;y1)�� **/
/** 	����x1  **/
static   char g_ka_a_rdptx[]="6CB56338 16F4DD56 0B1DEC45 8310CBCC 6856C095 05324A6D 23150C40 8F162BF0";
/** 	����y1  **/
static   char g_ka_a_rdpty[]="0D6FCF62 F1036C0A 1B6DACCF 57399223 A65F7D7B F2D9637E 5BBBEB85 7961BF1A";

/** 	���������rB��	33FE2194 0342161C 55619C4A 0C060293 D543C80A F19748CE 176D8347 7DE71C80 **/
static   char g_ka_b_rdnm[]= "33FE2194 0342161C 55619C4A 0C060293 D543C80A F19748CE 176D8347 7DE71C80";
/** 	������Բ���ߵ�RB=[rB]G=(x2;y2)�� **/
/** 	����x2  **/
static   char g_ka_b_rdptx[]="1799B2A2 C7782953 00D9A232 5C686129 B8F2B533 7B3DCF45 14E8BBC1 9D900EE5";
/** 	����y2  **/
static   char g_ka_b_rdpty[]="54C9288C 82733EFD F7808AE7 F27D0E73 2F7C73A7 D9AC98B7 D8740A91 D0DB3CF4";

static   char g_ka_share_k[]="55B0AC62 A6B927BA 23703832 C853DED4";


void KeyAgreementTest(int test_flag);

#endif 