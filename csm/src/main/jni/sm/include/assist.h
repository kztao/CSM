#ifndef _ASSIST_H_FD9529402AC2501F
#define _ASSIST_H_FD9529402AC2501F

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "mm_types.h" 
 

mm_i32_t char_2_num(mm_i8_t ch, mm_u8_t *p_num); 

mm_i32_t str2bytes(mm_u8_t *param, mm_i8_t *p_str, mm_i32_t len);

mm_void_t print_data_dbg(mm_void_t * p_data, mm_i32_t len, char *msg, mm_i32_t inv_prt);




typedef struct zuc_test_vector_st 
{
	mm_i8_t * p_key;	/* 密钥       key 16 bytes */
	mm_i8_t * p_iv;		/* 初始化向量 IV  16 bytes */
	mm_i8_t * p_z1;		/* 第一拍密钥 Z1   4 bytes */
	mm_i8_t * p_z2;		/* 第二拍密钥 Z2   4 bytes */
	mm_i8_t * p_z2k;	/* 第2000拍密钥Z2K 4 bytes */
}zuc_test_vector;


/*测试祖冲之算法的正确性*/
/* 测试数据来源：EEA3 EIA3 Document 3 Implementor's Test Data v1.1.pdf */
const static zuc_test_vector g_zuc_tv[]=
{
	{/*测试向量1*/
		/*密钥*/	(char*)"00000000 00000000 00000000 00000000",
		/* IV */	(char*)"00000000 00000000 00000000 00000000",
		/* Z1 */	(char*)"27bede74",
		/* Z2 */	(char*)"018082da",
		/* Z2K*/	NULL,
	},
	{/*测试向量2*/
		/*密钥*/	(char*)"ffffffff ffffffff ffffffff ffffffff",
		/* IV */	(char*)"ffffffff ffffffff ffffffff ffffffff",
		/* Z1 */	(char*)(char*)"0657cfa0",
		/* Z2 */	(char*)"7096398b",
		/* Z2K*/	NULL,
	}, 
	{/*测试向量3*/
		/*密钥*/	(char*)"3d4c4be9 6a82fdae b58f641d b17b455b",
		/* IV */	(char*)"84319aa8 de6915ca 1f6bda6b fbd8c766",
		/* Z1 */	(char*)"14f1c272",
		/* Z2 */	(char*)"3279c419",
		/* Z2K*/	NULL,
	},
	{/*测试向量4*/
		/*密钥*/	(char*)"4d320bfa d4c285bf d6b8bd00 f39d8b41",
		/* IV */	(char*)"52959dab a0bf176e ce2dc315 049eb574",
		/* Z1 */	(char*)"ed4400e7",
		/* Z2 */	(char*)"0633e5c5",
		/* Z2K*/	(char*)"7a574cdb",
	}
};




typedef struct eea3_test_vector_st 
{
	mm_i8_t * p_key;		 
	mm_i8_t * p_counter;	 	 
	mm_u32_t  bearer;	 
	mm_u32_t  direction;
	mm_u32_t  length;
	mm_i8_t * p_pt;
	mm_i8_t * p_ct;
}eea3_test_vector;
 
/*测试祖冲之算法的机密性算法 EEA3 的正确性 */
/* 测试数据来源：EEA3 EIA3 Document 3 Implementor's Test Data v1.1.pdf */
const static eea3_test_vector g_eea3_tv[]=
{
	{/*测试向量1*/
		/* 密钥		*/	(char*)"173d14ba 5003731d 7a600494 70f00a29",
		/* counter	*/	(char*)"66035492",
		/* bear		*/	0xf,
		/* direction*/	0,
		/* 比特长度	*/	193,
		/* 明文		*/	
		(char*)"6cf65340 735552ab 0c9752fa 6f9025fe 0bd675d9 005875b2 00000000",
		/* 密文		*/	
		(char*)"a6c85fc6 6afb8533 aafc2518 dfe78494 0ee1e4b0 30238cc8 00000000"			
	},  
	{/*测试向量2*/
		/* 密钥		*/	(char*)"e5bd3ea0 eb55ade8 66c6ac58 bd54302a",
		/* counter	*/	(char*)"00056823",
		/* bear		*/	0x18,
		/* direction*/	1,
		/* 比特长度	*/	800,
		/* 明文		*/	
		(char*)"14a8ef69 3d678507 bbe7270a 7f67ff50 06c3525b 9807e467 c4e56000 ba338f5d"
		"42955903 67518222 46c80d3b 38f07f4b e2d8ff58 05f51322 29bde93b bbdcaf38"
		"2bf1ee97 2fbf9977 bada8945 847a2a6c 9ad34a66 7554e04d 1f7fa2c3 3241bd8f"
		"01ba220d",
		/* 密文		*/	
		(char*)"131d43e0 dea1be5c 5a1bfd97 1d852cbf 712d7b4f 57961fea 3208afa8 bca433f4"
		"56ad09c7 417e58bc 69cf8866 d1353f74 865e8078 1d202dfb 3ecff7fc bc3b190f"
		"e82a204e d0e350fc 0f6f2613 b2f2bca6 df5a473a 57a4a00d 985ebad8 80d6f238"
		"64a07b01"			
	}, 					
	{/*测试向量3*/
		/* 密钥		*/	(char*)"d4552a8f d6e61cc8 1a200914 1a29c10b",
		/* counter	*/	(char*)"76452ec1",
		/* bear		*/	0x2,
		/* direction*/	1,
		/* 比特长度	*/	1570,
		/* 明文		*/	
		(char*)"38f07f4b e2d8ff58 05f51322 29bde93b bbdcaf38 2bf1ee97 2fbf9977 bada8945"
		"847a2a6c 9ad34a66 7554e04d 1f7fa2c3 3241bd8f 01ba220d 3ca4ec41 e074595f"
		"54ae2b45 4fd97143 20436019 65cca85c 2417ed6c bec3bada 84fc8a57 9aea7837"
		"b0271177 242a64dc 0a9de71a 8edee86c a3d47d03 3d6bf539 804eca86 c584a905"
		"2de46ad3 fced6554 3bd90207 372b27af b79234f5 ff43ea87 0820e2c2 b78a8aae"
		"61cce52a 0515e348 d196664a 3456b182 a07c406e 4a207912 71cfeda1 65d535ec"
		"5ea2d4df 40000000",
		/* 密文		*/	
		(char*)"8383b022 9fcc0b9d 2295ec41 c977e9c2 bb72e220 378141f9 c8318f3a 270dfbcd"
		"ee6411c2 b3044f17 6dc6e00f 8960f97a facd131a d6a3b49b 16b7babc f2a509eb"
		"b16a75dc ab14ff27 5dbeeea1 a2b155f9 d52c2645 2d0187c3 10a4ee55 beaa78ab"
		"4024615b a9f5d5ad c7728f73 560671f0 13e5e550 085d3291 df7d5fec edded559"
		"641b6c2f 585233bc 71e9602b d2305855 bbd25ffa 7f17ecbc 042daae3 8c1f57ad"
		"8e8ebd37 346f71be fdbb7432 e0e0bb2c fc09bcd9 6570cb0c 0c39df5e 29294e82"
		"703a637f 80000000"						
	}, 
	{/*测试向量4*/
	/* 密钥		*/	(char*)"db84b4fb ccda563b 66227bfe 456f0f77",
	/* counter	*/	(char*)"e4850fe1",
	/* bear		*/	0x10,
	/* direction*/	1,
	/* 比特长度	*/	2798,
	/* 明文		*/	
	(char*)"e539f3b8 973240da 03f2b8aa 05ee0a00 dbafc0e1 82055dfe 3d7383d9 2cef40e9"	
	"2928605d 52d05f4f 9018a1f1 89ae3997 ce19155f b1221db8 bb0951a8 53ad852c"
	"e16cff07 382c93a1 57de00dd b125c753 9fd85045 e4ee07e0 c43f9e9d 6f414fc4"
	"d1c62917 813f74c0 0fc83f3e 2ed7c45b a5835264 b43e0b20 afda6b30 53bfb642"
	"3b7fce25 479ff5f1 39dd9b5b 995558e2 a56be18d d581cd01 7c735e6f 0d0d97c4"
	"ddc1d1da 70c6db4a 12cc9277 8e2fbbd6 f3ba52af 91c9c6b6 4e8da4f7 a2c266d0"
	"2d001753 df089603 93c5d568 88bf49eb 5c16d9a8 0427a416 bcb597df 5bfe6f13"
	"890a07ee 1340e647 6b0d9aa8 f822ab0f d1ab0d20 4f40b7ce 6f2e136e b67485e5"
	"07804d50 4588ad37 ffd81656 8b2dc403 11dfb654 cdead47e 2385c343 6203dd83"
	"6f9c64d9 7462ad5d fa63b5cf e08acb95 32866f5c a787566f ca93e6b1 693ee15c"
	"f6f7a2d6 89d97417 98dc1c23 8e1be650 733b18fb 34ff880e 16bbd21b 47ac0000",
	/* 密文		*/	
	(char*)"4bbfa91b a25d47db 9a9f190d 962a19ab 323926b3 51fbd39e 351e05da 8b8925e3"
	"0b1cce0d 12211010 95815cc7 cb631950 9ec0d679 40491987 e13f0aff ac332aa6"
	"aa64626d 3e9a1917 519e0b97 b655c6a1 65e44ca9 feac0790 d2a321ad 3d86b79c"
	"5138739f a38d887e c7def449 ce8abdd3 e7f8dc4c a9e7b733 14ad310f 9025e619"
	"46b3a56d c649ec0d a0d63943 dff592cf 962a7efb 2c8524e3 5a2a6e78 79d62604"
	"ef268695 fa400302 7e22e608 30775220 64bd4a5b 906b5f53 1274f235 ed506cff"
	"0154c754 928a0ce5 476f2cb1 020a1222 d32c1455 ecaef1e3 68fb344d 1735bfbe"
	"deb71d0a 33a2a54b 1da5a294 e679144d df11eb1a 3de8cf0c c0619179 74f35c1d"
	"9ca0ac81 807f8fcc e6199a6c 7712da86 5021b04c e0439516 f1a526cc da9fd9ab"
	"bd53c3a6 84f9ae1e 7ee6b11d a138ea82 6c5516b5 aadf1abb e36fa7ff f92e3a11"
	"76064e8d 95f2e488 2b5500b9 3228b219 4a475c1a 27f63f9f fd264989 a1bc0000",
	},  
	{/*测试向量5*/ 
		/* 密钥		*/	(char*)"e13fed21 b46e4e7e c31253b2 bb17b3e0",
		/* counter	*/	(char*)"2738cdaa",
		/* bear		*/	0x1a,
		/* direction*/	0,
		/* 比特长度	*/	0xFB3,
		/* 明文		*/	
		(char*)"8d74e20d 54894e06 d3cb13cb 3933065e 8674be62 adb1c72b 3a646965 ab63cb7b"					
		"7854dfdc 27e84929 f49c64b8 72a490b1 3f957b64 827e71f4 1fbd4269 a42c97f8"
		"24537027 f86e9f4a d82d1df4 51690fdd 98b6d03f 3a0ebe3a 312d6b84 0ba5a182"
		"0b2a2c97 09c090d2 45ed267c f845ae41 fa975d33 33ac3009 fd40eba9 eb5b8857"
		"14b768b6 97138baf 21380eca 49f644d4 8689e421 5760b906 739f0d2b 3f091133"
		"ca15d981 cbe401ba f72d05ac e05cccb2 d297f4ef 6a5f58d9 1246cfa7 7215b892"
		"ab441d52 78452795 ccb7f5d7 9057a1c4 f77f80d4 6db2033c b79bedf8 e60551ce"
		"10c667f6 2a97abaf abbcd677 2018df96 a282ea73 7ce2cb33 1211f60d 5354ce78"
		"f9918d9c 206ca042 c9b62387 dd709604 a50af16d 8d35a890 6be484cf 2e74a928"
		"99403643 53249b27 b4c9ae29 eddfc7da 6418791a 4e7baa06 60fa6451 1f2d685c"
		"c3a5ff70 e0d2b742 92e3b8a0 cd6b04b1 c790b8ea d2703708 540dea2f c09c3da7"
		"70f65449 e84d817a 4f551055 e19ab850 18a0028b 71a144d9 6791e9a3 57793350"
		"4eee0060 340c69d2 74e1bf9d 805dcbcc 1a6faa97 6800b6ff 2b671dc4 63652fa8"
		"a33ee509 74c1c21b e01eabb2 16743026 9d72ee51 1c9dde30 797c9a25 d86ce74f"
		"5b961be5 fdfb6807 814039e7 137636bd 1d7fa9e0 9efd2007 505906a5 ac45dfde"
		"ed7757bb ee745749 c2963335 0bee0ea6 f409df45 80160000",
		/* 密文		*/	
		(char*)"94eaa4aa 30a57137 ddf09b97 b25618a2 0a13e2f1 0fa5bf81 61a879cc 2ae797a6"
		"b4cf2d9d f31debb9 905ccfec 97de605d 21c61ab8 531b7f3c 9da5f039 31f8a064"
		"2de48211 f5f52ffe a10f392a 04766998 5da454a2 8f080961 a6c2b62d aa17f33c"
		"d60a4971 f48d2d90 9394a55f 48117ace 43d708e6 b77d3dc4 6d8bc017 d4d1abb7"
		"7b7428c0 42b06f2f 99d8d07c 9879d996 00127a31 985f1099 bbd7d6c1 519ede8f"
		"5eeb4a61 0b349ac0 1ea23506 91756bd1 05c974a5 3eddb35d 1d4100b0 12e522ab"
		"41f4c5f2 fde76b59 cb8b96d8 85cfe408 0d1328a0 d636cc0e dc05800b 76acca8f"
		"ef672084 d1f52a8b bd8e0993 320992c7 ffbae17c 408441e0 ee883fc8 a8b05e22"
		"f5ff7f8d 1b48c74c 468c467a 028f09fd 7ce91109 a570a2d5 c4d5f4fa 18c5dd3e"
		"4562afe2 4ef77190 1f59af64 5898acef 088abae0 7e92d52e b2de5504 5bb1b7c4"
		"164ef2d7 a6cac15e eb926d7e a2f08b66 e1f759f3 aee44614 725aa3c7 482b3084"
		"4c143ff8 5b53f1e5 83c50125 7dddd096 b81268da a303f172 34c23335 41f0bb8e"
		"190648c5 807c866d 71932286 09adb948 686f7de2 94a802cc 38f7fe52 08f5ea31"
		"96d0167b 9bdd02f0 d2a5221c a508f893 af5c4b4b b9f4f520 fd84289b 3dbe7e61"
		"497a7e2a 584037ea 637b6981 127174af 57b471df 4b2768fd 79c1540f b3edf2ea"
		"22cb69be c0cf8d93 3d9c6fdd 645e8505 91cca3d6 2c0cc000",
	},	
};


typedef eea3_test_vector eia3_test_vector;
/*测试祖冲之算法的完整性算法 EIA3 的正确性 */
/* 测试数据来源：EEA3 EIA3 Document 3 Implementor's Test Data v1.1.pdf */

const static eia3_test_vector g_eia3_tv[]=
{
	{/*测试向量1*/
		/* 密钥		*/	(char*)"00000000 00000000 00000000 00000000",
		/* counter	*/	(char*)"00000000",
		/* bear		*/	0x0,
		/* direction*/	0,
		/* 比特长度	*/	1,
		/* 明文		*/	(char*)"00000000",
		/* MAC		*/	(char*)"c8a9595e"
	},  
	{/*测试向量2*/
		/* 密钥		*/	(char*)"47054125 561eb2dd a94059da 05097850",
		/* counter	*/	(char*)"561eb2dd",
		/* bear		*/	0x14,
		/* direction*/	0,
		/* 比特长度	*/	90,
		/* 明文		*/	(char*)"00000000 00000000 00000000",
		/* MAC		*/	(char*)"6719a088"
	}, 
	{/*测试向量3*/
		/* 密钥		*/	(char*)"c9e6cec4 607c72db 000aefa8 8385ab0a",
		/* counter	*/	(char*)"a94059da",
		/* bear		*/	0xa,
		/* direction*/	1,
		/* 比特长度	*/	577,
		/* 明文		*/	
		(char*)"983b41d4 7d780c9e 1ad11d7e b70391b1 de0b35da 2dc62f83 e7b78d63 06ca0ea0"
		"7e941b7b e91348f9 fcb170e2 217fecd9 7f9f68ad b16e5d7d 21e569d2 80ed775c"
		"ebde3f40 93c53881 00000000",
		/* MAC		*/	"fae8ff0b" 					
	},  
	{/*测试向量4*/
		/* 密钥		*/	(char*)"c8a48262 d0c2e2ba c4b96ef7 7e80ca59",
		/* counter	*/	(char*)"05097850",
		/* bear		*/	0x10,
		/* direction*/	1,
		/* 比特长度	*/	2079,
		/* 明文		*/	
		(char*)"b546430b f87b4f1e e834704c d6951c36 e26f108c f731788f 48dc34f1 678c0522"
		"1c8fa7ff 2f39f477 e7e49ef6 0a4ec2c3 de24312a 96aa26e1 cfba5756 3838b297"
		"f47e8510 c779fd66 54b14338 6fa639d3 1edbd6c0 6e47d159 d94362f2 6aeeedee"
		"0e4f49d9 bf841299 5415bfad 56ee82d1 ca7463ab f085b082 b09904d6 d990d43c"
		"f2e062f4 0839d932 48b1eb92 cdfed530 0bc14828 0430b6d0 caa094b6 ec8911ab"
		"7dc36824 b824dc0a f6682b09 35fde7b4 92a14dc2 f4364803 8da2cf79 170d2d50"
		"133fd494 16cb6e33 bea90b8b f4559b03 732a01ea 290e6d07 4f79bb83 c10e5800"
		"15cc1a85 b36b5501 046e9c4b dcae5135 690b8666 bd54b7a7 03ea7b6f 220a5469"
		"a568027e",
		/* MAC		*/	(char*)"004ac4d6"
	}, 
	{/*测试向量5*/
		/* 密钥		*/	(char*)"6b8b08ee 79e0b598 2d6d128e a9f220cb",
		/* counter	*/	(char*)"561eb2dd", 
		/* bear		*/	0x1C,
		/* direction*/	0,
		/* 比特长度	*/	5670,
		/* 明文		*/	
		(char*)"5bad7247 10ba1c56 d5a315f8 d40f6e09 3780be8e 8de07b69 92432018 e08ed96a"
		"5734af8b ad8a575d 3a1f162f 85045cc7 70925571 d9f5b94e 454a77c1 6e72936b"
		"f016ae15 7499f054 3b5d52ca a6dbeab6 97d2bb73 e41b8075 dce79b4b 86044f66"
		"1d4485a5 43dd7860 6e0419e8 059859d3 cb2b67ce 0977603f 81ff839e 33185954"
		"4cfbc8d0 0fef1a4c 8510fb54 7d6b06c6 11ef44f1 bce107cf a45a06aa b360152b"
		"28dc1ebe 6f7fe09b 0516f9a5 b02a1bd8 4bb0181e 2e89e19b d8125930 d178682f"
		"3862dc51 b636f04e 720c47c3 ce51ad70 d94b9b22 55fbae90 6549f499 f8c6d399"
		"47ed5e5d f8e2def1 13253e7b 08d0a76b 6bfc68c8 12f375c7 9b8fe5fd 85976aa6"
		"d46b4a23 39d8ae51 47f680fb e70f978b 38effd7b 2f7866a2 2554e193 a94e98a6"
		"8b74bd25 bb2b3f5f b0a5fd59 887f9ab6 8159b717 8d5b7b67 7cb546bf 41eadca2"
		"16fc1085 0128f8bd ef5c8d89 f96afa4f a8b54885 565ed838 a950fee5 f1c3b0a4"
		"f6fb71e5 4dfd169e 82cecc72 66c850e6 7c5ef0ba 960f5214 060e71eb 172a75fc"
		"1486835c bea65344 65b055c9 6a72e410 52241823 25d83041 4b40214d aa8091d2"
		"e0fb010a e15c6de9 0850973b df1e423b e148a237 b87a0c9f 34d4b476 05b803d7"
		"43a86a90 399a4af3 96d3a120 0a62f3d9 507962e8 e5bee6d3 da2bb3f7 237664ac"
		"7a292823 900bc635 03b29e80 d63f6067 bf8e1716 ac25beba 350deb62 a99fe031"
		"85eb4f69 937ecd38 7941fda5 44ba67db 09117749 38b01827 bcc69c92 b3f772a9"
		"d2859ef0 03398b1f 6bbad7b5 74f7989a 1d10b2df 798e0dbf 30d65874 64d24878"
		"cd00c0ea ee8a1a0c c753a279 79e11b41 db1de3d5 038afaf4 9f5c682c 3748d8a3"
		"a9ec54e6 a371275f 1683510f 8e4f9093 8f9ab6e1 34c2cfdf 4841cba8 8e0cff2b"
		"0bcc8e6a dcb71109 b5198fec f1bb7e5c 531aca50 a56a8a3b 6de59862 d41fa113"
		"d9cd9578 08f08571 d9a4bb79 2af271f6 cc6dbb8d c7ec36e3 6be1ed30 8164c31c"
		"7c0afc54 1c000000",
		/* MAC		*/	(char*)"0ca12792"
	},								
};

#endif
