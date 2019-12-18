#include "sm2_bn.h"
#include "mm_basic_fun.h"

/**
//	函数功能:								//
//		计算a对n的乘法逆					//
//	函数参数:								//
//		a:in								//
//		a_len:in,a的字长				    //
//		n:in								//
//		n_len:in,n的字长					//
//		in:out,a对n的乘法逆					//							
//		in_len:out,乘法逆的字长				//
//	函数返回:								//
//		无									//
**/

void SM2_BN_mod_inverse(u32_t *in, int *in_len, u32_t *a, int a_len, u32_t *n, int n_len)
{
	/** 根据测试,A,B,X,D,M,Y都分配最大64字节,
	* 由于SM2_BN_mul,SM2_BN_uadd有1字溢出,所以A,B,X,D,M,Y加大了4字节 
	**/

	u32_t *R;
	int A_len, B_len, X_len, Y_len, M_len, D_len, T_len;
	int sign;
	int i;
	//luoying change from 20150528
//	u32_t *A, *B, *X, *Y, *M, *D, *T;
// 	A = (u32_t *)MM_MALLOC(80+4);	
// 	B = (u32_t *)MM_MALLOC(80+4);
// 	X = (u32_t *)MM_MALLOC(80+4);
// 	D = (u32_t *)MM_MALLOC(80+4);
// 	M = (u32_t *)MM_MALLOC(80+4);
// 	Y = (u32_t *)MM_MALLOC(80+4);
	//luoying change to 20150528
	u32_t *A, *B, *X, *Y, *M, *D, *T;
	u32_t A0[96], B0[96], X0[96], Y0[96], M0[96], D0[96], T0[96];
	A = A0; B = B0;	X = X0; Y = Y0;	M = M0; D = D0;	T = T0;
	//luoying change end 20150528 
	
	R = in; 
	X_len = 0;
	Y[0] = 1; Y_len = 1;
	for(i = 0; i < a_len; i++)
		A[i] = a[i];
	A_len = a_len;
	for(i = 0; i < n_len; i++)
		B[i] = n[i];
	B_len = n_len;
	
	sign = 1;
	
	while (B_len)
	{
		SM2_BN_div(D, &D_len, M, &M_len, A, A_len, B, B_len); 
		T = A; T_len = A_len;
		A = B; A_len = B_len;
		B = M; B_len = M_len;
		
		SM2_BN_mul(T, &T_len, D, D_len, X, X_len);
		SM2_BN_uadd(T, &T_len, T, T_len, Y, Y_len);
		
		M = Y; M_len = Y_len;
		Y = X; Y_len = X_len;
		X = T; X_len = T_len;
		sign = -sign;
	}
	if (sign < 0)
		SM2_BN_usub(Y, &Y_len, n, n_len, Y, Y_len);
	
	SM2_BN_div(NULL, NULL, R, in_len, Y, Y_len, n, n_len);
	
// 	MM_FREE(A);//luoying del 20150528
// 	MM_FREE(B);
// 	MM_FREE(X);
// 	MM_FREE(D);
// 	MM_FREE(M);
// 	MM_FREE(Y);
}

