/* *Copyright (c) 2012, �人��ѧ�����о�����* 
   *All rights reserved.* 
   *
   *�ļ����ƣ�ecc.c
   *ժ    Ҫ����������ģ��
   *��    ��: �����
   *ʱ    ��: 2012.3.16 10:47
   *���°汾: v1.0.0
*/
#include "types.h"
#include "bn.h"
#include "ecp.h"
#include "ecc.h"
#include "config.h"
#include "sm2.h"
#include "sm3.h"
#include "malloc.h"


extern EC mEC_SM2;

void ECCGenkey(Word *pwPriKey,
			   Word *pwPubKeyX,
			   Word *pwPubKeyY
			   )
{
	A_Point KG;
	Word K[MAXBNWordLen];
	
	BNAssign(K,pwPriKey);
	ECPKG(K,&KG);
	BNAssign(pwPubKeyX,KG.X);
	BNAssign(pwPubKeyY,KG.Y);

}


int	ECCSM2SignHash (
					Word *pwRandom,
					Word *pwHash,
					Word *pwPriKey,
					Word *pwSignR,
					Word *pwSignS
					)
{
	
	A_Point KG;
	Word K[MAXBNWordLen],r[MAXBNWordLen],d[MAXBNWordLen],e[MAXBNWordLen],s[MAXBNWordLen];
	Word bn1[MAXBNWordLen],bn2[MAXBNWordLen],bn3[MAXBNWordLen];
	Word IntOne[MAXBNWordLen];
	Word *EC_N,*EC_NRR,EC_N_MC;
	int i;

	EC_N=mEC_SM2.EC_N;
	EC_NRR=mEC_SM2.EC_NRR;
	EC_N_MC=mEC_SM2.EC_N_MC;

	for (i = 0; i < BNWORDLEN; i++)
        IntOne[i] = 0;
    IntOne[0] = 1;

	BNAssign(K,pwRandom);
	BNAssign(d,pwPriKey);
	BNAssign(e,pwHash);
	
	ECPKG(K,&KG);
	BNModAdd(r,KG.X,e,EC_N);	//r=(e+x)modN
	BNModSub(r,r,EC_N,EC_N);	//check r

	BNAdd(bn1,r,K);	//bn1=r+k;
	
	BNAdd(bn2,IntOne,d);							//bn2=1+dA   //BNAdd(bn2,bn1,d,iBNWordLen);						
	BNMonInv(bn2,bn2,EC_N,EC_N_MC,EC_NRR);				//bn2=mon(1+dA)^-1
	BNMonMul(bn3,r,EC_NRR,EC_N,EC_N_MC);				//bn3=mon r
	BNMonMul(bn3,bn3,d,EC_N,EC_N_MC);					//bn3=r*dA
	BNModSub(bn3,K,bn3,EC_N);							//bn3=K-r*dA
	BNMonMul(bn2,bn2,bn3,EC_N,EC_N_MC);					//bn2=(1+dA)^-1(K-r*dA)
	BNModSub(s,bn2,EC_N,EC_N);							//check s

	BNAssign(pwSignR,r);
	BNAssign(pwSignS,s);

	return SM2_OK;
	
}


int	ECCSM2VerifyHash (Word		*pwHash,
					  Word		*pwPubKeyX,
					  Word		*pwPubKeyY,
					  Word		*pwSignR,
					  Word		*pwSignS
					  )
{
	Word r[MAXBNWordLen],s[MAXBNWordLen],e[MAXBNWordLen],t[MAXBNWordLen],R[MAXBNWordLen];

	A_Point Q,sGtP;
	Word *EC_N,*EC_NRR,EC_N_MC;
	
	EC_N    = mEC_SM2.EC_N;
	EC_NRR  = mEC_SM2.EC_NRR;
	EC_N_MC = mEC_SM2.EC_N_MC;

	BNAssign(e,   pwHash);
	BNAssign(r,   pwSignR);
	BNAssign(s,   pwSignS);
	BNAssign(Q.X, pwPubKeyX);
	BNAssign(Q.Y, pwPubKeyY);

	BNModAdd(t,r,s,EC_N);//(r+s)modN
	BNModSub(t,t,EC_N,EC_N);//check t
	

	ECPKGLQ(s,t,&Q,&sGtP);		//sG+tP
	
	BNModAdd(R,sGtP.X,e,EC_N); //R=(e+sGtP.x)modN
	BNModSub(R,R,EC_N,EC_N);   //check R

	if(BNCompare(R,r)==0)
		return SM2_OK;
	else
		return SM2_Signature_Illeage;
}


/************************************************************************/
/* SM2�����㷨                                                          */
/************************************************************************/
int	ECCSM2Encrypt (
				   Word *pwRandom,
				   BYTE *pbPlainText,
				   int iPlainTextLen,
				   Word *pwPubKeyX,
				   Word *pwPubKeyY,
				   BYTE *pbC1,
				   BYTE *pbC2,
				   BYTE *pbC3
				   )
{
	int i;
	A_Point KG,KP,Q;
	Word K[MAXBNWordLen];
	BYTE *Xbyte,*Ybyte,*XYbyte,*ZOut;
	BYTE *XMbyte,*XMYbyte;
	unsigned long bytelen1,bytelen2;
        

	BNAssign(K,pwRandom);
	BNAssign(Q.X, pwPubKeyX);
	BNAssign(Q.Y, pwPubKeyY);//Q=Pub

	ECPKG(K, &KG);
	BN2Byte(KG.X,pbC1,0);
	BN2Byte(KG.Y,pbC1,MAXBNByteLen);
	ECPKP(K, &Q, &KP);
	for(i=0;i<MAXBNWordLen;i++)		//�ж�Q�Ƿ�Ϊ����ԭ��
	{
		if((KP.X[i]!=0 )||(KP.Y[i]!=0))
			break;		
	}
	XYbyte=(BYTE *)malloc(2*MAXBNWordLen*WordByteLen);
	BN2Byte(KP.X,XYbyte,0);
	BN2Byte(KP.Y,XYbyte,MAXBNWordLen*WordByteLen);
	ZOut=(BYTE *)malloc(iPlainTextLen);
	GBKDF(XYbyte,2*MAXBNWordLen*WordByteLen,iPlainTextLen*8,ZOut,MAXBNByteLen);   //ZOut=KDF(x2||y2,klen)
    

	for(i=0;i<iPlainTextLen;i++)			//�ж�ZOut�Ƿ�Ϊ0
	{
		if(ZOut[i]!=0 )
			break;		
	}
	if(i==iPlainTextLen)
		  return 0;
	for(i=0;i<iPlainTextLen;i++)			//C2==Message^ZOut
			pbC2[i]=pbPlainText[i]^ZOut[i];
	free(XYbyte);
	free(ZOut);
	Xbyte=(BYTE *)malloc(MAXBNWordLen*WordByteLen);
	Ybyte=(BYTE *)malloc(MAXBNWordLen*WordByteLen);
	BN2Byte(KP.X,Xbyte,0);
	BN2Byte(KP.Y,Ybyte,0);
	XMbyte=(BYTE *)malloc(iPlainTextLen+MAXBNWordLen*WordByteLen);
	GBCombine(Xbyte,MAXBNWordLen*WordByteLen,pbPlainText,iPlainTextLen,XMbyte,&bytelen1);  //XMbyte=x2||Message
	XMYbyte=(BYTE *)malloc(iPlainTextLen+2*MAXBNWordLen*WordByteLen);
	GBCombine(XMbyte,bytelen1,Ybyte,MAXBNWordLen*WordByteLen,XMYbyte,&bytelen2);  //XMYbyte=x2||Message||y2
	
	SM3_Data(XMYbyte,bytelen2,pbC3,MAXBNByteLen);  //C3=Hash(x2||Message||y2)
	free(Xbyte);
	free(Ybyte);
	free(XMbyte);
	free(XMYbyte);
	
	return 1;
}
/************************************************************************/
/* SM2�����㷨                                                          */
/************************************************************************/
int	ECCSM2Decrypt (
				   BYTE *pbC1,
				   BYTE *pbC2,
				   BYTE *pbC3,
				   Word *pwPriKey,
				   BYTE *pbPlainText,
				   int iPlainTextLen
				   )
{
	int i;
	A_Point Q,PriQ;
	Word d[MAXBNWordLen];
	BYTE U[MAXBNByteLen];
	BYTE *Xbyte,*Ybyte,*XYbyte,*ZOut;
	BYTE *XMbyte,*XMYbyte;
	unsigned long bytelen1,bytelen2;	

	BNAssign(d,pwPriKey);
	Byte2BN(pbC1,0,MAXBNWordLen*WordByteLen,Q.X);
	Byte2BN(pbC1,MAXBNWordLen*WordByteLen,MAXBNWordLen*WordByteLen,Q.Y);

	ECPKP(d, &Q, &PriQ);
	for(i=0;i<MAXBNWordLen;i++)		//�ж�PriQ�Ƿ�Ϊ����Զ��
	{
		if((PriQ.X[i]!=0 )||(PriQ.Y[i]!=0))
			break;		
	}
	if(i==MAXBNWordLen)
	{	
		printf("i==MAXBNWordLen\n");
		return 0;
	}
	//delete by zxm , memory leak
	//Xbyte=(BYTE *)malloc(MAXBNWordLen*WordByteLen);
	//Ybyte=(BYTE *)malloc(MAXBNWordLen*WordByteLen);
	XYbyte=(BYTE *)malloc(2*MAXBNWordLen*WordByteLen);
	BN2Byte(PriQ.X,XYbyte,0);
	BN2Byte(PriQ.Y,XYbyte,MAXBNWordLen*WordByteLen);
		ZOut=(BYTE *)malloc(iPlainTextLen);
	GBKDF(XYbyte,2*MAXBNWordLen*WordByteLen,iPlainTextLen*8,ZOut,MAXBNByteLen);   //ZOut=KDF(x2||y2,klen)

	for(i=0;i<iPlainTextLen;i++)		    //�ж�ZOut�Ƿ�Ϊ0
	{
		if(ZOut[i]!=0 )
			break;		
	}
	if(i==iPlainTextLen)
	{
		printf("i==iPlainTextLen\n");
		return 0;
	}	
	
	for(i=0;i<iPlainTextLen;i++)			//M'=C2^ZOut
		pbPlainText[i]=pbC2[i]^ZOut[i];
	free(XYbyte);
	free(ZOut);
	Xbyte=(BYTE *)malloc(MAXBNWordLen*WordByteLen);
	Ybyte=(BYTE *)malloc(MAXBNWordLen*WordByteLen);

	BN2Byte(PriQ.X,Xbyte,0);
	BN2Byte(PriQ.Y,Ybyte,0);

	XMbyte=(BYTE *)malloc(iPlainTextLen+MAXBNWordLen*WordByteLen);
	GBCombine(Xbyte,MAXBNWordLen*WordByteLen,pbPlainText,iPlainTextLen,XMbyte,&bytelen1);  //XMbyte=x||M'
	XMYbyte=(BYTE *)malloc(iPlainTextLen+2*MAXBNWordLen*WordByteLen);
	GBCombine(XMbyte,bytelen1,Ybyte,MAXBNWordLen*WordByteLen,XMYbyte,&bytelen2);  //XMYbyte=x||M'||y
	SM3_Data(XMYbyte,bytelen2,U,MAXBNByteLen);  //C3=Hash(x2||Message||y2)

    for(i=0;i<HASHLEN;i++)
	{
		if(U[i]!=pbC3[i])
			{
				printf("U[%d]!=pbC3[%d]\n",i,i);
				free(Xbyte);
				free(Ybyte);	
				free(XMbyte);
				free(XMYbyte);
				return 0;
			}
	}
	free(Xbyte);
	free(Ybyte);	
	free(XMbyte);
	free(XMYbyte);
	return 1;
}
