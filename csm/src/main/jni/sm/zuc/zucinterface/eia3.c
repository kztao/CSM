#include "mm_memory.h" 
#include "mm_macro.h"
#include "eia3.h" 

#define GET_DWORD(u32_high, u32_low, i)	( ((u32_high)<<i) | ( (u32_low)>>(32-(i)) ) )
#define GET_BIT(p_u8, pos)			( (p_u8)[pos>>3] & (1 << (7-((pos) & 0x7))) )  
/*
#if 0
mm_u32_t GET_BIT(mm_u8_t * DATA, mm_u32_t i)
{
	//方法1：利用官方代码将4字节转为32比特后取对应位置
	mm_u32_t r1, r2;
	
	{
		mm_u32_t d32 ;
		MM_LOAD_U32H(d32, DATA+(i/32)*4);
		r1 = d32 & (1<<(31-(i&0x1F)));
		//	return (DATA[i/32] & (1<<(31-(i%32)))) ? 1 : 0;
	}

	//方法1：直接取字节的对应位置
	{
		mm_u32_t pos = i>>3; 
		r2 = DATA[pos]& (1<<(7-(i&0x7))); 
		if((!r1)!=(!r2))
		{
			int debug = 1;
		}
	} 
	return r1;
}
#endif
*/
  
/* init */
mm_i32_t eia3_init_core(zuc_ctx *p, mm_u8_t ik[EIA3_IK_LEN], 
				   mm_u32_t count, mm_u32_t bearer, mm_u32_t direction )
{    
	mm_u8_t iv[16]; 
	
	/* init */
	MM_STORE_U32H(count, iv);  
	MM_MEMSET(iv+5, 0x00, 3);
	iv[4]	= (mm_u8_t)(bearer << 3);
	
	MM_MEMCPY(iv+8, iv, 8);
	direction <<= 7;
	iv[8]	^= direction;
	iv[14]	^= direction;  
	
	/* init zuc */
	zuc_init_core(p, ik, iv);  
	
	return 1;
}


/* unit */
mm_i32_t eia3_unit_core(zuc_ctx *p, mm_u8_t mac[EIA3_MAC_LEN])
{
	MM_STORE_U32H(p->mac,mac); 
	zuc_unit_core(p); 
	return 1;
}

 
/* process msg */
mm_i32_t eia3_process_core( zuc_ctx *p, mm_u8_t* p_msg, mm_u32_t bit_len )
{
	mm_u32_t t = 0, i = 0, j = 0, key32_0 = 0, key32_1 = 0;

	/* gen key */
	zuc_gen_key_u32(p, key32_1);
	t = p->mac;
	
	for ( i = 0; i <= bit_len; i++ )
	{
		j = i & 0x1F;
		
		if( !j )
		{
			key32_0 = key32_1;
			zuc_gen_key_u32(p, key32_1);
		}
		
		if ( GET_BIT(p_msg,i) || ( i == bit_len ) )
		{
			t ^= ( j ) ? GET_DWORD(key32_0, key32_1, j) : key32_0; 
		}  
	}
	
	zuc_gen_key_u32(p, key32_1);
	t ^=  key32_1;   
	p->mac = t; 

	t = key32_0 = key32_1 = 0;
	return 1;
}



// #include <stdio.h>
// FILE*fp = NULL;

/* init */
mm_i32_t eia3_init_core2(zuc_ctx *p, mm_u8_t ik[EIA3_IK_LEN], 
						mm_u32_t count, mm_u32_t bearer, mm_u32_t direction )
{    
	mm_u8_t iv[16]; 

	/* init */
	MM_STORE_U32H(count, iv);  
	MM_MEMSET(iv+5, 0x00, 3);
	iv[4]	= (mm_u8_t)(bearer << 3);

	MM_MEMCPY(iv+8, iv, 8);
	direction <<= 7;
	iv[8]	^= direction;
	iv[14]	^= direction;  

	/* init zuc */
	zuc_init_core(p, ik, iv);   

	p->key32h = 0;
	zuc_gen_key_u32(p, p->key32l);

	//fp = fopen("d:\\ZUC20160318.txt", "wt");//debug
	return 1;
}


/* unit */
mm_i32_t eia3_unit_core2(zuc_ctx *p, mm_u8_t mac[EIA3_MAC_LEN])
{
	mm_u32_t j;
  
	j = p->eia3_bits & 0x1f;
	if( j == 1 )
	{
		p->key32h = p->key32l;
		zuc_gen_key_u32(p, p->key32l); 
	}

	p->mac ^= ( j ) ? GET_DWORD(p->key32h, p->key32l, j) : p->key32l; // T = T XOR K_LENGTH

	//fprintf(fp, "%4d\t%08x, %08x, %08x\n", p->eia3_bits-1, p->key32h, p->key32l, p->mac);//debug
	zuc_gen_key_u32(p, p->key32l);
	p->mac ^=  p->key32l;		// T = T XOR K_{32*(L-1)}

	//fprintf(fp, "%4d\t%08x, %08x, %08x\n", 9999, p->key32h, p->key32l, p->mac);//debug
	MM_STORE_U32H(p->mac,mac);	// MAC = T = T XOR K_{32*(L-1)}
	zuc_unit_core(p); 

	//fclose(fp);//debug
 
	return 1;
}


/* process msg */
mm_i32_t eia3_process_core2( zuc_ctx *p, mm_u8_t* p_msg, mm_u32_t bit_len )
{ 
	mm_u32_t t, i, j, key32h, key32l, eia3_bits;

	eia3_bits = p->eia3_bits;
	key32h = p->key32h;
	key32l = p->key32l;
	t = p->mac;

	i = 0;
	while ( i < bit_len )
	{ 
		j = (eia3_bits) & 0x1f;
		if( j == 1 )
		{
			key32h = key32l;
			zuc_gen_key_u32(p, key32l); 
		}

		if ( GET_BIT(p_msg,i) )
		{
			t ^= ( j ) ? GET_DWORD(key32h, key32l, j) : key32l; 
		}   
		i++;
		eia3_bits++;

		//fprintf(fp, "%4d\t%08x, %08x, %08x\n", eia3_bits-1, key32h, key32l, t);//debug
	}


	p->key32h = key32h;
	p->key32l = key32l;
	p->mac = t;
	p->eia3_bits = eia3_bits;

	t = key32h = key32l = eia3_bits = 0;
	return 1; 
}







/*//暂时保留，作为对照代码做对比测试用
mm_u32_t GET_WORD(mm_u32_t * DATA, mm_u32_t i)
{
	mm_u32_t WORD, ti;
	
	ti	= i % 32;
	if (ti == 0) {
		WORD = DATA[i/32];
	}
	else {
		WORD = (DATA[i/32]<<ti) | (DATA[i/32+1]>>(32-ti));
	}
	
	return WORD;
}

// 采取一次性获取所有key值，再对这些key值做MAC 
mm_i32_t eia3_process_mode1( zuc_ctx *p, mm_u8_t* p_msg, mm_u32_t bit_len )
{
	mm_u32_t i;
	mm_u32_t L	= (bit_len + 31) / 32+2, T;
	mm_u32_t *z	= (mm_u32_t *) malloc(L*sizeof(mm_u32_t));

	MM_MEMSET(z, 0x00, L*sizeof(mm_u32_t));

	for (i = 0; i < L; i++)
	{
		zuc_gen_key_u32(p, z[i]);  
	}

	T = 0;

	for (i=0; i<bit_len; i++) 
	{
		if (GET_BIT(p_msg,i)) 
		{
			T ^= GET_WORD(z,i); 
		}
	}

	T ^= GET_WORD(z,bit_len);  
	T ^= z[L-1];  
	p->mac = T;

	free(z);  
	return 1; 
} 
*/
