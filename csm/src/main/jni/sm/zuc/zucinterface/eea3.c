#include "mm_memory.h" 
#include "mm_macro.h"
#include "eea3.h"


mm_i32_t eea3_init_core(zuc_ctx *p_eea3, mm_u8_t* p_ck, 
				   mm_u32_t count, mm_u32_t bearer, mm_u32_t direction)
{  
	mm_u8_t  iv[16]; 
	 
	MM_MEMSET(p_eea3, 0x00, sizeof(zuc_ctx)); 

	/* init */
	MM_MEMSET(iv+5, 0, 3);
	MM_STORE_U32H(count,iv); 
	iv[4]	= (mm_u8_t)( (bearer << 3) | ((direction&1)<<2) );
	MM_MEMCPY(iv+8, iv, 8);  

	/* The initialization of ZUC */
	zuc_init_core(p_eea3, p_ck, iv); 

	return 1;
}


mm_i32_t eea3_unit_core(zuc_ctx *p_eea3 )
{
	zuc_unit_core(p_eea3);
	MM_MEMSET(p_eea3, 0x00, sizeof(zuc_ctx));
	return 1;
}
