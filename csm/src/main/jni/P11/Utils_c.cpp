
#include "Utils_c.h"
#include <unistd.h>
#include <sys/time.h>
#include <malloc.h>
#include <cstring>


#define MILLION 1000000

/**
* The default constructor to create a UtilsTime without parameter.
* Both the sec part and usec part are made zero.
*
*/

#define NULL_PTR 0

void Utilsgettime(UtilscTimePtr get_time) 
{
	struct timeval tp;
	gettimeofday(&tp, NULL_PTR);
	(*get_time).sec = (tp).tv_sec;
	(*get_time).usec = (tp).tv_usec;
	//printf("tv_sec; %d\n", tp.tv_sec);
   // printf("tv_usec; %d\n", tp.tv_usec);
}

unsigned long long Utilsgetuseconds(UtilscTimePtr getted_time)
{
	unsigned long long tmp=0;	
	tmp = MILLION * (unsigned long long)(*getted_time).sec + (*getted_time).usec;
	return tmp;
}


/**
* This program is to overload the operator +=,with a UtilsTime paramater.
*
* @param t   the UtilsTime to be added to the objext
* @return    self object
*/
int UtilsTimeAdded(UtilscTimePtr tt1, UtilscTimePtr tt2) 
{
	if((tt1==NULL)||(tt2==NULL))
	{
		printf("UtilsTimeAdded input error/n");
		return 0;
	}
	if((*tt1).usec + (*tt2).usec >= MILLION)
	{
		(*tt1).sec = (*tt1).sec + (*tt2).sec + 1;	// add the sec part of the paramater to the sec part of the object
		(*tt1).usec = (*tt1).usec + (*tt2).usec - MILLION;	// add the usec part of the paramater to the usec part of the object
	}
	else
	{
		(*tt1).sec = (*tt1).sec + (*tt2).sec;
		(*tt1).usec = (*tt1).usec + (*tt2).usec;
		// add the sec part of the paramater to the sec part of the object
		// add the usec part of the paramater to the usec part of the object
	}
	return 1;

}


/**
* This program is to overload the operator -=,with a UtilsTime paramater.
*
* @param t   the UtilsTime to be added to the objext
* @return    self object
*/
int UtilsTimeSubstracted(UtilscTimePtr tt1, UtilscTimePtr tt2) 
{
	if(((*tt1).sec < (*tt2).sec) || (((*tt1).sec == (*tt2).sec) && ((*tt1).usec < (*tt2).usec)))
	{
		printf("Invalid parameter.\n");
		return 0;
	}
	if((*tt1).usec < (*tt2).usec)
	{
		(*tt1).sec = (*tt1).sec - (*tt2).sec - 1; 
		(*tt1).usec = (*tt1).usec - (*tt2).usec + MILLION;
	}
	else
	{	
		(*tt1).sec = (*tt1).sec - (*tt2).sec; 
		(*tt1).usec = (*tt1).usec - (*tt2).usec ;
	}
	return 1;
}

/**
* This program is to output UtilsTime object in a format.
*/
/*int Utilsprint(UtilscTimePtr getted_time, const char* tag, unsigned int looptime)
{
	unsigned long long time_usec = 0;
	float time_msec = 0;

	if(!tag || looptime == 0)
	{
		printf("Invalid parameter.\n");
		return 0;
	}

	time_usec = Utilsgetuseconds(getted_time);

	if(time_usec==0)
	{
		printf("Error:time_usec==0\n");
		return 0;
	}

	time_msec = time_usec/1000.0;

	if(looptime == 1)
	{
		printf("[%s] time is %.3lf ms\n", tag, time_msec);
	}	
	else 
	{
		printf("[%s] %u loops in %.3lf ms, average time is %.3lf ms\n", tag, looptime, time_msec, time_msec/looptime);
	}
	return 1;
}*/

/*int Utilssprint(UtilscTimePtr getted_time,char *address, const char *tag, unsigned int looptime)
{
	
	if(!address || !tag || looptime == 0)
	{
		printf("Invalid parameter.\n");
		return 0;
	}
	if(looptime == 1)
	{
		return sprintf(address,"[%s] time is %.3lf ms<br>",tag, Utilsgetuseconds(getted_time)/1000.0f);
	}	
	else 
	{	
		return sprintf(address,"[%s] %u loops in %.3lf ms, average time is %.3lf ms<br>", tag, looptime, Utilsgetuseconds(getted_time)/1000.0f, Utilsgetuseconds(getted_time)/1000.0f/looptime);
	}
}*/


/*void Utilsprintn(UtilscTimePtr getted_time,const char* tag, unsigned int n)  
{	
	printf("[%s][%u] time is %.3lf ms\n", tag, n, Utilsgetuseconds(getted_time)/1000.0f);
	
}*/

/*int Utilssprintn(UtilscTimePtr getted_time, char *address, const char* tag, unsigned int n)  
{
	return sprintf(address,"[%s][%u] time is %.3lf ms\n", tag, n, Utilsgetuseconds(getted_time)/1000.0f);

}
*/
/*
void UtilsPrintData(const char *title, const void *data, unsigned int size, unsigned int offset)
{

#if 0
	if (!data || !size)
	{
		return;
	}

	printf("%s[%d]{%d-%d}:\n", title, size, offset, offset + size - 1);
	PRINT_LINE;
	printf("   ADDR                          HEX                            DATA      \n");
	PRINT_LINE;

	int i, j, iterator;
	int row = (size + 15) >> 4, col = (size) & 15;
	for (i = 0; i < row; i++)
	{
		printf("0x%08X:      ", (unsigned int)data + offset + (i << 4));
		for (j = 0; j < ((i == row - 1) ? (((col == 0) ? 16 : col)) : (16)); j++)
		{
			if (j && !(j & 3))
			{
				printf(" ");
			}
			iterator = ((unsigned char*)data)[(i << 4) + j + offset];
			printf("%02X", iterator);
		}
		printf("%*c", 6, 0x20);

		if (i == row - 1 && col)
		{
			printf("%*c", 36 - (col << 1) - ((col + 3) >> 2), 0x20);
		}

		for (j = 0; j < ((i == row - 1) ? (((col == 0) ? 16 : col)) : (16)); j++)
		{
			iterator = ((unsigned char*)data)[(i << 4) + j + offset];

			printf("%c", ((iterator >= 0x20 && iterator <= 0x80)? iterator : 0x2E));
		}
		printf("\n");
	}
	PRINT_LINE;
#endif
	if (!data || !size)
	{
		return;
	}
	printf("%s[%d]{%d-%d}:\n", title, size, offset, offset + size - 1);
	printf("--------------------------------------------------------------------------\n");

	printf("   ADDR                          HEX                            DATA      \n");
	printf("--------------------------------------------------------------------------\n");

	int i, j, iterator;
	int row = (size + 15) >> 4, col = (size) & 15;
	for (i = 0; i < row; ++i)
	{
		printf("0x%08X:      ", *(unsigned int*)&data + offset + (i << 4));
		for (j = 0; j < ((i == row - 1) ? (((col == 0) ? 16 : col)) : (16)); ++j)
		{
			if (j && !(j & 3))
			{
				printf(" ");
			}
			iterator = ((unsigned char*)data)[(i << 4) + j + offset];
			printf("%02X", iterator);
		}
		printf("%*c", 6, 0x20);
		if (i == row - 1 && col)
		{
			printf("%*c", 36 - (col << 1) - ((col + 3) >> 2), 0x20);
		}
		for (j = 0; j < ((i == row - 1) ? (((col == 0) ? 16 : col)) : (16)); ++j)
		{
			iterator = ((unsigned char*)data)[(i << 4) + j + offset];
			printf("%c", ((iterator >= 0x20 && iterator <= 0x80)? iterator : 0x2E));
		}
		printf("\n");
	}
	printf("--------------------------------------------------------------------------\n");

}

char c2b(char m, unsigned char* n)
{
	//0x30 - 0x39 0x41 - 0x46 0x61 - 0x66
	if (m < 0x30 || (m > 0x39 && m < 0x41) || (m > 0x46 && m < 0x61) || m > 0x66)
	{
		return -1;
	}
	if (m >= 0x30 && m <= 0x39)
	{
		*n = m - 0x30;
	}
	else if (m >= 0x41 && m <= 0x46)
	{
		*n = m - 0x37;
	}
	else
	{
		*n = m - 0x57;
	}
	return 0;

}*/
/*
char UtilsStr2Byte(const char *str, char *hex) //hexlen = strlen / 2
{
	char *trimstr = (char*)malloc(strlen(str) + 1);
	if(NULL == trimstr)
	{
		return -1;
	}
	char *temp = trimstr;
	memset(trimstr, 0, strlen(str) + 1);
	while (*str != '\0')
	{
		if (*str != ' ')
		{
			*temp++ = *str;
		}
		++str;
	}
	*temp = '\0';

	unsigned int strlens = strlen(trimstr);
	if (!strlens || (strlens & 1))
	{
		free(trimstr);
		trimstr = NULL;
		return -1;
	}
	int i = 0;
	unsigned char x = 0, y = 0;
	for (i = 0; i < strlens; i += 2)
	{
		if (c2b(trimstr[i], &x) || c2b(trimstr[i + 1], &y))
		{
			if (trimstr)
			{
				free(trimstr);
				trimstr = NULL;
			}
			return -2;
		}
		hex[i >> 1] = (x << 4) + y;
		//if (i == 0)
		//{
		//	printf("unsigned char Data[%u] = {\n0x%02X", strlens >> 1, (unsigned char)hex[i >> 1]);
		//}
		//else
		//{
		//	printf(",0x%02X", (unsigned char)hex[i >> 1]);
		//}
	}
	//printf("\n};\n");
	if (trimstr)
	{
		free(trimstr);
		trimstr = NULL;
	}
	return 0;
}
*/


