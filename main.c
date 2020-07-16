#include <stdio.h>
#include "miracl.h"
#include"SM2_sign.h"
#include"test_SM2_sign.h"
int main(void)
{
	test_SM2_sign();
	printf("\nmain end!\n");
	return 0;
}