#include <stdio.h>
#include "miracl.h"
#include"SM2_sign.h"

void test_SM2_sign()
{
	unsigned char pubx_char[32], puby_char[32],ZA[32];
	unsigned char r[32], s[32];//ǩ��
	const unsigned char* message = "be there or be square!";
	big d,pubx,puby;  //˽Կ
	epoint* pub;//��Կ
	
	SM2_init();//����ʼ����Բ���߲���
	SM2_creat_key(&d, &pub);

	//��ȡ��Կpub�е�pubx,puby
	pubx = mirvar(0);
	puby = mirvar(0);
	epoint_get(pub, pubx, puby);
	big_to_bytes(32, pubx, pubx_char, TRUE);
	big_to_bytes(32, puby, puby_char, TRUE);
	
	SM2_ZA(pubx_char, puby_char, ZA);

	SM2_sign(message,strlen(message),ZA,d,r,s);

	SM2_verify(message, strlen(message), ZA, pubx_char, puby_char, r, s);
	
}