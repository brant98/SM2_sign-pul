#include "miracl.h"


int SM2_init(void);//³õÊ¼»¯
int isInRange(big num);
int SM2_creat_key(big* d, epoint** pub);
void SM2_ZA(unsigned char pubx[], unsigned char puby[], unsigned char ZA[]);
int SM2_sign(unsigned char* message, int len, unsigned char ZA[], big d, unsigned char R[], unsigned char S[]);
int SM2_verify(unsigned char* message, int len, unsigned char ZA[], unsigned char pubx[], unsigned char puby[], unsigned char R[], unsigned char S[]);
