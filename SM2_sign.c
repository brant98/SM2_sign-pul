#include <stdio.h>
#include <time.h>
#include "miracl.h"

// ECC椭圆曲线参数（SM2标准推荐参数）
static unsigned char SM2_p[32] = {
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static unsigned char SM2_a[32] = {
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC };
static unsigned char SM2_b[32] = {
	0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
	0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93 };
static unsigned char SM2_n[32] = {
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B, 0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23 };
static unsigned char SM2_Gx[32] = {
	0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
	0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7 };
static unsigned char SM2_Gy[32] = {
	0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
	0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0 };
static unsigned char SM2_h[32] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

big para_p, para_a, para_b, para_n, para_Gx, para_Gy, para_h;
epoint* G;
miracl* mip;
/*
功能：SM2签名算法椭圆曲线参数初始化
输入：无
输出：无
返回：0失败  1成功
*/
int SM2_init(void)
{
	epoint* nG;
	mip = mirsys(10000, 16);
	mip->IOBASE = 16;
	para_p = mirvar(0);
	para_a = mirvar(0);
	para_b = mirvar(0);
	para_n = mirvar(0);
	para_Gx = mirvar(0);
	para_Gy = mirvar(0);
	para_h = mirvar(0);

	G = epoint_init();
	nG = epoint_init();

	bytes_to_big(32, SM2_p, para_p);  // 32=256/8
	bytes_to_big(32, SM2_a, para_a);
	bytes_to_big(32, SM2_b, para_b);
	bytes_to_big(32, SM2_n, para_n);
	bytes_to_big(32, SM2_Gx, para_Gx);
	bytes_to_big(32, SM2_Gy, para_Gy);
	//bytes_to_big(256, SM2_h, para_h);

	/*Initialises GF(p) elliptic curve.(MR_PROJECTIVE specifying projective coordinates)*/
	ecurve_init(para_a, para_b, para_p, MR_PROJECTIVE);

	/*initialise point G*/
	if (!epoint_set(para_Gx, para_Gy, 0, G))
		return 0;

	ecurve_mult(para_n, G, nG);

	/*test if the order of the point is n*/
	if (!point_at_infinity(nG))
		return 0;
	printf("Init successed!\n");
	return 1;             //成功运行到最后则返回1.若返回的是0则表示初始化不正确
}
int isInRange(big num) //判断d是否在规定范围内  1至n-1的闭区间
{
	big one, decr_n;

	one = mirvar(0);
	decr_n = mirvar(0);

	convert(1, one);
	decr(para_n, 1, decr_n);

	if ((mr_compare(num, one) > 0) && (mr_compare(num, decr_n) < 0))//compare(x,y)  x>y +1   x=y 0  x<y -1
		return 1;//返回1表示在适合范围
	return 0;//返回0表示不在适合的范围
}
int SM2_creat_key(big* d, epoint** pub)
{
	big temp = mirvar(0);
	copy(para_n, temp);
	*d = mirvar(0);
	*pub = epoint_init();
	irand(time(NULL));
	bigrand(temp, *d);  // d私钥 d应在1至n-2之间，包括两端
	while (isInRange(*d) != 1)
	{
		bigrand(temp, *d);
	}
	ecurve_mult(*d, G, *pub);//pub中存放公钥
	printf("creat key done!\n");
	return 1; //成功返回1
}
//计算ZA：关于用户A的可辨别标识、部分椭圆曲线系统参数和用户A公钥的杂凑值。
/*
	功能：计算ZA
	输入：基点Gx,Gy   公钥pubx,puby
	输出：ZA[]
	返回：无
*/
void SM2_ZA(unsigned char pubx[], unsigned char puby[], unsigned char ZA[])
{
	unsigned char ENTLA[2] = { 0x00, 0x80 }; //签名者的具有长度为entlenA比特的可辨别标识IDA，记ENTLA是由整数entlenA转换而成的两个字节
	unsigned char IDA[16] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };//签名者的用户标识
	unsigned char Msg[210];	//210 = size of IDA + 2 + 32 * 6(a,b,Gx,Gy,pubx,puby)  =210字节

	//ZA = Hash(ENTLA || IDA || a || b || Gx || Gy || xpub|| ypub)
	memcpy(Msg, ENTLA, 2);
	memcpy(Msg + 2, IDA, sizeof(IDA));
	memcpy(Msg + 2 + sizeof(IDA), SM2_a, 32);
	memcpy(Msg + 2 + sizeof(IDA) + 32, SM2_b, 32);
	memcpy(Msg + 2 + sizeof(IDA) + 32 * 2, SM2_Gx, 32);
	memcpy(Msg + 2 + sizeof(IDA) + 32 * 3, SM2_Gy, 32);
	memcpy(Msg + 2 + sizeof(IDA) + 32 * 4, pubx, 32);
	memcpy(Msg + 2 + sizeof(IDA) + 32 * 5, puby, 32);
	//此处使用的是hash256,当然最标准的应该是使用SM3进行杂凑
	sha256 sha_256;
	shs256_init(&sha_256);
	for (int i = 0; i < 210; i++)
	{
		shs256_process(&sha_256, Msg[i]);
	}
	shs256_hash(&sha_256, ZA);
	printf("ZA done!\n");
}

/*
	功能：私钥签名
	输入：message消息、len消息长度、ZA预处理值、rand随机数、d私钥
	输出：R签名R部分、S签名S部分
	返回：!0成功   0失败
*/
int SM2_sign(unsigned char* message, int len, unsigned char ZA[], big d, unsigned char R[], unsigned char S[])
{
	unsigned char hash[32];
	int M_len = len + 32;
	unsigned char* M = NULL;
	big r, s, e, k, KGx, KGy, zero;
	big rem, rk, z1, z2;
	epoint* KG;
	//initiate
	zero = mirvar(0);
	e = mirvar(0);
	k = mirvar(0);
	KGx = mirvar(0);
	KGy = mirvar(0);
	r = mirvar(0);
	s = mirvar(0);
	rem = mirvar(0);
	rk = mirvar(0);
	z1 = mirvar(0);
	z2 = mirvar(0);

	KG = epoint_init();
	//step1, set M' = ZA || M
	M = (char*)malloc(sizeof(char) * (M_len + 1));
	memcpy(M, ZA, 32);
	memcpy(M + 32, message, len);

	//step2, generate e = H(M)
	//此处使用的是hash256,当然最标准的应该使用SM3进行杂凑,      此处可能存在大问题哈！
	sha256 sha_256;
	shs256_init(&sha_256);
	for (int i = 0; M[i]!=0; i++)
	{
		shs256_process(&sha_256, M[i]);
	}
	shs256_hash(&sha_256, hash);
	bytes_to_big(32, hash, e);
	
	//step3:generate k 在1至n-1的双侧闭区间
	irand(time(NULL));
	bigrand(para_n, k);  // d私钥 d应在1至n-2之间，包括两端
	while (isInRange(k) != 1)
	{
		bigrand(para_n, k);
	}

	//step4:calculate kG
	ecurve_mult(k, G, KG);

	//step5:calculate r
	epoint_get(KG, KGx, KGy);
	add(e, KGx, r);
	divide(r, para_n, rem);

	//judge r = 0 or n + k = n?
	add(r, k, rk);
	if ((mr_compare(r, zero) == 0) || (mr_compare(rk, para_n) == 0))
	{
		printf("Wrong in Generating r!");
			return 0;
	}

	//step6:generate s
	incr(d, 1, z1);
		xgcd(z1, para_n, z1, z1, z1);
		multiply(r, d, z2);
		divide(z2, para_n, rem);
		subtract(k, z2, z2);
	add(z2, para_n, z2);
	multiply(z1, z2, s);
	divide(s, para_n, rem);

	//judge s = 0?
	if (mr_compare(s, zero) == 0)
	{
		printf("Wrong in generating s!");
		return 0;
	}

	big_to_bytes(32, r, R, TRUE);
	big_to_bytes(32, s, S, TRUE);

	free(M);
	printf("sign done!\n");
	return 1;
}

/*
	功能：公钥验证签名
	输入：message消息、len消息长度、ZA预处理值、Px公钥Gx、Py公钥Gy、R签名R部分、S签名S部分
	输出：无
	返回：0成功 !0失败
*/
int SM2_verify(unsigned char* message, int len, unsigned char ZA[], unsigned char pubx[], unsigned char puby[], unsigned char R[], unsigned char S[])
{
	unsigned char hash[32];
	int M_len = len + 32;
	unsigned char* M = NULL;
	big PAx, PAy, r, s, e, t, rem, x1, y1,zero;
	big RR;
	epoint* PA, * sG, * tPA;

	PAx = mirvar(0);
	PAy = mirvar(0);
	r = mirvar(0);
	s = mirvar(0);
	e = mirvar(0);
	t = mirvar(0);
	x1 = mirvar(0);
	y1 = mirvar(0);
	rem = mirvar(0);
	RR = mirvar(0);
	zero = mirvar(0);

	PA = epoint_init();
	sG = epoint_init();
	tPA = epoint_init();

	bytes_to_big(32, pubx, PAx);
	bytes_to_big(32, puby, PAy);

	bytes_to_big(32, R, r);
	bytes_to_big(32, S, s);

	//initialise public key
	if (!epoint_set(PAx, PAy, 0, PA)) 
		return 0;

	//step1: test if r belong to [1, n-1]
	if (isInRange(r)==0)
		return 0;

	//step2: test if s belong to [1, n-1]
	if (isInRange(s)==0)
	{
		printf("s is not in the range!\n");
		return 0;
	}

	//step3, generate M
	M = (char*)malloc(sizeof(char) * (M_len + 1));
	memcpy(M, ZA, 32);
	memcpy(M + 32, message, len);

	//step4, generate e = H(M)
	//此处使用的是hash256,当然最标准的应该使用SM3进行杂凑
	sha256 sha_256;
	shs256_init(&sha_256);
	for (int i = 0; M[i]!=0; i++)
	{
		shs256_process(&sha_256, M[i]);
	}
	shs256_hash(&sha_256, hash);
	bytes_to_big(32, hash, e);
	//step5:generate t
	add(r, s, t);
	divide(t, para_n, rem);

	if (mr_compare(t,zero)==0) 
		return 0;

	//step 6: generate(x1, y1)
	ecurve_mult(s, G, sG);
	ecurve_mult(t, PA, tPA);
	ecurve_add(sG, tPA);
	epoint_get(tPA, x1, y1);

	//step7:generate RR
	add(e, x1, RR);
	divide(RR, para_n, rem);
	free(M);

	if (0 == mr_compare(RR, r))
	{
		printf("After verifying,the signature is belong to Alice!\n");
	}
	else
	{
		printf("WRONG!The message is not from Alice!\n");
	}
	return 0;
}