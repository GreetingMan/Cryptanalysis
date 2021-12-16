/*=====================================================================================================================
Name: The distinguish test of ALLPC (preprint version on IEEE IoTJ, DOI 10.1109/JIOT.2021.3126317)

-This is a test of differential-type distinguish of ALLPC, we use a full 25-round differential trail 

  \alpha-->\beta: 0x00 00 99 99 99 00 99 00--->0x00 99 00 00 99 99 99 00  (holds with probability 2^{-24})

-We randomly choose 2^{30} of pairs of plaintext (P,P') satisfying P XOR P' = \alpha, then the expected number of 
ALLPC(P) XOR ALLPC(P') = \beta is about 64, which is much higher than the random case.
 
-We follow the basic definition of ALLPC to make the program more clear, at the cost of dragging down the speed. 

-This program can be executed within about 10 mins on a personal workshop.
 
Date: 2021-12-09

By: Ting Cui

Email: cuiting_1209@hotmail.com
=======================================================================================================================*/
# include "stdio.h"
# include "stdlib.h"
# include "time.h"


unsigned char F(unsigned char rkey, unsigned char X)// F function of ALLPC as defined.
{
	static unsigned char S[16]={0xe,0x4,0xb,0x1, 0x7, 0x9, 0xc, 0xa,0xd, 0x2, 0x0, 0xf, 0x8, 0x5, 0x3, 0x6};
	unsigned char Y;
	Y=X^rkey;
	Y=(S[Y&0xf]<<4)^(S[(Y>>4)&0xf]);
	return(Y);
}


void roundKeyGenerator(unsigned _int64 key[2], unsigned char rkey[25][4])
// extract round keys for the main key, the key schedule seems make no affect the distinguisher.
{
	static unsigned char S[16]={0xe,0x4,0xb,0x1, 0x7, 0x9, 0xc, 0xa,0xd, 0x2, 0x0, 0xf, 0x8, 0x5, 0x3, 0x6};

	unsigned _int64 i;

	unsigned _int64 temp0,temp1;
	unsigned char sValue=0;

	for(i=0;i<25;i++)
	{
		rkey[i][3]=key[0]&0xff;
		rkey[i][2]=(key[0]>>8)&0xff;
		rkey[i][1]=(key[0]>>16)&0xff;
		rkey[i][0]=(key[0]>>24)&0xff;

		temp0=(key[0]>>51);
		temp1=(key[1]>>51);

		key[0]=(key[0]<<13)^temp1;
		key[1]=(key[1]<<13)^temp0;//left rotation 13

		sValue=key[0]&0xff;
		
		key[0]^=sValue;

		sValue=(S[(sValue>>4)&0xf]<<4)^(S[sValue&0xf]);//S-box operation

		key[0]^=sValue;
	
		key[0]^=(i<<59);// round constant added

	}

} 




void fullRoundALLPCEncrypt(unsigned char rkey[25][4], unsigned char pltx[8])
{
	int temp;
	int i;
	for(i=0;i<24;i++)
	{
		pltx[7]=	pltx[7] ^ F(rkey[i][0],pltx[0]);
		pltx[7]=	pltx[7]  ^	pltx[1]^	pltx[2]^	pltx[3];
		pltx[6]=	pltx[6]  ^	pltx[3]^	rkey[i][1];
		pltx[5]=	pltx[5]  ^	pltx[3]^	rkey[i][2];
		pltx[4]=	pltx[4]  ^	pltx[3]^	rkey[i][3];

        temp=pltx[0];

		pltx[0]=pltx[2];
		pltx[2]=pltx[4];
		pltx[4]=pltx[6];
		pltx[6]=pltx[7];
		pltx[7]=pltx[1];
		pltx[1]=pltx[3];
		pltx[3]=pltx[5];
		pltx[5]=temp;

	}//0-23 round
	{
		pltx[7]=	pltx[7] ^ F(rkey[i][0],pltx[0]);
		pltx[7]=	pltx[7]  ^	pltx[1]^	pltx[2]^	pltx[3];
		pltx[6]=	pltx[6]  ^	pltx[3]^	rkey[i][1];
		pltx[5]=	pltx[5]  ^	pltx[3]^	rkey[i][2];
		pltx[4]=	pltx[4]  ^	pltx[3]^	rkey[i][3];
	}//24-th round

}




void differentialDistinguisherTest()
{
	unsigned _int64 key[2]={0x2718281828459045, 0x2353602874713526};// the constant e
	unsigned char rkey[25][4];
	
	unsigned char pltx[8]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};//one plaintext
	unsigned char pltx1[8]={0};//another plaintext
	unsigned char inputDifference[8]={0x00,0x99,0x00,0x99,0x99,0x99,0x00,0x00};	//0x00 00 99 99 99 00 99 00--->0x00 99 00 00 99 99 99 00
	unsigned char outputDifference[8]={0x00,0x99,0x99,0x99,0x00,0x00,0x99,0x00};

	roundKeyGenerator(key, rkey);

	int counter=0;
	unsigned _int32 T=1<<30;
	int i,j;

	FILE *fp;
	fp=fopen("the result.txt","wr");

	time_t t1,t2;

	t1=time(NULL);
	for(i=0;i<T;i++)//T=1<<30 times of encryption
	{
	
		for(j=0;j<8;j++)   { pltx1[j]=pltx[j]^inputDifference[j];}
		fullRoundALLPCEncrypt(rkey, pltx);
		fullRoundALLPCEncrypt(rkey, pltx1);

		for(j=0;j<8;j++)
		{
			if((pltx[j]^pltx1[j])!=outputDifference[j])
				goto L1;
		}

		counter++;
		L1:;
	}
	t2=time(NULL);
	fprintf(fp,"There are %d/2^30 pairs of plaintexts satisfy our differential\n",counter);
	fprintf(fp,"The distinguish spending %d seconds.\n",t2-t1);
}


void main()
{
	differentialDistinguisherTest();
}