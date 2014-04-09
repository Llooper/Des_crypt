#include<iostream>
#include<string.h>
#include<stdio.h>
using namespace std;
class DES
{
private:
  bool sub_key[16][48];		//16������Կ
	bool bcryptedmsg[64];			 //����
	bool bdecipher[64];				//���ܵĽ��
  //l0 r0�м����
  bool rmsgi[32], lmsgi[32];			//��i�� Li, Ri
  bool rmsgi1[32], lmsgi1[32];		//��i+1��

private:
  const static int IP_Table[64];     //��ʼֵ��ip
  const static int C0[28];          //����Կ ,�û�ѡ��1
  const static int D0[28];
  const static int KEY_MOVE[16];	//ѭ�����Ʊ�
  const static int CP_Table[48];		//�û�ѡ��2
  const static int E_Table[48];	//���ܺ���, e����  
  const static int S_Box[8][4][16];     //sbox 
  const static int P_Table[32];		//�û�����p 
  const static int IP_1_Table[64];		//���ʼ�û�ip
  //λ����
  const static char bitmask[8];

public:
	bool bmsg[64];		//����
	bool bkey[64];			//��Կ
	  //��������Կ
	  void ProduceSubKey();
	  //�ܵĵļ�������
	  void Crypte();
	  //����
	  void Decipher();
	  //�������
	  void OutPutCryptedMsg();
	  //������ܺ������
	  void OutPutDecipher(); 
private:
  //��ʼ�û�
  void InitSwap(bool in[64]);
  //��ʼ���û�
  void InitReSwap(bool out[64]);
  //ѭ������
  void SubKeyOff(bool* _subkey,int _off);
  //e�����������
  void EOperation(bool a[32],bool b[48]);

  //���XOR����
  //��ͬΪ0 ��ͬΪ1
  void XORoperation(bool a[],bool b[],bool c[],int length);
  //sbox
  void DealSBox(bool in[48],bool out[32]);
  void _DealSBox(bool in[6],bool out[4],int box);
  //p opraration
  void POperation(bool temp[32],bool result[32]);
  //���ܺ���
  void CrypteFunction(bool in[32],int isubkey,bool out[32]);

  //����֮�丳ֵ
  void CopyArray(bool array1[],bool array2[],int size);
};
// ��ʼ�û�IP��
const int  DES::IP_Table[64] = {
	58, 50, 42, 34, 26, 18, 10, 2, 
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1, 
	59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};

//���ʼֵ��IP-1��
const int DES::IP_1_Table[64] =  {
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30, 
	37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26, 
	33, 1, 41,  9, 49, 17, 57, 25
};

//�����û�E��
const int DES::E_Table[48] = {
	32,  1,  2,  3,  4,  5,  
	4,  5,  6,  7,  8,  9, 
	8,  9, 10, 11, 12, 13, 
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21, 
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32,  1
};

//�û�����P��
const int DES::P_Table[32] = {
	16, 7, 20, 21, 29, 12, 28, 17, 
	1,  15, 23, 26, 5,  18, 31, 10,
	2,  8, 24, 14, 32, 27, 3,  9,  
	19, 13, 30, 6,  22, 11, 4,  25
};

//��Կ�û�ѡ��1��
const int  DES::C0[28] = {
	57, 49, 41, 33, 25, 17,  9,  
	1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27, 
	19, 11,  3, 60, 52, 44, 36
};
const int DES::D0[28] = {
	63, 55, 47, 39, 31, 23, 15,  
	7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29, 
	21, 13,  5, 28, 20, 12,  4
};

//��Կ�û�ѡ��2��
const int DES::CP_Table[48] = {
	14, 17, 11, 24,  1,  5,  3, 28, 
	15,  6, 21, 10,  23, 19, 12,  4,
	26,  8, 16,  7,  27, 20, 13,  2,
	41, 52, 31, 37, 47, 55, 30, 40, 
	51, 45, 33, 48, 44, 49, 39, 56, 
	34, 53, 46, 42, 50, 36, 29, 32
};

//ѭ������λ��
const int DES::KEY_MOVE[16] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

//����S��
const int DES::S_Box[8][4][16] = {
		{ //s[1]
			{14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7},
			{ 0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8},
			{ 4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0},
			{15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13}
		},
 		{ //s[2]
			{15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10},
			{ 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5},
			{ 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15},
			{13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9}
 		},
 		{ //S[3]
			{10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8},
			{13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1},
			{13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7},
			{ 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11,5, 2,12}
		},
		{ //S[4]
			{ 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15},
			{13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9},
			{10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4},
			{ 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14}
 		},
		{	//S[5]
			{ 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9},
			{14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6},
			{ 4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14},
			{11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3}
		}, 
		{//	S[6]
			{12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11},
			{10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8},
			{ 9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6},
			{ 4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13}
 		},
		{ //S[7]
			{ 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1},
			{13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6},
			{ 1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2},
			{ 6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12}
		},
		{	//S[8]
			{13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7},
			{ 1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2},
			{ 7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8},
			{ 2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11}
		}
};


//��64λ���Ľ��г��û����������Ϊ�����֣���32λΪl����32λΪr
void DES::InitSwap(bool in[64]) {
	//�����û�
	for (int i = 0; i < 32; i++)
	{
		lmsgi[i]=in[IP_Table[i]-1];                  //L0
		rmsgi[i]=in[IP_Table[i+32]-1];            //R0
	}
};
//��r���������û���E���������õ�x��48λ��
void DES::EOperation(bool r[32], bool x[48]) {
  for (int i = 0; i < 48; i++)
  {
	  x[i]=r[E_Table[i]-1];
  }
};
//����I�ֵ���Կ��x��򣬵õ�y��48λ��
void DES::XORoperation(bool a[], bool x[], bool y[], int length) {
	for (int i = 0; i < length; i++) {
		if (a[i]==x[i])
		{
			y[i]=0;
		}
		else
		{
			y[i]=1;
		}
	}
};

//��y��Ϊ���봩��S�У��õ�z��32λ��
void DES::DealSBox(bool in[48], bool out[32]) { 
	bool recvin[6], sendout[4];
	//8������
	for (int i = 0; i < 8; i++) {
		//��ȡ����
		for (int j = 0; j < 6; j++) {
			recvin[j] = in[ i * 6 + j ];	//����Ӧ��Si���ӵ�6λ�Ž�_in�У�����Ӧ�ĺ��ӽ��д���
		}
		//ѹ��
		_DealSBox(recvin, sendout,  i);		//��_in�е�6λѹ����4λ
		//�Ž�out����
		for (int item = 0; item < 4; item++)
		{
		out[ i * 4 +item ] = sendout[item];
		}
	}
};
void DES::_DealSBox(bool in[6], bool out[4], int box)
{
	int raw, col;
	raw = in[0] * 2 + in[5];	//ת����ʮ���� ��
	col = in[1]*2*2*2 + in[2]*2*2 + in[3]*2 + in[4];		//��
	int result = S_Box[box][raw - 1][col - 1];
  //ת�ɶ�����
	 for (int i = 3; i >= 0; i--)
	{
		out[i]=(result>>(3  - i)) & 1;            //10���������Ƶõ�2������
	}
};
//��ѹ��֮���z�ٽ���һ���û�p����
void DES::POperation(bool temp[32],bool result[32])
{
	for (int i = 0; i < 32; i++)
	{
		 result[i] = temp[P_Table[i] - 1];
	}
};

//��ʼ���û�����
void DES::InitReSwap(bool out[64])
{
  //��ϳ�64����
	bool temp[64];
	for (int i = 0; i < 32; i++)
	{
		 temp[i] = rmsgi[i];
		 temp[32 + i] = lmsgi[i];
	}
  //������ip����
	 for (int i = 0; i < 64; i++)
	{
			out[i] = temp[IP_1_Table[i] - 1];
	}
};

//ѭ������
void DES::SubKeyOff(bool* _subkey, int _off)
{
  //��û�и��õİ취???
		bool temp;
		for (int i = 0; i < _off; i++)
		{
			 temp = _subkey[0];
			for (int i = 0; i < 27; i++)
			{
				 _subkey[i] = _subkey[i+1];
			}
			_subkey[27] = temp;
		}
};

//��������Կ
void DES::ProduceSubKey()
{
  //�û�ѡ��1
	bool ctemp[28], dtemp[28];
	for (int i = 0; i < 28; i++)
	{
		///64λ��Կ��Ϊ56λ
		ctemp[i]=bkey[C0[i] - 1];
		dtemp[i]=bkey[D0[i] - 1];
	 }
	bool keytemp[56];
	for (int i = 0; i < 16; i++)
	{
    //ѭ������
		 SubKeyOff(ctemp, KEY_MOVE[i]);
		 SubKeyOff(dtemp, KEY_MOVE[i]);
    //�ϲ���һ��56����
		 for (int j = 0; j <28; j++)
		{

			keytemp[j] = ctemp[j];
			keytemp[28 + j] = dtemp[j];
		}
    //�û�ѡ��2
		for (int j = 0; j < 48; j++)
		{
			sub_key[i][j] = keytemp[CP_Table[j] - 1];
		}
	 }
};

//���ܺ���
//Isub_key�����õ�i������Կ����
void DES::CrypteFunction(bool in[32], int Isub_key, bool out[32])
{
  //�Դ�������32λ���Ľ��������û� E ����
	bool temp1[48];
	EOperation(in, temp1);

	//����һ������õ���48λ�������i����Կ����������
	bool temp2[48];
	XORoperation(temp1, (bool *)sub_key[Isub_key], temp2, 48); 

  //����ѹ��
	bool temp3[48];
	DealSBox(temp2,temp3);

  //�û�����p
	POperation(temp3,out);

};

// des��������
void DES::Crypte()
{
	bool temp1[32], temp2[32];
  //��ʼ�û�ip
	InitSwap(bmsg);
  //16�ֵ���
	for (int i = 0; i < 16; i++)
	{
		if (i%2 == 0 )
		{
			//L1=R0
			CopyArray(rmsgi, lmsgi1, 32);
			//f(R0, k0)
			CrypteFunction(rmsgi, i,  temp1);
			//L0+f(R0, k0)
			XORoperation(lmsgi, temp1, temp2, 32);
			//R1=L0+f(R0,k0)
			CopyArray(temp2,rmsgi1,32);
		}
		else
		{
			//L2=R1
			CopyArray(rmsgi1, lmsgi, 32);
			//f(R1,k1)
			CrypteFunction(rmsgi1, i, temp1);
			//L1+f(R1,k1)
			XORoperation(lmsgi1, temp1, temp2, 32);
			//R2=L1+f(R1,k1)
			CopyArray(temp2, rmsgi, 32);
		 }
	 }

	//���ʼ�û�ip
	InitReSwap(bcryptedmsg);
};

//����
//ok
void DES::Decipher()
{
	bool temp1[32], temp2[32];
	//��ʼ�û�ip
	InitSwap(bcryptedmsg);
	//16�ֵ�������

	for (int i = 0; i < 16; i++)
	{
		if (i%2==0)
		{
			//L1=R0
			CopyArray(rmsgi, lmsgi1, 32);
			//f(R0,k0)
			CrypteFunction(rmsgi, 15-i, temp1);
		  //L0+f(R0,k0)
			XORoperation(lmsgi, temp1, temp2, 32);
			//R1=L0+f(R0,k0)
			 CopyArray(temp2,rmsgi1,32);
		}
		else
		{
				//L2=R1
			  CopyArray(rmsgi1, lmsgi, 32);
			  //f(R1,k1)
			  CrypteFunction(rmsgi1, 15-i, temp1);
			  //L1+f(R1,k1)
			  XORoperation(lmsgi1, temp1, temp2, 32);
			  //R2=L1+f(R1,k1)
			  CopyArray(temp2, rmsgi, 32);
		}
	}
	//���ʼ�û�ip
	InitReSwap(bdecipher);
};
  //���鸳ֵ
void DES::CopyArray(bool content[], bool empty[], int size) 
{
	for (int i = 0; i < size; i++)
	{
		empty[i]=content[i];
	}
};
//�������
void DES::OutPutCryptedMsg()
{
  cout<<endl<<"����:"<<endl;;
  for (int i = 0; i < 64; i++)
  {
    cout<<bcryptedmsg[i];
  }
};

//�����������

void DES::OutPutDecipher()
{
  cout<<endl<<"����:"<<endl;;
  for (int i = 0; i < 64; i++)
  {
    cout<<bdecipher[i];
  }
  cout<<endl;
};
int main() 
{
	int key[64] = {
		0, 0, 0, 0, 0, 0, 1, 0,
		1, 0, 0, 1, 0, 1, 1, 0,
		0, 1, 0, 0, 1, 0, 0, 0,
		1, 1, 0, 0, 0, 1, 0, 0,
		0, 0, 1, 1, 1, 0, 0, 0,
		0, 0, 1, 1, 0, 0, 0, 0,
		0, 0, 1, 1, 1, 0, 0, 0,
		0, 1, 1, 0, 0, 1, 0, 0
	};
	int msg1[64] = {
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0
	};
	int msg2[64] = {
		1, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0
	};

	int key1[64] = {
		1,1,1,0,0,0,1,0,
		1,1,1,1,0,1,1,0,
		1,1,0,1,1,1,1,0,
		0,0,1,1,0,0,0,0,
		0,0,1,1,1,0,1,0,
		0,1,1,0,0,0,1,0,
		1,1,0,1,1,1,0,0
	};
	int key2[64] = {
		0,1,1,0,0,0,1,0,
		1,1,1,1,0,1,1,0,
		1,1,0,1,1,1,1,0,
		0,0,1,1,0,0,0,0,
		0,0,1,1,1,0,1,0,
		0,1,1,0,0,0,1,0,
		1,1,0,1,1,1,0,0
	};
	int msg[64] = {
		0,1,1,0,1,0,0,0,
		1,0,0,0,0,1,0,1,
		0,0,1,0,1,1,1,1,
		0,1,1,1,1,0,1,0,
		0,0,0,1,0,0,1,1,
		0,1,1,1,0,1,1,0,
		1,1,1,0,1,0,1,1,
		1,0,1,0,0,1,0,0
	};
	int item;
	DES des;
	for(int i = 0; i < 2; i++){
		int temp;
		cout<<"ѡ�����ģʽ��\n��1Ϊͬһ��Կ���ܲ�ͬ���ĶΣ�\n��2Ϊ��ͬ��Կ����ͬһ���ĶΣ���";
		cin>>temp;
		if(temp == 1) {
			cout<<"ѡ����Ҫ���ܵ����ĶΣ�1 ���� 2����";
			for(int i = 0 ; i < 2; i++) {
				cin>>item;
				if(item == 1) {
					cout<<"���Ķ�1��"<<endl;
					for(int i = 0; i < 64; i++) {
						cout<<msg1[i]<<" ";
					}
					cout<<endl;
					cout<<"��Կ��"<<endl;
					for(int i = 0; i < 64; i++) {
						cout<<key[i]<<" ";
					}
					for(int i = 0; i  < 64; i++) {
						des.bmsg[i] = msg1[i];
						des.bkey[i] = key[i];
					}
				}
			else {
				cout<<"���Ķ�2��"<<endl;
				for(int i = 0; i < 64; i++) {
					cout<<msg2[i]<<" ";
				}
				cout<<endl;
				cout<<"��Կ��"<<endl;
					for(int i = 0; i < 64; i++) {
						cout<<key[i]<<" ";
					}
				for(int i = 0; i  < 64; i++) {
					des.bmsg[i] = msg2[i];
					des.bkey[i] = key[i];
				}
			}	
			des.ProduceSubKey();
			des.Crypte();       //����
			 des.OutPutCryptedMsg();  //�������

			 des.Decipher();   //����
			 des.OutPutDecipher();    //���ܺ������
			 if(i == 0)
				 cout<<"ѡ����Ҫ���ܵ����Ŀ飨1 ���� 2����";
			}
		}  //if
		else {
			cout<<"ѡ����Ҫʹ�õ���Կ��1 ���� 2����";
			for(int i = 0 ; i < 2; i++) {
				cin>>item;
				if(item == 1) {
					cout<<"���ĶΣ�"<<endl;
					for(int i = 0; i < 64; i++) {
						cout<<msg[i]<<" ";
					}
					cout<<endl;
					cout<<"��Կ1��"<<endl;
					for(int i = 0; i < 64; i++) {
						cout<<key1[i]<<" ";
					}
					for(int i = 0; i  < 64; i++) {
						des.bmsg[i] = msg[i];
						des.bkey[i] = key1[i];
					}
				}
				else {
					cout<<"���ĶΣ�"<<endl;
					for(int i = 0; i < 64; i++) {
						cout<<msg[i]<<" ";
					}
					cout<<endl;
					cout<<"��Կ2��"<<endl;
					for(int i = 0; i < 64; i++) {
						cout<<key2[i]<<" ";
					}
					for(int i = 0; i  < 64; i++) {
						des.bmsg[i] = msg[i];
						des.bkey[i] = key2[i];
					}
				}	
				des.ProduceSubKey();
				des.Crypte();       //����
				 des.OutPutCryptedMsg();  //�������

				 des.Decipher();   //����
				 des.OutPutDecipher();    //���ܺ������
				 if(i == 0)
					 cout<<"ѡ����Ҫʹ�õ���Կ��1 ���� 2����";
			}
		}
	} //for
	system("pause");
	return 0;
}

