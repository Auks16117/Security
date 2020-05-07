/*
	使い方：
  1.平文を作る(8bit, 2進数)
	　　ex: 10001011
	2.パスワードを設定する
	　　ex: 235
	3.実行する
	暗号化: cryptofile enc password plain.txt enc1.txt
	復号: cryptofile dec password enc2.txt dec.txt
	*注意*
	password:パスワード(10bit, 10進数表記, 0~1023で設定)
	plain.txt:平文(8bit, ２進数)
	enc1.txt:暗号化した結果(8bit, 2進数)
	enc2.txt:暗号化したテキスト(8bit, 2進数)
	dec.txt:復号した結果(8bit, 2進数)
	出力ファイルは適当に
*/

#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<stdlib.h>
#include<string.h>


// S0
int S0[2][16] = {
	{ 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1 },
	{ 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0 }
};

// S1
int S1[2][16] = {
	{ 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1 },
	{ 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1 }
};

void print(char *c, char *mozi, int len) {
	int i, c_len;
	c_len = strlen(c);
	printf("%s:", c);
	for (i = 0; i < 20 - c_len; i++) {
		printf(" ");
	}
	for (i = 0; i < 10 - len; i++) {
		printf(" ");
	}
	for (i = 0; i < len; i++) {
		printf("%d", mozi[i]);
	}
	printf("\n");
}

// ���̐���
void key_create(char *key, char *key1, char *key2) {
	int i;
	char p10[10], ls_1[10], ls_2[10];

	p10[0] = key[2];
	p10[1] = key[4];
	p10[2] = key[1];
	p10[3] = key[6];
	p10[4] = key[3];
	p10[5] = key[9];
	p10[6] = key[0];
	p10[7] = key[8];
	p10[8] = key[7];
	p10[9] = key[5];

	print("�u��(P10)", p10, 10);

	for (i = 0; i < 10; i++) {
		if (i == 0 || i == 5) {
			ls_1[i + 4] = p10[i];
		}
		else {
			ls_1[i - 1] = p10[i];
		}
	}
	print("�r�b�g�ړ�(LS-1)", ls_1, 10);


	key1[0] = ls_1[5];
	key1[1] = ls_1[2];
	key1[2] = ls_1[6];
	key1[3] = ls_1[3];
	key1[4] = ls_1[7];
	key1[5] = ls_1[4];
	key1[6] = ls_1[9];
	key1[7] = ls_1[8];


	for (i = 0; i < 10; i++) {
		if (i == 0 || i == 1 || i == 5 || i == 6) {
			ls_2[i + 3] = ls_1[i];
		}
		else {
			ls_2[i - 2] = ls_1[i];
		}
	}
	print("�r�b�g�ړ�(LS-2)", ls_2, 10);
	key2[0] = ls_2[5];
	key2[1] = ls_2[2];
	key2[2] = ls_2[6];
	key2[3] = ls_2[3];
	key2[4] = ls_2[7];
	key2[5] = ls_2[4];
	key2[6] = ls_2[9];
	key2[7] = ls_2[8];
}

// �����]�u(IP:Initial Permutation)
void InitialPermutation(char *plain_text, char *ip) {
	ip[0] = plain_text[1];
	ip[1] = plain_text[5];
	ip[2] = plain_text[2];
	ip[3] = plain_text[0];
	ip[4] = plain_text[3];
	ip[5] = plain_text[7];
	ip[6] = plain_text[4];
	ip[7] = plain_text[6];
}

// �����z�u�̔��΂̑���(IP-1)
void InitialPermutationInverse(char *l3, char * r3, char *ipInverse) {
	ipInverse[0] = l3[3];
	ipInverse[1] = l3[0];
	ipInverse[2] = l3[2];
	ipInverse[3] = r3[0];
	ipInverse[4] = r3[2];
	ipInverse[5] = l3[1];
	ipInverse[6] = r3[3];
	ipInverse[7] = r3[1];
}

// �]�u(P4:Permutation)
void Permutation(char *sbox_output, char *p4) {
	p4[0] = sbox_output[1];
	p4[1] = sbox_output[3];
	p4[2] = sbox_output[2];
	p4[3] = sbox_output[0];
}

// �֐�F
void function_f(char *r, char *key, char *p4) {
	int i, input_s0, input_s1;
	char e_p[8], upper_bit[4], under_bit[4], sbox_output[4];

	// �g���]�u (E/P:Expansion Permutation)
	e_p[0] = r[3];
	e_p[1] = r[0];
	e_p[2] = r[1];
	e_p[3] = r[2];
	e_p[4] = r[1];
	e_p[5] = r[2];
	e_p[6] = r[3];
	e_p[7] = r[0];

	print("�g���]�u(E/P)", e_p, 8);

	// XOR����
	for (i = 0; i < 8; i++) {
		e_p[i] = e_p[i] ^ key[i];
	}
	print("XOR", e_p, 8);

	// S0��S1�ɕ�����
	for (i = 3; 0 <= i; i--) {
		upper_bit[i] = e_p[i];
	}

	for (i = 7; 4 <= i; i--) {
		under_bit[i - 4] = e_p[i];
	}

	// S-BOX
	input_s0 = upper_bit[0] * 8 + upper_bit[3] * 4 + upper_bit[1] * 2 + upper_bit[2];
	input_s1 = under_bit[0] * 8 + under_bit[3] * 4 + under_bit[1] * 2 + under_bit[2];

	sbox_output[0] = S0[0][input_s0];
	sbox_output[1] = S0[1][input_s0];
	sbox_output[2] = S1[0][input_s1];
	sbox_output[3] = S1[1][input_s1];
	print("Sbox", sbox_output, 4);
	Permutation(sbox_output, p4);
	print("�]�u(P4)", p4, 4);
}

// XOR�֐�
void xor(char *sbox_output, char *l, char *output) {
	int i;

	for (i = 0; i < 4; i++) {
		output[i] = sbox_output[i] ^ l[i];
	}
}

int main(int argc, char *argv[]){

	int i, password;
	int j = 0;
	char key[10], key1[8], key2[8], l1[4], l2[4], l3[4], r1[4], r2[4], r3[4], ip[8], p4_1[4], p4_2[4];
	char ipInverse[8], mode[4], plain_text[9], chr;
	FILE *inputfile = NULL;
	FILE *outputfile = NULL;

	// �����������Ȃ��Ƃ��͏I������
	if (argc <= 4) {
		printf("�����������܂���\n");
		exit(EXIT_FAILURE);
	}

	// enc��dec�̂ǂ����ł��Ȃ��ꍇ�I������
	memcpy(mode, argv[1], sizeof(argv[1]));
	if (strcmp("enc", mode) != 0 && strcmp("dec", mode) != 0) {
		printf("enc�ł�dec�ł������܂���\n");
		exit(EXIT_FAILURE);
	}

	// ����2�i���ɂ���
	password = atoi(argv[2]);
	for (i = 9; 0 <= i; i--) {
		key[i] = password % 2;
		password = password / 2;
	}

	// ���͗p�t�@�C�����J��
	inputfile = fopen(argv[3], "r");
	if (inputfile == NULL) {
		printf("Couldn't open %s\n", argv[2]);
		exit(EXIT_FAILURE);
	}

	// �e�L�X�g�������o��
	while ((chr = fgetc(inputfile)) != EOF) {
		if (chr == '0') {
			plain_text[j] = 0;
		}
		else {
			plain_text[j] = 1;
		}
		j++;
	}

	// �o�͗p�t�@�C�����J��
	outputfile = fopen(argv[4], "w");
	if (outputfile == NULL) {
		printf("Couldn't open %s\n", argv[3]);
		exit(EXIT_FAILURE);
	}

	if (strcmp("enc", mode) == 0) {
		printf("���[�h: �Í���");
	}
	else {
		printf("���[�h: ������");
	}
	printf("\n");
	print("���͕�", plain_text, 8);
	print("��", key, 10);
	printf("\n");

	printf("-------------���̐���-------------\n");

	// ��1�ƌ�2�𐶐�����
	key_create(key, key1, key2);
	print("K1(P8)", key1, 8);
	print("K2(P8)", key2, 8);


	if (strcmp("enc", mode) == 0) {
		printf("\n-------------�Í���---------------\n");
	}
	else {
		printf("\n-------------������---------------\n");
	}
	InitialPermutation(plain_text, ip);
	print("�����]�u(IP)", ip, 8);

	for (i = 0; i < 4; i++) {
		l1[i] = ip[i];
		r1[i] = ip[i + 4];
	}

	print("L1", l1, 4);
	print("R1", r1, 4);

	// �Í��������Ƃ�
	if (strcmp("enc", mode) == 0) {
		printf("\n      *  �֐�F-1   *\n");
		function_f(r1, key1, p4_1);
		xor (p4_1, l1, r2);
		memcpy(l2, r1, sizeof(r1));
		print("L2", l2, 4);
		print("R2", r2, 4);
		printf("\n      *  �֐�F-2  *\n");
		function_f(r2, key2, p4_2);
		xor (p4_2, l2, l3);
		memcpy(r3, r2, sizeof(r2));
		print("L3", l3, 4);
		print("R3", r3, 4);
		printf("\n\n");
		// IP-1
		InitialPermutationInverse(l3, r3, ipInverse);
		print("�Í���",ipInverse, 8);
	}
	//�@�����������Ƃ�
	else {
		printf("\n      *  �֐�F-1  *\n");
		function_f(r1, key2, p4_1);
		xor (p4_1, l1, r2);
		memcpy(l2, r1, sizeof(r1));
		print("L2", l2, 4);
		print("R2", r2, 4);
		printf("\n      *  �֐�F-2  *\n");
		function_f(r2, key1, p4_2);
		xor (p4_2, l2, l3);
		memcpy(r3, r2, sizeof(r2));
		print("L3", l3, 4);
		print("R3", r3, 4);
		printf("\n\n");
		// IP-1
		InitialPermutationInverse(l3, r3, ipInverse);
		print("���������Í���", ipInverse, 8);
	}

	for (i = 0; i < 8; i++) {
		fprintf(outputfile, "%d" ,ipInverse[i]);
	}
	printf("\n");
	fclose(inputfile);
	fclose(outputfile);

	return 0;
}
