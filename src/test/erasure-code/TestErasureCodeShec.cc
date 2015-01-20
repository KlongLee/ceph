/******************************************************************************

  SUMMARY: TestErasureCodeShec

   COPYRIGHT(C) 2014 FUJITSU LIMITED.

*******************************************************************************/


#include <errno.h>
#include <pthread.h>

#include "crush/CrushWrapper.h"
#include "osd/osd_types.h"

#include "include/stringify.h"
#include "global/global_init.h"
#include "erasure-code/shec/ErasureCodeShec.h"
#include "erasure-code/ErasureCodePlugin.h"
#include "common/ceph_argparse.h"
#include "global/global_context.h"
#include "gtest/gtest.h"

void* thread1(void* pParam);
void* thread2(void* pParam);
void* thread3(void* pParam);
void* thread4(void* pParam);
void* thread5(void* pParam);


TEST(ErasureCodeShec, init_1)
{
	//�S�Đ���l
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["directory"] = "/usr/lib64/ceph/erasure-code";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//�p�����[�^�m�F
	EXPECT_EQ(6u, shec->k);
	EXPECT_EQ(4u, shec->m);
	EXPECT_EQ(3u, shec->c);
	EXPECT_EQ(8u, shec->w);
	EXPECT_STREQ("", shec->technique);
	EXPECT_STREQ("default", shec->ruleset_root.c_str());
	EXPECT_STREQ("osd", shec->ruleset_failure_domain.c_str());
	EXPECT_TRUE(shec->matrix != NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_2)
{
	//�S�Đ���l
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-root"] = "test";
	(*parameters)["ruleset-failure-domain"] = "host";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	(*parameters)["w"] = "8";
	//init���s
	shec->init(*parameters);

	//�p�����[�^�m�F
	EXPECT_EQ(6u, shec->k);
	EXPECT_EQ(4u, shec->m);
	EXPECT_EQ(3u, shec->c);
	EXPECT_EQ(8u, shec->w);
	EXPECT_STREQ("", shec->technique);
	EXPECT_STREQ("test", shec->ruleset_root.c_str());
	EXPECT_STREQ("host", shec->ruleset_failure_domain.c_str());
	EXPECT_TRUE(shec->matrix != NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_3)
{
	//�S�Đ���l
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	(*parameters)["w"] = "16";
	//init���s
	shec->init(*parameters);

	//�p�����[�^�m�F
	EXPECT_EQ(6u, shec->k);
	EXPECT_EQ(4u, shec->m);
	EXPECT_EQ(3u, shec->c);
	EXPECT_EQ(16u, shec->w);
	EXPECT_STREQ("", shec->technique);
	EXPECT_STREQ("default", shec->ruleset_root.c_str());
	EXPECT_STREQ("osd", shec->ruleset_failure_domain.c_str());
	EXPECT_TRUE(shec->matrix != NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_4)
{
	//�S�Đ���l
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	(*parameters)["w"] = "32";
	//init���s
	shec->init(*parameters);

	//�p�����[�^�m�F
	EXPECT_EQ(6u, shec->k);
	EXPECT_EQ(4u, shec->m);
	EXPECT_EQ(3u, shec->c);
	EXPECT_EQ(32u, shec->w);
	EXPECT_STREQ("", shec->technique);
	EXPECT_STREQ("default", shec->ruleset_root.c_str());
	EXPECT_STREQ("osd", shec->ruleset_failure_domain.c_str());
	EXPECT_TRUE(shec->matrix != NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_5)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	//plugin�w��Ȃ�
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��邱�Ƃ��m�F
	EXPECT_TRUE(shec->matrix != NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_6)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "jerasure";	//�ُ�l
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��邱�Ƃ��m�F
	EXPECT_TRUE(shec->matrix != NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_7)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "abc";	//�ُ�l
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��邱�Ƃ��m�F
	EXPECT_TRUE(shec->matrix != NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_8)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["directory"] = "/usr/lib64/";	//�ُ�l
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��邱�Ƃ��m�F
	EXPECT_TRUE(shec->matrix != NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_9)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-root"] = "abc";	//�ُ�l
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��邱�Ƃ��m�F
	EXPECT_TRUE(shec->matrix != NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_10)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "abc";	//�ُ�l
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��邱�Ƃ��m�F
	EXPECT_TRUE(shec->matrix != NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_11)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "abc";		//�ُ�l
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��邱�Ƃ��m�F
	EXPECT_TRUE(shec->matrix != NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_12)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "-1";	//�ُ�l
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_13)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "abc";
	(*parameters)["k"] = "0.1";	//�ُ�l
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_14)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "a";		//�ُ�l
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_15)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	//k �w��Ȃ�
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_16)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "-1";		//�ُ�l
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_17)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "0.1";		//�ُ�l
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_18)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "a";		//�ُ�l
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_19)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	//m�@�w��Ȃ�
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_20)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "-1";		//�ُ�l
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_21)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "0.1";		//�ُ�l
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_22)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "a";		//�ُ�l
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_23)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	//c �w��Ȃ�
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_24)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	(*parameters)["w"] = "1";		//�ُ�l
	//init���s
	shec->init(*parameters);

	//matrix������Ă��邱�Ƃ��m�F
	EXPECT_TRUE(shec->matrix != NULL);
	//k,m,c�Ɏw�肵���l���������Ă��邱�Ƃ��m�F
	EXPECT_EQ(6u,shec->k);
	EXPECT_EQ(4u,shec->m);
	EXPECT_EQ(3u,shec->c);
	//w�Ƀf�t�H���g�l���������Ă��邱�Ƃ��m�F
	EXPECT_EQ(8u,shec->w);
	delete shec;
}

TEST(ErasureCodeShec, init_25)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	(*parameters)["w"] = "-1";		//�ُ�l
	//init���s
	shec->init(*parameters);

	//matrix������Ă��邱�Ƃ��m�F
	EXPECT_TRUE(shec->matrix != NULL);
	//k,m,c�Ɏw�肵���l���������Ă��邱�Ƃ��m�F
	EXPECT_EQ(6u,shec->k);
	EXPECT_EQ(4u,shec->m);
	EXPECT_EQ(3u,shec->c);
	//w�Ƀf�t�H���g�l���������Ă��邱�Ƃ��m�F
	EXPECT_EQ(8u,shec->w);
	delete shec;
}

TEST(ErasureCodeShec, init_26)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	(*parameters)["w"] = "0.1";		//�ُ�l
	//init���s
	shec->init(*parameters);

	//matrix������Ă��邱�Ƃ��m�F
	EXPECT_TRUE(shec->matrix != NULL);
	//k,m,c�Ɏw�肵���l���������Ă��邱�Ƃ��m�F
	EXPECT_EQ(6u,shec->k);
	EXPECT_EQ(4u,shec->m);
	EXPECT_EQ(3u,shec->c);
	//w�Ƀf�t�H���g�l���������Ă��邱�Ƃ��m�F
	EXPECT_EQ(8u,shec->w);
	delete shec;
}

TEST(ErasureCodeShec, init_27)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	(*parameters)["w"] = "a";		//�ُ�l
	//init���s
	shec->init(*parameters);

	//matrix������Ă��邱�Ƃ��m�F
	EXPECT_TRUE(shec->matrix != NULL);
	//k,m,c�Ɏw�肵���l���������Ă��邱�Ƃ��m�F
	EXPECT_EQ(6u,shec->k);
	EXPECT_EQ(4u,shec->m);
	EXPECT_EQ(3u,shec->c);
	//w�Ƀf�t�H���g�l���������Ă��邱�Ƃ��m�F
	EXPECT_EQ(8u,shec->w);

	delete shec;
}

TEST(ErasureCodeShec, init_28)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "10";	//m���傫���l
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_29)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	//k�@�w��Ȃ�
	//m�@�w��Ȃ�
	//c�@�w��Ȃ�
	//init���s
	shec->init(*parameters);

	//matrix������Ă��邱�Ƃ��m�F
	EXPECT_TRUE(shec->matrix != NULL);
	//k,m,c�Ƀf�t�H���g�l���������Ă��邱�Ƃ��m�F
	EXPECT_EQ(2u,shec->k);
	EXPECT_EQ(1u,shec->m);
	EXPECT_EQ(1u,shec->c);

	delete shec;
}

TEST(ErasureCodeShec, init_30)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "12";
	(*parameters)["m"] = "8";
	(*parameters)["c"] = "8";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��邱�Ƃ��m�F
	EXPECT_TRUE(shec->matrix != NULL);
	//k,m,c�Ƀf�t�H���g�l���������Ă��邱�Ƃ��m�F
	EXPECT_EQ(12u,shec->k);
	EXPECT_EQ(8u,shec->m);
	EXPECT_EQ(8u,shec->c);

	delete shec;
}

TEST(ErasureCodeShec, init_31)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "13";
	(*parameters)["m"] = "7";
	(*parameters)["c"] = "7";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_32)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "7";
	(*parameters)["m"] = "13";
	(*parameters)["c"] = "13";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_33)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "12";
	(*parameters)["m"] = "9";
	(*parameters)["c"] = "8";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init_34)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "8";
	(*parameters)["m"] = "12";
	(*parameters)["c"] = "12";
	//init���s
	shec->init(*parameters);

	//matrix������Ă��Ȃ����Ƃ��m�F
	EXPECT_TRUE(shec->matrix == NULL);

	delete shec;
}

TEST(ErasureCodeShec, init2_1)	//OSD���̎w�肪�ł��Ȃ�
{
	//�S�Đ���l
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//�p�����[�^�m�F
	EXPECT_EQ(6u, shec->k);
	EXPECT_EQ(4u, shec->m);
	EXPECT_EQ(3u, shec->c);
	EXPECT_EQ(8u, shec->w);
	EXPECT_STREQ("", shec->technique);
	EXPECT_STREQ("default", shec->ruleset_root.c_str());
	EXPECT_STREQ("osd", shec->ruleset_failure_domain.c_str());
	EXPECT_TRUE(shec->matrix != NULL);

	delete shec;
}

TEST(ErasureCodeShec, init2_2)	//OSD���̎w�肪�ł��Ȃ�
{
	//�S�Đ���l
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//�p�����[�^�m�F
	EXPECT_EQ(6u, shec->k);
	EXPECT_EQ(4u, shec->m);
	EXPECT_EQ(3u, shec->c);
	EXPECT_EQ(8u, shec->w);
	EXPECT_STREQ("", shec->technique);
	EXPECT_STREQ("default", shec->ruleset_root.c_str());
	EXPECT_STREQ("osd", shec->ruleset_failure_domain.c_str());
	EXPECT_TRUE(shec->matrix != NULL);

	delete shec;
}

/*
TEST(ErasureCodeShec, init2_3)	//OSD���̎w�肪�ł��Ȃ�
{
	//�S�Đ���l
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init���s
	shec->init(*parameters);

	//k,m,c�Ƀf�t�H���g�l���������Ă��邱�Ƃ��m�F
	EXPECT_EQ(2u,shec->k);
	EXPECT_EQ(1u,shec->m);
	EXPECT_EQ(1u,shec->c);

	delete shec;
}
*/

TEST(ErasureCodeShec, init2_4)
{
	//�S�Đ���l
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);
	shec->init(*parameters);	//init��2��N��

	//�p�����[�^�m�F
	EXPECT_EQ(6u, shec->k);
	EXPECT_EQ(4u, shec->m);
	EXPECT_EQ(3u, shec->c);
	EXPECT_EQ(8u, shec->w);
	EXPECT_STREQ("", shec->technique);
	EXPECT_STREQ("default", shec->ruleset_root.c_str());
	EXPECT_STREQ("osd", shec->ruleset_failure_domain.c_str());
	EXPECT_TRUE(shec->matrix != NULL);

	delete shec;
}

TEST(ErasureCodeShec, init2_5)
{
	//�S�Đ���l
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	map<std::string, std::string> *parameters2 = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "host";
	(*parameters)["k"] = "10";
	(*parameters)["m"] = "6";
	(*parameters)["c"] = "5";
	(*parameters)["w"] = "16";
	//init���s
	shec->init(*parameters);

	//�l��ς���init�Ď��s
	(*parameters2)["plugin"] = "shec";
	(*parameters2)["technique"] = "";
	(*parameters2)["ruleset-failure-domain"] = "osd";
	(*parameters2)["k"] = "6";
	(*parameters2)["m"] = "4";
	(*parameters2)["c"] = "3";
	shec->init(*parameters2);

	//�l���㏑������Ă��邱�Ƃ��m�F
	EXPECT_EQ(6u, shec->k);
	EXPECT_EQ(4u, shec->m);
	EXPECT_EQ(3u, shec->c);
	EXPECT_EQ(8u, shec->w);
	EXPECT_STREQ("", shec->technique);
	EXPECT_STREQ("default", shec->ruleset_root.c_str());
	EXPECT_STREQ("osd", shec->ruleset_failure_domain.c_str());
	EXPECT_TRUE(shec->matrix != NULL);

	delete shec;
}

TEST(ErasureCodeShec, minimum_to_decode_1)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//minimum_to_decode�̈����錾
	set<int> want_to_decode;
	set<int> available_chunks;
	set<int> minimum_chunks;

	//�����ɒl����
	want_to_decode.insert(0);
	available_chunks.insert(0);
	available_chunks.insert(1);
	available_chunks.insert(2);

	//minimum_to_decode�̎��s
	EXPECT_EQ(0,shec->minimum_to_decode(want_to_decode,available_chunks,&minimum_chunks));
	EXPECT_TRUE(minimum_chunks.size());

	delete shec;
}

TEST(ErasureCodeShec, minimum_to_decode_2)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//minimum_to_decode�̈����錾
	set<int> want_to_decode;
	set<int> available_chunks;
	set<int> minimum_chunks;

	//�����ɒl����
	for (int i=0;i<10;i++){
		want_to_decode.insert(i);
		available_chunks.insert(i);
	}

	//minimum_to_decode�̎��s
	EXPECT_EQ(0,shec->minimum_to_decode(want_to_decode,available_chunks,&minimum_chunks));
	EXPECT_TRUE(minimum_chunks.size());

	delete shec;
}

TEST(ErasureCodeShec, minimum_to_decode_3)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//minimum_to_decode�̈����錾
	set<int> want_to_decode;
	set<int> available_chunks;
	set<int> minimum_chunks;

	//�����̒l����
	for (int i=0;i<32;i++){		//k+m��葽���v�f��
		want_to_decode.insert(i);
		available_chunks.insert(i);
	}

	//minimum_to_decode�̎��s
	EXPECT_NE(0,shec->minimum_to_decode(want_to_decode,available_chunks,&minimum_chunks));
	EXPECT_NE(want_to_decode,minimum_chunks);
	delete shec;
}

TEST(ErasureCodeShec, minimum_to_decode_4)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//minimum_to_decode�̈����錾
	set<int> want_to_decode;
	set<int> available_chunks;
	set<int> minimum_chunks;

	//�����̒l����
	for (int i=0;i<9;i++){
		want_to_decode.insert(i);
		available_chunks.insert(i);
	}
	want_to_decode.insert(100);		//k+m-1���傫���l
	available_chunks.insert(100);	//k+m-1���傫���l

	//minimum_to_decode�̎��s
	EXPECT_NE(0,shec->minimum_to_decode(want_to_decode,available_chunks,&minimum_chunks));

	delete shec;
}

TEST(ErasureCodeShec, minimum_to_decode_5)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//minimum_to_decode�̈����錾
	set<int> want_to_decode;
	set<int> available_chunks;
	set<int> minimum_chunks;

	//�����̒l����
	for (int i=0;i<10;i++){
		want_to_decode.insert(i);
	}
	for (int i=0;i<32;i++){		//k+m��葽���v�f��
		available_chunks.insert(i);
	}

	//minimum_to_decode�̎��s
	EXPECT_NE(0,shec->minimum_to_decode(want_to_decode,available_chunks,&minimum_chunks));

	delete shec;
}

TEST(ErasureCodeShec, minimum_to_decode_6)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//minimum_to_decode�̈����錾
	set<int> want_to_decode;
	set<int> available_chunks;
	set<int> minimum_chunks;

	//�����̒l����
	for (int i=0;i<9;i++){
		want_to_decode.insert(i);
		available_chunks.insert(i);
	}
	available_chunks.insert(100);		//k+m-1���傫���l

	//minimum_to_decode�̎��s
	EXPECT_NE(0,shec->minimum_to_decode(want_to_decode,available_chunks,&minimum_chunks));

	delete shec;
}

TEST(ErasureCodeShec, minimum_to_decode_7)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//minimum_to_decode�̈����錾
	set<int> want_to_decode;
	set<int> available_chunks;
	set<int> minimum_chunks;

	//�����̒l����
	want_to_decode.insert(1);
	want_to_decode.insert(3);
	want_to_decode.insert(5);	//available_chunks�Ɋ܂܂�Ȃ��l
	available_chunks.insert(1);
	available_chunks.insert(3);
	available_chunks.insert(6);

	//minimum_to_decode�̎��s
	EXPECT_NE(0,shec->minimum_to_decode(want_to_decode,available_chunks,&minimum_chunks));

	delete shec;
}


TEST(ErasureCodeShec, minimum_to_decode_8)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//minimum_to_decode�̈����錾
	set<int> want_to_decode;
	set<int> available_chunks;
	//minimum_chunks �� NULL �œn��

	//�����̒l����
	for (int i=0;i<10;i++){
		want_to_decode.insert(i);
		available_chunks.insert(i);
	}

	//minimum_to_decode�̎��s
	EXPECT_NE(0,shec->minimum_to_decode(want_to_decode,available_chunks,NULL));

	delete shec;
}


TEST(ErasureCodeShec, minimum_to_decode_9)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//minimum_to_decode�̈����錾
	set<int> want_to_decode;
	set<int> available_chunks;
	set<int> minimum_chunks,minimum;

	//�����̒l����
	for (int i=0;i<10;i++){
		want_to_decode.insert(i);
		available_chunks.insert(i);
	}
	shec->minimum_to_decode(want_to_decode,available_chunks,&minimum_chunks);
	minimum = minimum_chunks;		//����l��ۑ�
	for (int i=100;i<120;i++){
		minimum_chunks.insert(i);	//minimum_chunks�ɗ]���ȃf�[�^������
	}

	//minimum_to_decode�̎��s
	EXPECT_EQ(0,shec->minimum_to_decode(want_to_decode,available_chunks,&minimum_chunks));
	EXPECT_EQ(minimum,minimum_chunks);	//����l�Ɣ�r

	delete shec;
}

TEST(ErasureCodeShec, minimum_to_decode2_1)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//minimum_to_decode�̈����錾
	set<int> want_to_decode;
	set<int> available_chunks;
	set<int> minimum_chunks;

	//�����̒l����
	want_to_decode.insert(0);
	available_chunks.insert(0);
	available_chunks.insert(1);
	available_chunks.insert(2);

	//minimum_to_decode�̎��s
	EXPECT_EQ(0,shec->minimum_to_decode(want_to_decode,available_chunks,&minimum_chunks));
	EXPECT_TRUE(minimum_chunks.size());

	delete shec;
}

/*
TEST(ErasureCodeShec, minimum_to_decode2_2)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init�����s

	//minimum_to_decode�̈����錾
	set<int> want_to_decode;
	set<int> available_chunks;
	set<int> minimum_chunks;

	//�����̒l����
	want_to_decode.insert(0);
	available_chunks.insert(0);
	available_chunks.insert(1);
	available_chunks.insert(2);

	//minimum_to_decode�̎��s
	EXPECT_NE(0,shec->minimum_to_decode(want_to_decode,available_chunks,&minimum_chunks));

	delete shec;
}
*/

TEST(ErasureCodeShec, minimum_to_decode2_3)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//minimum_to_decode�̈����錾
	set<int> want_to_decode;
	set<int> available_chunks;
	set<int> minimum_chunks;

	//�����̒l����
	want_to_decode.insert(0);
	want_to_decode.insert(2);
	available_chunks.insert(0);
	available_chunks.insert(1);
	available_chunks.insert(2);
	available_chunks.insert(3);

	//�X���b�h�N��
	pthread_t tid;
	pthread_create(&tid,NULL,thread1,shec);
	sleep(1);
	printf("*** test start ***\n");
	//minimum_to_decode�̎��s
	EXPECT_EQ(0,shec->minimum_to_decode(want_to_decode,available_chunks,&minimum_chunks));
	EXPECT_EQ(want_to_decode,minimum_chunks);
	printf("*** test end ***\n");
	//�X���b�h�̒�~�҂�
	pthread_join(tid,NULL);

	delete shec;
}


TEST(ErasureCodeShec, minimum_to_decode_with_cost_1)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//minimum_to_decode_with_cost�̈����錾
	set<int> want_to_decode;
	map<int,int> available_chunks;
	set<int> minimum_chunks;

	//�����̒l����
	want_to_decode.insert(0);
	available_chunks[0] = 0;
	available_chunks[1] = 1;
	available_chunks[2] = 2;

	//minimum_to_decode_with_cost�̎��s
	EXPECT_EQ(0,shec->minimum_to_decode_with_cost(want_to_decode,available_chunks,&minimum_chunks));
	EXPECT_TRUE(minimum_chunks.size());

	delete shec;
}

/*
TEST(ErasureCodeShec, minimum_to_decode_with_cost_2_2)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init�����s

	//minimum_to_decode_with_cost�̈����錾
	set<int> want_to_decode;
	map<int,int> available_chunks;
	set<int> minimum_chunks;

	//�����̒l����
	want_to_decode.insert(0);
	available_chunks[0] = 0;
	available_chunks[1] = 1;
	available_chunks[2] = 2;

	minimum_to_decode_with_cost�̎��s
	EXPECT_NE(0,shec->minimum_to_decode_with_cost(want_to_decode,available_chunks,&minimum_chunks));
	delete shec;
}
*/

TEST(ErasureCodeShec, minimum_to_decode_with_cost_2_3)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//minimum_to_decode_with_cost�̈����錾
	set<int> want_to_decode;
	map<int,int> available_chunks;
	set<int> minimum_chunks;

	//�����̒l����
	want_to_decode.insert(0);
	want_to_decode.insert(2);
	available_chunks[0] = 0;
	available_chunks[1] = 1;
	available_chunks[2] = 2;
	available_chunks[3] = 3;

	//�X���b�h�̋N��
	pthread_t tid;
	pthread_create(&tid,NULL,thread2,shec);
	sleep(1);
	printf("*** test start ***\n");
	//minimum_to_decode_with_cost�̎��s
	EXPECT_EQ(0,shec->minimum_to_decode_with_cost(want_to_decode,available_chunks,&minimum_chunks));
	EXPECT_EQ(want_to_decode,minimum_chunks);
	printf("*** test end ***\n");
	//�X���b�h�̒�~�҂�
	pthread_join(tid,NULL);

	delete shec;
}


TEST(ErasureCodeShec, encode_1)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			"012345"															//192
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	//encode�̎��s
	EXPECT_EQ(0, shec->encode(want_to_encode, in, &encoded));
	EXPECT_EQ(shec->get_chunk_count(), encoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), encoded[0].length());


	//encoded����ʂɕ\��
	map<int,bufferlist>::iterator itr;

	for ( itr = encoded.begin();itr != encoded.end(); itr++ )
	{
		std::cout << itr->first << ": " << itr->second << std::endl;
	}


	//decode
	int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	map<int, bufferlist> decoded;
	decoded.clear();
	EXPECT_EQ(0,shec->decode(set<int>(want_to_decode, want_to_decode+2), encoded, &decoded));
	EXPECT_EQ(2u, decoded.size());
	EXPECT_EQ(32u, decoded[0].length());
/*
	//decoded����ʂɕ\��
//	map<int,bufferlist>::iterator itr;

	for ( itr = decoded.begin();itr != decoded.end(); itr++ )
	{
		std::cout << itr->first << ": " << itr->second << std::endl;
	}
*/
	bufferlist out1,out2,usable;
	//encode���ʂ�out1�ɂ܂Ƃ߂�
	for (unsigned int i = 0; i < encoded.size(); i++)
	  out1.append(encoded[i]);
	//docode���ʂ�out2�ɂ܂Ƃ߂�
	int r = shec->decode_concat(encoded, &out2);
	std::cout << "r:" << r << std::endl;
	//out2��padding�O�̃f�[�^���ɍ��킹��
	usable.substr_of(out2, 0, in.length());
	EXPECT_FALSE(out1 == in); //���f�[�^��encode��̃f�[�^��r
	EXPECT_TRUE(usable == in); //���f�[�^��decode��̃f�[�^��r


//	std::cout << "in:" << in << std::endl;			//���f�[�^��\��
//	std::cout << "out1:" << out1 << std::endl;		//encode��̃f�[�^��\��
//	std::cout << "out2:" << out2 << std::endl;
//	std::cout << "usable:" << usable << std::endl;	//decode��̃f�[�^��\��


	delete shec;
}

TEST(ErasureCodeShec, encode_2)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	//encode�̎��s
	EXPECT_EQ(0, shec->encode(want_to_encode, in, &encoded));
	EXPECT_EQ(shec->get_chunk_count(), encoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), encoded[0].length());

/*
	//encoded����ʂɕ\��
	map<int,bufferlist>::iterator itr;
	for ( itr = encoded.begin();itr != encoded.end(); itr++ )
	{
		std::cout << itr->first << ": " << itr->second << std::endl;
	}
*/

	//decode
	int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	map<int, bufferlist> decoded;
	EXPECT_EQ(0,shec->decode(set<int>(want_to_decode, want_to_decode+2), encoded, &decoded));
	EXPECT_EQ(2u, decoded.size());
	EXPECT_EQ(32u, decoded[0].length());

	bufferlist out1,out2,usable;
	//encode���ʂ�out1�ɂ܂Ƃ߂�
	for (unsigned int i = 0; i < encoded.size(); i++)
	  out1.append(encoded[i]);
	//docode���ʂ�out2�ɂ܂Ƃ߂�
	shec->decode_concat(encoded, &out2);
	//out2��padding�O�̃f�[�^���ɍ��킹��
	usable.substr_of(out2, 0, in.length());
	EXPECT_FALSE(out1 == in); //���f�[�^��encode��̃f�[�^��r
	EXPECT_TRUE(usable == in); //���f�[�^��decode��̃f�[�^��r

	/*
		std::cout << "in:" << in << std::endl;			//���f�[�^��\��
		std::cout << "out1:" << out1 << std::endl;		//encode��̃f�[�^��\��
		std::cout << "usable:" << usable << std::endl;	//decode��̃f�[�^��\��
	*/

	delete shec;
}

TEST(ErasureCodeShec, encode_3)
{
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	bufferlist in;
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			);
	set<int> want_to_encode;
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);
	want_to_encode.insert(10);
	want_to_encode.insert(11);
	map<int, bufferlist> encoded;
	EXPECT_EQ(0, shec->encode(want_to_encode, in, &encoded));
	EXPECT_EQ(shec->get_chunk_count(), encoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), encoded[0].length());

/*
	//encoded����ʂɕ\��
	map<int,bufferlist>::iterator itr;

	for ( itr = encoded.begin();itr != encoded.end(); itr++ )
	{
		std::cout << itr->first << ": " << itr->second << std::endl;
	}
*/

	//decode
	int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	map<int, bufferlist> decoded;
	EXPECT_EQ(0,shec->decode(set<int>(want_to_decode, want_to_decode+2), encoded, &decoded));
	EXPECT_EQ(2u, decoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), decoded[0].length());

	bufferlist out1,out2,usable;
	//encode���ʂ�out1�ɂ܂Ƃ߂�
	for (unsigned int i = 0; i < encoded.size(); i++)
	  out1.append(encoded[i]);
	//docode���ʂ�out2�ɂ܂Ƃ߂�
	shec->decode_concat(encoded, &out2);
	//out2��padding�O�̃f�[�^���ɍ��킹��
	usable.substr_of(out2, 0, in.length());
	EXPECT_FALSE(out1 == in); //���f�[�^��encode��̃f�[�^��r
	EXPECT_TRUE(usable == in); //���f�[�^��decode��̃f�[�^��r

/*
	std::cout << "in:" << in << std::endl;			//���f�[�^��\��
	std::cout << "out1:" << out1 << std::endl;		//encode��̃f�[�^��\��
	std::cout << "usable:" << usable << std::endl;	//decode��̃f�[�^��\��
*/
	delete shec;
}

TEST(ErasureCodeShec, encode_4)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			);
	for(unsigned int i = 0; i < shec->get_chunk_count()-1; i++)
		want_to_encode.insert(i);
	want_to_encode.insert(100);

	//encode�̎��s
	EXPECT_EQ(0, shec->encode(want_to_encode, in, &encoded));
	EXPECT_EQ(shec->get_chunk_count()-1, encoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), encoded[0].length());

/*
	//encoded����ʂɕ\��
	map<int,bufferlist>::iterator itr;

	for ( itr = encoded.begin();itr != encoded.end(); itr++ )
	{
		std::cout << itr->first << ": " << itr->second << std::endl;
	}
*/

	//decode
	int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	map<int, bufferlist> decoded;
	EXPECT_EQ(0,shec->decode(set<int>(want_to_decode, want_to_decode+2), encoded, &decoded));
	EXPECT_EQ(2u, decoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), decoded[0].length());

	bufferlist out1,out2,usable;
	//encode���ʂ�out1�ɂ܂Ƃ߂�
	for (unsigned int i = 0; i < encoded.size(); i++)
	  out1.append(encoded[i]);
	//docode���ʂ�out2�ɂ܂Ƃ߂�
	shec->decode_concat(encoded, &out2);
	//out2��padding�O�̃f�[�^���ɍ��킹��
	usable.substr_of(out2, 0, in.length());
	EXPECT_FALSE(out1 == in); //���f�[�^��encode��̃f�[�^��r
	EXPECT_TRUE(usable == in); //���f�[�^��decode��̃f�[�^��r

/*
	std::cout << "in:" << in << std::endl;			//���f�[�^��\��
	std::cout << "out1:" << out1 << std::endl;		//encode��̃f�[�^��\��
	std::cout << "usable:" << usable << std::endl;	//decode��̃f�[�^��\��
*/
	delete shec;
}

/*
TEST(ErasureCodeShec, encode_6)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);
	EXPECT_EQ(0, shec->encode(want_to_encode, NULL, &encoded)); //inbuf=NULL
	EXPECT_EQ(shec->get_chunk_count(), encoded.size());
	EXPECT_EQ(0, encoded[0].length());


	//encoded����ʂɕ\��
	map<int,bufferlist>::iterator itr;

	for ( itr = encoded.begin();itr != encoded.end(); itr++ )
	{
		std::cout << itr->first << ": " << itr->second << std::endl;
	}

	delete shec;
}
*/

TEST(ErasureCodeShec, encode_8)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	//encode�̎��s
	EXPECT_NE(0, shec->encode(want_to_encode, in, NULL));	//encoded = NULL

	delete shec;
}



TEST(ErasureCodeShec, encode_9)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);
	for (int i = 0;i<100;i++)
	{
		encoded[i].append("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	}
//	std::cout << "encoded:" << encoded << std::endl;

	//encode�̎��s
	EXPECT_NE(0, shec->encode(want_to_encode, in, &encoded));

	delete shec;
}


TEST(ErasureCodeShec, encode2_1)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			"012345"															//192
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	//encode�̎��s
	EXPECT_EQ(0, shec->encode(want_to_encode, in, &encoded));
	EXPECT_EQ(shec->get_chunk_count(), encoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), encoded[0].length());

	//encoded����ʂɕ\��
	map<int,bufferlist>::iterator itr;
	for ( itr = encoded.begin();itr != encoded.end(); itr++ )
	{
		std::cout << itr->first << ": " << itr->second << std::endl;
	}

	//decode
	int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	map<int, bufferlist> decoded;
	EXPECT_EQ(0,shec->decode(set<int>(want_to_decode, want_to_decode+2), encoded, &decoded));
	EXPECT_EQ(2u, decoded.size());
	EXPECT_EQ(32u, decoded[0].length());

	bufferlist out1,out2,usable;
	//encode���ʂ�out1�ɂ܂Ƃ߂�
	for (unsigned int i = 0; i < encoded.size(); i++)
	  out1.append(encoded[i]);
	//docode���ʂ�out2�ɂ܂Ƃ߂�
	shec->decode_concat(encoded, &out2);
	//out2��padding�O�̃f�[�^���ɍ��킹��
	usable.substr_of(out2, 0, in.length());
	EXPECT_FALSE(out1 == in); //���f�[�^��encode��̃f�[�^��r
	EXPECT_TRUE(usable == in); //���f�[�^��decode��̃f�[�^��r

	std::cout << "in:" << in << std::endl;			//���f�[�^��\��
	std::cout << "out1:" << out1 << std::endl;		//encode��̃f�[�^��\��
	std::cout << "usable:" << usable << std::endl;	//decode��̃f�[�^��\��

	delete shec;
}

/*
TEST(ErasureCodeShec, encode2_2)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init�����s

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			"012345"															//192
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	//encode�̎��s
	EXPECT_NE(0, shec->encode(want_to_encode, in, &encoded));

	//encoded����ʂɕ\��
	map<int,bufferlist>::iterator itr;
	for ( itr = encoded.begin();itr != encoded.end(); itr++ )
	{
		std::cout << itr->first << ": " << itr->second << std::endl;
	}

	delete shec;
}
*/

TEST(ErasureCodeShec, encode2_3)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			"012345"															//192
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	//�X���b�h�̋N��
	pthread_t tid;
	pthread_create(&tid,NULL,thread4,shec);
	sleep(1);
	printf("*** test start ***\n");
	//encode�̎��s
	EXPECT_EQ(0, shec->encode(want_to_encode, in, &encoded));
	EXPECT_EQ(shec->get_chunk_count(), encoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), encoded[0].length());
	printf("*** test end ***\n");
	//�X���b�h�̒�~�҂�
	pthread_join(tid,NULL);

	//encoded����ʂɕ\��
	map<int,bufferlist>::iterator itr;
	for ( itr = encoded.begin();itr != encoded.end(); itr++ )
	{
		std::cout << itr->first << ": " << itr->second << std::endl;
	}

	//decode
	int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	map<int, bufferlist> decoded;

	EXPECT_EQ(0,shec->decode(set<int>(want_to_decode, want_to_decode+2), encoded, &decoded));
	EXPECT_EQ(2u, decoded.size());
	EXPECT_EQ(32u, decoded[0].length());

	bufferlist out1,out2,usable;
	//encode���ʂ�out1�ɂ܂Ƃ߂�
	for (unsigned int i = 0; i < encoded.size(); i++)
	  out1.append(encoded[i]);
	//docode���ʂ�out2�ɂ܂Ƃ߂�
	shec->decode_concat(encoded, &out2);
	//out2��padding�O�̃f�[�^���ɍ��킹��
	usable.substr_of(out2, 0, in.length());
	EXPECT_FALSE(out1 == in); //���f�[�^��encode��̃f�[�^��r
	EXPECT_TRUE(usable == in); //���f�[�^��decode��̃f�[�^��r

	std::cout << "in:" << in << std::endl;
	std::cout << "out1:" << out1 << std::endl;
	std::cout << "usable:" << usable << std::endl;

	delete shec;
}

TEST(ErasureCodeShec, decode_1)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//248
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	//encode�̎��s
	EXPECT_EQ(0, shec->encode(want_to_encode, in, &encoded));
	EXPECT_EQ(shec->get_chunk_count(), encoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), encoded[0].length());

	// all chunks are available
	{
		//decode�̈����錾
		int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		map<int, bufferlist> decoded;

		//decode�̎��s
		EXPECT_EQ(0,shec->decode(set<int>(want_to_decode, want_to_decode+2), encoded, &decoded));
		EXPECT_EQ(2u, decoded.size());

		//���ʂ̊m�F
		bufferlist out;
		shec->decode_concat(encoded, &out);
		bufferlist usable;
		usable.substr_of(out, 0, in.length());
		EXPECT_TRUE(usable == in); //���f�[�^��decode��̃f�[�^��r
	}

	delete shec;
}

TEST(ErasureCodeShec, decode_2)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			"012345"	//192
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	//encode�����s
	EXPECT_EQ(0, shec->encode(want_to_encode, in, &encoded));
	EXPECT_EQ(shec->get_chunk_count(), encoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), encoded[0].length());

	// all chunks are available
	{
		//decode�̈����錾
		int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		map<int, bufferlist> decoded;

		//decode�̎��s
		EXPECT_EQ(0,shec->decode(set<int>(want_to_decode, want_to_decode+2), encoded, &decoded));
		EXPECT_EQ(2u, decoded.size());

		//���ʂ̊m�F
		bufferlist out;
		shec->decode_concat(encoded, &out);
		bufferlist usable;
		usable.substr_of(out, 0, in.length());
		EXPECT_TRUE(usable == in); //���f�[�^��decode��̃f�[�^��r
	}

	delete shec;
}

TEST(ErasureCodeShec, decode_3)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//248
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	//encode�̎��s
	EXPECT_EQ(0, shec->encode(want_to_encode, in, &encoded));
	EXPECT_EQ(shec->get_chunk_count(), encoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), encoded[0].length());

	// all chunks are available
	{
		//decode�̈����錾
		int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };	//k+m��葽���v�f��
		map<int, bufferlist> decoded;

		//decode�̎��s
		EXPECT_EQ(0,shec->decode(set<int>(want_to_decode, want_to_decode+11), encoded, &decoded));
		EXPECT_EQ(10u, decoded.size());
		EXPECT_EQ(shec->get_chunk_size(in.length()), decoded[0].length());

		bufferlist out1,out2,usable;
		//encode���ʂ�out1�ɂ܂Ƃ߂�
		for (unsigned int i = 0; i < encoded.size(); i++)
		  out1.append(encoded[i]);
		//docode���ʂ�out2�ɂ܂Ƃ߂�
		shec->decode_concat(encoded, &out2);
		//out2��padding�O�̃f�[�^���ɍ��킹��
		usable.substr_of(out2, 0, in.length());
		EXPECT_FALSE(out1 == in); //���f�[�^��encode��̃f�[�^��r
		EXPECT_TRUE(usable == in); //���f�[�^��decode��̃f�[�^��r
	}

	delete shec;
}

TEST(ErasureCodeShec, decode_4)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//248
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	//encode�̎��s
	EXPECT_EQ(0, shec->encode(want_to_encode, in, &encoded));
	EXPECT_EQ(shec->get_chunk_count(), encoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), encoded[0].length());

	// all chunks are available
	{
		//decode�̈����錾
		int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 100 };	//100:k+m���傫���l
		map<int, bufferlist> decoded;

		//decode�̎��s
		EXPECT_EQ(0,shec->decode(set<int>(want_to_decode, want_to_decode+9), encoded, &decoded));
		EXPECT_EQ(10u, decoded.size());
		EXPECT_EQ(shec->get_chunk_size(in.length()), decoded[0].length());

		bufferlist out1,out2,usable;
		//encode���ʂ�out1�ɂ܂Ƃ߂�
		for (unsigned int i = 0; i < encoded.size(); i++)
		  out1.append(encoded[i]);
		//docode���ʂ�out2�ɂ܂Ƃ߂�
		shec->decode_concat(encoded, &out2);
		//out2��padding�O�̃f�[�^���ɍ��킹��
		usable.substr_of(out2, 0, in.length());
		EXPECT_FALSE(out1 == in); //���f�[�^��encode��̃f�[�^��r
		EXPECT_TRUE(usable == in); //���f�[�^��decode��̃f�[�^��r
	}

	delete shec;
}

/*
TEST(ErasureCodeShec, decode_6)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//decode�̈����錾
	int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	map<int, bufferlist> decoded;

	//decode�̎��s
//	map<int, bufferlist> inchunks;
	EXPECT_NE(0,shec->decode(set<int>(want_to_decode, want_to_decode+2), NULL, &decoded));

	delete shec;
}
*/

TEST(ErasureCodeShec, decode_7)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//248
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	//encode�̎��s
	EXPECT_EQ(0, shec->encode(want_to_encode, in, &encoded));
	EXPECT_EQ(shec->get_chunk_count(), encoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), encoded[0].length());

	// all chunks are available
	{
		//decode�̈����錾
		int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		map<int, bufferlist> decoded;

		//want_to_decode�ƈ�v���Ȃ��L�[�̃��X�g���쐬
		bufferlist buf;
		buf.append("abc");
		encoded[100] = buf;

		//decode�̎��s
		EXPECT_EQ(0,shec->decode(set<int>(want_to_decode, want_to_decode+2), encoded, &decoded));
		EXPECT_EQ(2u, decoded.size());
		EXPECT_EQ(shec->get_chunk_size(in.length()), decoded[0].length());

		bufferlist out1,out2,usable;
		//encode���ʂ�out1�ɂ܂Ƃ߂�
		for (unsigned int i = 0; i < encoded.size(); i++)
		  out1.append(encoded[i]);
		//docode���ʂ�out2�ɂ܂Ƃ߂�
		shec->decode_concat(encoded, &out2);
		//out2��padding�O�̃f�[�^���ɍ��킹��
		usable.substr_of(out2, 0, in.length());
		EXPECT_FALSE(out1 == in); //���f�[�^��encode��̃f�[�^��r
		EXPECT_TRUE(usable == in); //���f�[�^��decode��̃f�[�^��r
	}

	delete shec;
}


TEST(ErasureCodeShec, decode_8)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//248
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	//encode�̎��s
	EXPECT_EQ(0, shec->encode(want_to_encode, in, &encoded));
	EXPECT_EQ(shec->get_chunk_count(), encoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), encoded[0].length());

	// all chunks are available
	{
		//decode�̈����錾
		int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		//decode�̎��s
		 //decoded = NULL
		EXPECT_NE(0,shec->decode(set<int>(want_to_decode, want_to_decode+2), encoded, NULL));
	}

	delete shec;
}


TEST(ErasureCodeShec, decode_9)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//248
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	//encode�̎��s
	EXPECT_EQ(0, shec->encode(want_to_encode, in, &encoded));
	EXPECT_EQ(shec->get_chunk_count(), encoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), encoded[0].length());

	// all chunks are available
	{
		//decode�̈����錾
		int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		map<int, bufferlist> decoded;

		//decoded�ɗ]���ȃf�[�^����
		bufferlist buf;
		buf.append("a");
		for (int i=0;i<100;i++)
		{
			decoded[i] = buf;
		}

		//decode�̎��s
		EXPECT_NE(0,shec->decode(set<int>(want_to_decode, want_to_decode+2), encoded, &decoded));
/*
		//decoded����ʂɕ\��
		map<int,bufferlist>::iterator itr;
		for ( itr = decoded.begin();itr != decoded.end(); itr++ )
		{
			std::cout << itr->first << ": " << itr->second << std::endl;
		}
*/
	}

	delete shec;
}

TEST(ErasureCodeShec, decode2_1)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//248
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	//encode�̎��s
	EXPECT_EQ(0, shec->encode(want_to_encode, in, &encoded));
	EXPECT_EQ(shec->get_chunk_count(), encoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), encoded[0].length());

	// all chunks are available
	{
		//decode�̈����錾
		int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		map<int, bufferlist> decoded;

		//decode�̎��s
		EXPECT_EQ(0,shec->decode(set<int>(want_to_decode, want_to_decode+2), encoded, &decoded));
		EXPECT_EQ(2u, decoded.size());

		//���ʂ̊m�F
		bufferlist out;
		shec->decode_concat(encoded, &out);
		bufferlist usable;
		usable.substr_of(out, 0, in.length());
		EXPECT_TRUE(usable == in); //���f�[�^��decode��̃f�[�^��r
	}

	delete shec;
}

/*
TEST(ErasureCodeShec, decode2_2)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	// init�����s

	//encoded�̍쐬
	map<int, bufferlist> encoded;
	bufferlist buf;
	buf.append("ABCDEFGH");
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		encoded[i] = buf;

	// all chunks are available
	{
		//decode�̈����錾
		int want_to_decode[] = { 0 };
		map<int, bufferlist> decoded;

		//decode�̎��s
		EXPECT_NE(0,shec->decode(set<int>(want_to_decode, want_to_decode+2), encoded, &decoded));
	}

	delete shec;
}
*/

TEST(ErasureCodeShec, decode2_3)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//248
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	//encode�̎��s
	EXPECT_EQ(0, shec->encode(want_to_encode, in, &encoded));
	EXPECT_EQ(shec->get_chunk_count(), encoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), encoded[0].length());

	// all chunks are available
	{
		//decode�̈����錾
		int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		map<int, bufferlist> decoded;

		//�X���b�h�̋N��
		pthread_t tid;
		pthread_create(&tid,NULL,thread4,shec);
		sleep(1);
		printf("*** test start ***\n");
		//decode�̎��s
		EXPECT_EQ(0,shec->decode(set<int>(want_to_decode, want_to_decode+2), encoded, &decoded));
		EXPECT_EQ(2u, decoded.size());
		printf("*** test end ***\n");
		//�X���b�h�̒�~�҂�
		pthread_join(tid,NULL);

		//���ʂ̊m�F
		bufferlist out;
		shec->decode_concat(encoded, &out);
		bufferlist usable;
		usable.substr_of(out, 0, in.length());
		EXPECT_TRUE(usable == in); //���f�[�^��decode��̃f�[�^��r

	}

	delete shec;
}

TEST(ErasureCodeShec, decode2_4)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//encode�̈����錾
	bufferlist in;
	set<int> want_to_encode;
	map<int, bufferlist> encoded;

	//�����̒l����
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//248
			);
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	//encode�̎��s
	EXPECT_EQ(0, shec->encode(want_to_encode, in, &encoded));
	EXPECT_EQ(shec->get_chunk_count(), encoded.size());
	EXPECT_EQ(shec->get_chunk_size(in.length()), encoded[0].length());

	//decode�̈����錾
	int want_to_decode[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	map<int, bufferlist> decoded;

	// cannot recover
	bufferlist out;
	map<int, bufferlist> degraded;
	degraded[0] = encoded[0];

	//decode�̎��s
	EXPECT_EQ(-1, shec->decode(set<int>(want_to_decode, want_to_decode+2), degraded, &decoded));

	delete shec;
}

TEST(ErasureCodeShec, create_ruleset_1_2)
{
	//ruleset�̍쐬
	CrushWrapper *crush = new CrushWrapper;
	crush->create();
	crush->set_type_name(2, "root");
	crush->set_type_name(1, "host");
	crush->set_type_name(0, "osd");

	int rootno;
	crush->add_bucket(0, CRUSH_BUCKET_STRAW, CRUSH_HASH_RJENKINS1, 5, 0, NULL, NULL, &rootno);
	crush->set_item_name(rootno, "default");

	map<string,string> loc;
	loc["root"] = "default";

	int num_host = 2;
	int num_osd = 5;
	int osd = 0;
	for (int h = 0; h < num_host; ++h) {
		loc["host"] = string("host-") + stringify(h);
		for (int o = 0; o < num_osd; ++o, ++osd) {
			crush->insert_item(g_ceph_context, osd, 1.0, string("osd.") + stringify(osd), loc);
		}
	}

	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map < std::string, std::string > *parameters = new map<std::string,
			std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//create_ruleset�̈����錾
	stringstream ss;

	//create_ruleset�̎��s
	EXPECT_EQ(0, shec->create_ruleset("myrule", *crush, &ss));
	EXPECT_STREQ("myrule",crush->rule_name_map[0].c_str());

	//rule_name_map����ʂɕ\��
	map<int32_t,string>::iterator itr;
	for ( itr = crush->rule_name_map.begin();itr != crush->rule_name_map.end(); itr++ )
	{
		std::cout <<"+++ rule_name_map[" << itr->first << "]: " << itr->second << " +++\n";
	}

	//�����ōĎ��s
	EXPECT_EQ(-EEXIST, shec->create_ruleset("myrule", *crush, &ss));

	delete shec,crush;
}

/*
TEST(ErasureCodeShec, create_ruleset_3)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map < std::string, std::string > *parameters = new map<std::string,
			std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//create_ruleset�̈����錾
	stringstream ss;
	CrushWrapper *crush = NULL;
	EXPECT_NE(0, shec->create_ruleset("myrule", *crush, &ss));	//crush = NULL

	delete shec;
}
*/


TEST(ErasureCodeShec, create_ruleset_4)
{
	//ruleset�̍쐬
	CrushWrapper *crush = new CrushWrapper;
	crush->create();
	crush->set_type_name(2, "root");
	crush->set_type_name(1, "host");
	crush->set_type_name(0, "osd");

	int rootno;
	crush->add_bucket(0, CRUSH_BUCKET_STRAW, CRUSH_HASH_RJENKINS1, 5, 0, NULL, NULL, &rootno);
	crush->set_item_name(rootno, "default");

	map<string,string> loc;
	loc["root"] = "default";

	int num_host = 2;
	int num_osd = 5;
	int osd = 0;
	for (int h = 0; h < num_host; ++h) {
		loc["host"] = string("host-") + stringify(h);
		for (int o = 0; o < num_osd; ++o, ++osd) {
			crush->insert_item(g_ceph_context, osd, 1.0, string("osd.") + stringify(osd), loc);
		}
	}

	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map < std::string, std::string > *parameters = new map<std::string,
			std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//create_ruleset�̎��s
	EXPECT_EQ(0, shec->create_ruleset("myrule", *crush, NULL));	//ss = NULL

	delete shec,crush;
}


TEST(ErasureCodeShec, create_ruleset2_1)
{
	//ruleset�̍쐬
	CrushWrapper *crush = new CrushWrapper;
	crush->create();
	crush->set_type_name(2, "root");
	crush->set_type_name(1, "host");
	crush->set_type_name(0, "osd");

	int rootno;
	crush->add_bucket(0, CRUSH_BUCKET_STRAW, CRUSH_HASH_RJENKINS1, 5, 0, NULL, NULL, &rootno);
	crush->set_item_name(rootno, "default");

	map<string,string> loc;
	loc["root"] = "default";

	int num_host = 2;
	int num_osd = 5;
	int osd = 0;
	for (int h = 0; h < num_host; ++h) {
		loc["host"] = string("host-") + stringify(h);
		for (int o = 0; o < num_osd; ++o, ++osd) {
			crush->insert_item(g_ceph_context, osd, 1.0, string("osd.") + stringify(osd), loc);
		}
	}

	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map < std::string, std::string > *parameters = new map<std::string,
			std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//create_ruleset�̈����錾
	stringstream ss;

	//create_ruleset�̎��s
	EXPECT_EQ(0, shec->create_ruleset("myrule", *crush, &ss));
	EXPECT_STREQ("myrule",crush->rule_name_map[0].c_str());

	//rule_name_map����ʂɕ\��
	map<int32_t,string>::iterator itr;
	for ( itr = crush->rule_name_map.begin();itr != crush->rule_name_map.end(); itr++ )
	{
		std::cout <<"+++ rule_name_map[" << itr->first << "]: " << itr->second << " +++\n";
	}

	delete shec,crush;
}

TEST(ErasureCodeShec, create_ruleset2_2)
{
	//ruleset�̍쐬
	CrushWrapper *crush = new CrushWrapper;
	crush->create();
	crush->set_type_name(2, "root");
	crush->set_type_name(1, "host");
	crush->set_type_name(0, "osd");

	int rootno;
	crush->add_bucket(0, CRUSH_BUCKET_STRAW, CRUSH_HASH_RJENKINS1, 5, 0, NULL, NULL, &rootno);
	crush->set_item_name(rootno, "default");

	map<string,string> loc;
	loc["root"] = "default";

	int num_host = 2;
	int num_osd = 5;
	int osd = 0;
	for (int h = 0; h < num_host; ++h) {
		loc["host"] = string("host-") + stringify(h);
		for (int o = 0; o < num_osd; ++o, ++osd) {
			crush->insert_item(g_ceph_context, osd, 1.0, string("osd.") + stringify(osd), loc);
		}
	}

	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map < std::string, std::string > *parameters = new map<std::string,
			std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	// init�����s

	//create_ruleset�̈����錾
	stringstream ss;

	//create_ruleset�̎��s
	EXPECT_EQ(0, shec->create_ruleset("myrule", *crush, &ss));

	delete shec,crush;
}

struct Create_ruleset2_3_Param{
	ErasureCodeShec *shec;
	CrushWrapper *crush;
};

TEST(ErasureCodeShec, create_ruleset2_3)
{
	//ruleset�̍쐬
	CrushWrapper *crush = new CrushWrapper;
	crush->create();
	crush->set_type_name(2, "root");
	crush->set_type_name(1, "host");
	crush->set_type_name(0, "osd");

	int rootno;
	crush->add_bucket(0, CRUSH_BUCKET_STRAW, CRUSH_HASH_RJENKINS1, 5, 0, NULL, NULL, &rootno);
	crush->set_item_name(rootno, "default");

	map<string,string> loc;
	loc["root"] = "default";

	int num_host = 2;
	int num_osd = 5;
	int osd = 0;
	for (int h = 0; h < num_host; ++h) {
		loc["host"] = string("host-") + stringify(h);
		for (int o = 0; o < num_osd; ++o, ++osd) {
			crush->insert_item(g_ceph_context, osd, 1.0, string("osd.") + stringify(osd), loc);
		}
	}

	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map < std::string, std::string > *parameters = new map<std::string,
			std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//create_ruleset�̈����錾
	stringstream ss;

	//�X���b�h�̋N��
	pthread_t tid;
	pthread_create(&tid,NULL,thread3,shec);
	sleep(1);
	printf("*** test start ***\n");
	//create_ruleset�̎��s
	EXPECT_TRUE((shec->create_ruleset("myrule", *crush, &ss)) >= 0);
	printf("*** test end ***\n");
	//�X���b�h�̒�~�҂�
	pthread_join(tid,NULL);

	//rule_name_map����ʂɕ\��
	map<int32_t,string>::iterator itr;
	for ( itr = crush->rule_name_map.begin();itr != crush->rule_name_map.end(); itr++ )
	{
		std::cout <<"+++ rule_name_map[" << itr->first << "]: " << itr->second << " +++\n";
	}

	delete shec,crush;
}

TEST(ErasureCodeShec, get_chunk_count_1)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map < std::string, std::string > *parameters = new map<std::string,
			std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//get_chunk_count�̎��s
	EXPECT_EQ(10u, shec->get_chunk_count());

	delete shec;
}

TEST(ErasureCodeShec, get_chunk_count_2)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map < std::string, std::string > *parameters = new map<std::string,
			std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init�����s

	//get_chunk_count�̎��s
	EXPECT_EQ(10u, shec->get_chunk_count());

	delete shec;
}

TEST(ErasureCodeShec, get_data_chunk_count_1)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map < std::string, std::string > *parameters = new map<std::string,
			std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	shec->init(*parameters);

	//get_data_chunk_count�̎��s
	EXPECT_EQ(6u, shec->get_data_chunk_count());

	delete shec;
}

TEST(ErasureCodeShec, get_data_chunk_count_2)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map < std::string, std::string > *parameters = new map<std::string,
			std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	//init�����s

	//get_data_chunk_count�̎��s
	EXPECT_EQ(6u, shec->get_data_chunk_count());

	delete shec;
}

TEST(ErasureCodeShec, get_chunk_size_1_2)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map < std::string, std::string > *parameters = new map<std::string,
			std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	(*parameters)["w"] = "8";
	shec->init(*parameters);

	//k*w*4�Ŋ���؂�鐔�i192=6*8*4�j��n����get_chunk_size�����s
	EXPECT_EQ(32u, shec->get_chunk_size(192));
	//k*w*4�Ŋ���؂�Ȃ���(192=6*8*4-2)��n����get_chunk_size�����s
	EXPECT_EQ(32u, shec->get_chunk_size(190));

	delete shec;
}

/*
TEST(ErasureCodeShec, get_chunk_size2)
{
	//init
	ErasureCodeShec* shec = new ErasureCodeShecReedSolomonVandermonde("");
	map < std::string, std::string > *parameters = new map<std::string,
			std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	(*parameters)["w"] = "8";
	//init�����s

	//k*w*4�Ŋ���؂�鐔�i192=6*8*4�j��n����get_chunk_size�����s
	EXPECT_EQ(32u, shec->get_chunk_size(192));
	//k*w*4�Ŋ���؂�Ȃ���(192=6*8*4-2)��n����get_chunk_size�����s
	EXPECT_EQ(32u, shec->get_chunk_size(190));

	delete shec;
}
*/


/*
TEST(ErasureCodeShec, init)
{
	ErasureCodePluginRegistry &instance = ErasureCodePluginRegistry::instance();
//	ErasureCodePlugin* plugin;
	ErasureCodePlugin* plugin = new ErasureCodePlugin();

	map<std::string, std::string> *parameters = new map<std::string, std::string>();
	(*parameters)["plugin"] = "shec";
	(*parameters)["technique"] = "";
	(*parameters)["directory"] = "/usr/lib64/ceph/erasure-code";
	(*parameters)["ruleset-root"] = "default";
	(*parameters)["ruleset-failure-domain"] = "osd";
	(*parameters)["k"] = "6";
	(*parameters)["m"] = "4";
	(*parameters)["c"] = "3";
	(*parameters)["w"] = "8";
	string plugin_name = "shec";
	stringstream ss;
	instance.load(plugin_name,*parameters,&plugin,ss);
	ErasureCodeInterfaceRef *erasure_code2;
	plugin->factory(*parameters,erasure_code2);
	EXPECT_EQ(10u, (*erasure_code2)->get_chunk_count());
	delete parameters;
}
*/


/*

TEST(ErasureCodeShec, encode_decode)
{
  ErasureCodeShec shec;

  bufferlist in;
  in.append("ABCDE");
  set<int> want_to_encode;
  for(unsigned int i = 0; i < shec.get_chunk_count(); i++)
    want_to_encode.insert(i);
  map<int, bufferlist> encoded;
  EXPECT_EQ(0, shec.encode(want_to_encode, in, &encoded));
  EXPECT_EQ(shec.get_chunk_count(), encoded.size());
  EXPECT_EQ(shec.get_chunk_size(in.length()), encoded[0].length());
  EXPECT_EQ('A', encoded[0][0]);
  EXPECT_EQ('B', encoded[0][1]);
  EXPECT_EQ('C', encoded[0][2]);
  EXPECT_EQ('D', encoded[1][0]);
  EXPECT_EQ('E', encoded[1][1]);
  EXPECT_EQ('A'^'D', encoded[2][0]);
  EXPECT_EQ('B'^'E', encoded[2][1]);
  EXPECT_EQ('C'^0, encoded[2][2]);

  // all chunks are available
  {
    int want_to_decode[] = { 0, 1 };
    map<int, bufferlist> decoded;
    EXPECT_EQ(0, shec.decode(set<int>(want_to_decode, want_to_decode+2),
                                encoded,
                                &decoded));
    EXPECT_EQ(2u, decoded.size());
    EXPECT_EQ(3u, decoded[0].length());
    EXPECT_EQ('A', decoded[0][0]);
    EXPECT_EQ('B', decoded[0][1]);
    EXPECT_EQ('C', decoded[0][2]);
    EXPECT_EQ('D', decoded[1][0]);
    EXPECT_EQ('E', decoded[1][1]);
  }

  // one chunk is missing
  {
    map<int, bufferlist> degraded = encoded;
    degraded.erase(0);
    EXPECT_EQ(2u, degraded.size());
    int want_to_decode[] = { 0, 1 };
    map<int, bufferlist> decoded;
    EXPECT_EQ(0, shec.decode(set<int>(want_to_decode, want_to_decode+2),
                                degraded,
                                &decoded));
    EXPECT_EQ(2u, decoded.size());
    EXPECT_EQ(3u, decoded[0].length());
    EXPECT_EQ('A', decoded[0][0]);
    EXPECT_EQ('B', decoded[0][1]);
    EXPECT_EQ('C', decoded[0][2]);
    EXPECT_EQ('D', decoded[1][0]);
    EXPECT_EQ('E', decoded[1][1]);
  }
}

TEST(ErasureCodeShec, decode)
{
  ErasureCodeShec shec;

#define LARGE_ENOUGH 2048
  bufferptr in_ptr(buffer::create_page_aligned(LARGE_ENOUGH));
  in_ptr.zero();
  in_ptr.set_length(0);
  const char *payload =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  in_ptr.append(payload, strlen(payload));
  bufferlist in;
  in.push_front(in_ptr);
  int want_to_encode[] = { 0, 1, 2 };
  map<int, bufferlist> encoded;
  EXPECT_EQ(0, shec.encode(set<int>(want_to_encode, want_to_encode+3),
                              in,
                              &encoded));
  EXPECT_EQ(3u, encoded.size());

  // successfull decode
  bufferlist out;
  EXPECT_EQ(0, shec.decode_concat(encoded, &out));
  bufferlist usable;
  usable.substr_of(out, 0, in.length());
  EXPECT_TRUE(usable == in);

  // cannot recover
  map<int, bufferlist> degraded;
  degraded[0] = encoded[0];
  EXPECT_EQ(-ERANGE, shec.decode_concat(degraded, &out));
}

TEST(ErasureCodeShec, create_ruleset)
{
  CrushWrapper *c = new CrushWrapper;
  c->create();
  c->set_type_name(2, "root");
  c->set_type_name(1, "host");
  c->set_type_name(0, "osd");

  int rootno;
  c->add_bucket(0, CRUSH_BUCKET_STRAW, CRUSH_HASH_RJENKINS1,
		5, 0, NULL, NULL, &rootno);
  c->set_item_name(rootno, "default");

  map<string,string> loc;
  loc["root"] = "default";

  int num_host = 2;
  int num_osd = 5;
  int osd = 0;
  for (int h=0; h<num_host; ++h) {
    loc["host"] = string("host-") + stringify(h);
    for (int o=0; o<num_osd; ++o, ++osd) {
      c->insert_item(g_ceph_context, osd, 1.0, string("osd.") + stringify(osd), loc);
    }
  }

  stringstream ss;
  ErasureCodeShec shec;
  EXPECT_EQ(0, shec.create_ruleset("myrule", *c, &ss));
}

*/

int main(int argc, char **argv) {
  vector<const char*> args;
  argv_to_vec(argc, (const char **)argv, args);

  global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT, CODE_ENVIRONMENT_UTILITY, 0);
  common_init_finish(g_ceph_context);

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

void* thread1(void* pParam)
{
	clock_t start,end;
	ErasureCodeShec* shec = (ErasureCodeShec*)pParam;
	set<int> want_to_decode;
	set<int> available_chunks;
	set<int> minimum_chunks;

	want_to_decode.insert(0);
	want_to_decode.insert(1);
	available_chunks.insert(0);
	available_chunks.insert(1);
	available_chunks.insert(2);

	start = clock();
	start = start / CLOCKS_PER_SEC;
	end = clock();
	end = end / CLOCKS_PER_SEC;
	printf("*** thread loop start ***\n");
	while ((start+3)>end)
	{
		shec->minimum_to_decode(want_to_decode,available_chunks,&minimum_chunks);
		end = clock();
		end = end / CLOCKS_PER_SEC;
	}
	printf("*** thread loop end ***\n");
}

void* thread2(void* pParam)
{
	clock_t start,end;
	ErasureCodeShec* shec = (ErasureCodeShec*)pParam;
	set<int> want_to_decode;
	map<int,int> available_chunks;
	set<int> minimum_chunks;

	want_to_decode.insert(0);
	want_to_decode.insert(1);
	available_chunks[0] = 0;
	available_chunks[1] = 1;
	available_chunks[2] = 2;

	start = clock();
	start = start / CLOCKS_PER_SEC;
	end = clock();
	end = end / CLOCKS_PER_SEC;
	printf("*** thread loop start ***\n");
	while ((start+3)>end)
	{
		shec->minimum_to_decode_with_cost(want_to_decode,available_chunks,&minimum_chunks);
		end = clock();
		end = end / CLOCKS_PER_SEC;
	}
	printf("*** thread loop end ***\n");
}

void* thread3(void* pParam)
{
	clock_t start,end;
	ErasureCodeShec* shec = (ErasureCodeShec*)pParam;

	CrushWrapper *crush = new CrushWrapper;
	crush->create();
	crush->set_type_name(2, "root");
	crush->set_type_name(1, "host");
	crush->set_type_name(0, "osd");

	int rootno;
	crush->add_bucket(0, CRUSH_BUCKET_STRAW, CRUSH_HASH_RJENKINS1, 5, 0, NULL, NULL, &rootno);
	crush->set_item_name(rootno, "default");

	map<string,string> loc;
	loc["root"] = "default";

	int num_host = 2;
	int num_osd = 5;
	int osd = 0;
	for (int h = 0; h < num_host; ++h) {
		loc["host"] = string("host-") + stringify(h);
		for (int o = 0; o < num_osd; ++o, ++osd) {
			crush->insert_item(g_ceph_context, osd, 1.0, string("osd.") + stringify(osd), loc);
		}
	}

	stringstream ss;
	int i = 0;
	char name[30];
	start = clock();
	start = start / CLOCKS_PER_SEC;
	end = clock();
	end = end / CLOCKS_PER_SEC;
	printf("*** thread loop start ***\n");
	while ((start+3)>end)
	{
		sprintf(name,"myrule%d",i);
		shec->create_ruleset(name,*crush,&ss);
		end = clock();
		end = end / CLOCKS_PER_SEC;
		i++;
	}
	printf("*** thread loop end ***\n");
}

void* thread4(void* pParam)
{
	clock_t start,end;
	ErasureCodeShec* shec = (ErasureCodeShec*)pParam;

	bufferlist in;
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//248
			);
	set<int> want_to_encode;
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);

	map<int, bufferlist> encoded;

	start = clock();
	start = start / CLOCKS_PER_SEC;
	end = clock();
	end = end / CLOCKS_PER_SEC;
	printf("*** thread loop start ***\n");
	while ((start+3)>end)
	{
		shec->encode(want_to_encode, in, &encoded);
		end = clock();
		end = end / CLOCKS_PER_SEC;
		encoded.clear();
	}
	printf("*** thread loop end ***\n");
}

void* thread5(void* pParam)
{
	clock_t start,end;
	ErasureCodeShec* shec = (ErasureCodeShec*)pParam;

	bufferlist in;
	in.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//length = 62
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//124
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//186
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//248
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"	//310
			);
	set<int> want_to_encode;
	for(unsigned int i = 0; i < shec->get_chunk_count(); i++)
		want_to_encode.insert(i);
	map<int,bufferlist> encoded;
	shec->encode(want_to_encode, in, &encoded);

	int want_to_decode[] = { 0, 1, 2, 3, 4, 5};
	map<int, bufferlist> decoded;

	start = clock();
	start = start / CLOCKS_PER_SEC;
	end = clock();
	end = end / CLOCKS_PER_SEC;
	printf("*** thread loop start ***\n");
	while ((start+3)>end)
	{
		shec->decode(set<int>(want_to_decode, want_to_decode+2), encoded, &decoded);
		end = clock();
		end = end / CLOCKS_PER_SEC;
		decoded.clear();
	}
	printf("*** thread loop end ***\n");
}
