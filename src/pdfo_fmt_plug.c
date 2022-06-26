/* PDF owner password cracker patch for JtR. Hacked together based on pdf_fmt_plug.c by
 * Didier Stevens <didier.stevens at gmail.com>.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pdfo;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pdfo);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
#include "md5.h"
#include "aes.h"
#include "sha2.h"
#include "rc4.h"
#include "pdfcrack_md5.h"
#include "loader.h"

#define FORMAT_LABEL        "PDFO"
#define FORMAT_NAME         ""
#define FORMAT_TAG          "$pdfo$"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME      "MD5 RC4 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0x507
#define PLAINTEXT_LENGTH    32
#define BINARY_SIZE         0
#define SALT_SIZE           sizeof(struct custom_salt)
#define BINARY_ALIGN        1
#define SALT_ALIGN          sizeof(int)
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  4

#ifndef OMP_SCALE
#define OMP_SCALE           8 // Tuned w/ MKPC for core i7
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;
static int any_cracked;
static size_t cracked_size;

static struct custom_salt {
	int V;
	int R;
	unsigned char u[127];
	unsigned char o[127];
	int length;
	int length_u;
	int length_o;
} *crypt_out;

static struct fmt_tests pdf_tests[] = {
	{"$pdfo$1*2*40*32*7303809eaf677bdb5ca64b9d8cb0ccdd47d09a7b28ad5aa522c62685c6d9e499*4*test", "test"},
	{"$pdfo$1*2*40*32*be72ff4450d87231d318b78f204e7589bc882e5a842c5b529f1f9dd0ac4de2fc*0*", "secret"},
	{"$pdfo$2*3*128*32*09523923ee2f8e95c3e4688a1b508d6c7540d52a4afafd4cb2a8fa796b335116*4*test", "secret"},
	{NULL}
};

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr;
	char *p;
	int res;

	if (strncmp(ciphertext,  FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* V */
		goto err;
	if (!isdec(p)) goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* R */
		goto err;
	if (!isdec(p)) goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* length */
		goto err;
	if (!isdec(p)) goto err;
	res = atoi(p);
	if (res > 256)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* length_o */
		goto err;
	if (!isdec(p)) goto err;
	res = atoi(p);
	if (res > 127)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* o */
		goto err;
	if (strlen(p) != res * 2)
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* length_u */
		goto err;
	if (!isdec(p)) goto err;
	res = atoi(p);
	if (res > 127)
		goto err;
	if (res > 0) {
		if ((p = strtokm(NULL, "*")) == NULL)	/* u */
			goto err;
		if (strlen(p) != res)
			goto err;
	}
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	return split_fields[1];
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;
	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$pdfo$" marker */
	p = strtokm(ctcopy, "*");
	cs.V = atoi(p);
	p = strtokm(NULL, "*");
	cs.R = atoi(p);
	p = strtokm(NULL, "*");
	cs.length = atoi(p);
	p = strtokm(NULL, "*");
	cs.length_o = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.length_o; i++)
		cs.o[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.length_u = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.length_u; i++)
		cs.u[i] = p[i];
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	crypt_out = (struct custom_salt *)salt;
}

static void pdf_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}


static const unsigned char padding[32] =
{
        0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41,
        0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
        0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
        0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a
};


/* Compute an encryption key (PDF 1.7 algorithm 3.2) */
static void
pdf_compute_encryption_key(unsigned char *password, int pwlen, unsigned char *key)
{
        unsigned char buf[32];
        int n;
        MD5_CTX md5;

        n = crypt_out->length / 8;

        /* Step 1 - copy and pad password string */
        if (pwlen > 32)
                pwlen = 32;
        memcpy(buf, password, pwlen);
        memcpy(buf + pwlen, padding, 32 - pwlen);

        /* Step 2 - init md5 and pass value of step 1 */
        MD5_Init(&md5);
        MD5_Update(&md5, buf, 32);

        /* Step 7 - finish the hash */
        MD5_Final(buf, &md5);

        /* Step 8 (revision 3 or greater) - do some voodoo 50 times */
        if (crypt_out->R >= 3)
        {
                /* for (i = 0; i < 50; i++)
                {
                        MD5_Init(&md5);
                        MD5_Update(&md5, buf, n);
                        MD5_Final(buf, &md5);
                } */
                md5_50(buf);
        }
        /* Step 9 - the key is the first 'n' bytes of the result */
        memcpy(key, buf, n);
}

/* Computing the owner password (PDF 1.7 algorithm 3.3) */

static void pdf_compute_owner_password(unsigned char *password,  unsigned char *output)
{

	int pwlen = strlen((char*)password);
	unsigned char key[128];
	unsigned char key2[128];
	unsigned char buf[32];
	unsigned int opwlen;

	if (crypt_out->R == 2) {
		RC4_KEY arc4;
		int n;
		n = crypt_out->length / 8;
		pdf_compute_encryption_key(password, pwlen, key);
		RC4_set_key(&arc4, n, key);
		opwlen = crypt_out->length_u;
		if (opwlen > 32)
				opwlen = 32;
		memcpy(buf, crypt_out->u, opwlen);
		memcpy(buf + opwlen, padding, 32 - opwlen);
		RC4(&arc4, 32, buf, output);
	}
	else if (crypt_out->R >= 3) {
		RC4_KEY arc4;
		int n;
		unsigned char i;
		int j;

		n = crypt_out->length / 8;
		pdf_compute_encryption_key(password, pwlen, key);
		RC4_set_key(&arc4, n, key);
		opwlen = crypt_out->length_u;
		if (opwlen > 32)
				opwlen = 32;
		memcpy(buf, crypt_out->u, opwlen);
		memcpy(buf + opwlen, padding, 32 - opwlen);
		RC4(&arc4, 32, buf, output);
		
		for (i = 1; i <= 19; i++)
		{
			for (j = 0; j < n; j++)
				key2[j] = key[j] ^ i;
			RC4_set_key(&arc4, n, key2);
			memcpy(buf, output, 32);
			RC4(&arc4, 32, buf, output);
		}
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char output[32];
		pdf_compute_owner_password((unsigned char*)saved_key[index], output);
		if (crypt_out->R == 2 || crypt_out->R == 5 || crypt_out->R == 6)
			if (memcmp(output, crypt_out->o, 32) == 0) {
				cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		if (crypt_out->R == 3 || crypt_out->R == 4)
			if (memcmp(output, crypt_out->o, 16) == 0) {
				cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return cracked[index];
}

/*
 * Report revision as tunable cost, since between revisions 2 and 6,
 * only revisions 3 and 4 seem to have a similar c/s rate.
 */
static unsigned int pdf_revision(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->R;
}

struct fmt_main fmt_pdfo = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{
			"revision",
		},
		{ FORMAT_TAG },
		pdf_tests
	},
	{
		init,
		done,
		fmt_default_reset,
		prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
		pdf_revision,
	},
	fmt_default_source,
	{
		fmt_default_binary_hash
	},
	fmt_default_salt_hash,
	NULL,
	set_salt,
	pdf_set_key,
	get_key,
	fmt_default_clear_keys,
	crypt_all,
	{
		fmt_default_get_hash
	},
	cmp_all,
	cmp_one,
	cmp_exact
}
};

#endif /* plugin stanza */
