#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
        char * number_str = BN_bn2dec(a);
        printf("%s %s\n", msg, number_str);
        OPENSSL_free(number_str);
}

// r = a ** e mod m
int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m)
{
	BN_CTX *ctx = BN_CTX_new();
	BN_one(r);

	while (!BN_is_zero(e))
	{
		if (BN_is_odd(e))
		{
			// r = (r * a) % m
			if (!BN_mod_mul(r, r, a, m, ctx))
			{
				BN_CTX_free(ctx);
				return 0;
			}
		}

		// a = (a * a) % m
		if (!BN_mod_mul(a, a, a, m, ctx))
		{
			BN_CTX_free(ctx);
			return 0;
		}

		// e = e / 2
		if (!BN_rshift1(e,e))
		{
			BN_CTX_free(ctx);
			return 0;
		}
	}
	BN_CTX_free(ctx);
	return 1;
}

int main (int argc, char *argv[])
{
        BIGNUM *a = BN_new();
        BIGNUM *e = BN_new();
        BIGNUM *m = BN_new();
        BIGNUM *res = BN_new();

        if(argc != 4){
                printf("usage: exp base exponent modulus\n");
                return -1;
        }

        BN_dec2bn(&a, argv[1]);
        BN_dec2bn(&e, argv[2]);
        BN_dec2bn(&m, argv[3]);
        printBN("a = ", a);
        printBN("e = ", e);
        printBN("m = ", m);

        ExpMod(res,a,e,m);

        printBN("a**e mod m = ", res);

        if(a != NULL) BN_free(a);
        if(e != NULL) BN_free(e);
        if(m != NULL) BN_free(m);
        if(res != NULL) BN_free(res);

        return 0;
}
