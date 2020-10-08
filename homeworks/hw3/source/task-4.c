#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>

#define MAX_BITS 3
#define MAX_STR_LENG 10
#define MESSAGE "hello"

unsigned long mix()
{
    unsigned long a = clock();
    unsigned long b = time(NULL);
    unsigned long c = getpid();
    a = a - b;  a = a - c;  a = a^(c >> 13);
    b = b - c;  b = b - a;  b = b^(a << 8);
    c = c - a;  c = c - b;  c = c^(b >> 13);
    a = a - b;  a = a - c;  a = a^(c >> 12);
    b = b - c;  b = b - a;  b = b^(a << 16);
    c = c - a;  c = c - b;  c = c^(b >> 5);
    a = a - b;  a = a - c;  a = a^(c >> 3);
    b = b - c;  b = b - a;  b = b^(a << 10);
    c = c - a;  c = c - b;  c = c^(b >> 15);

    return c;
}

int randString(char *string)
{
    int a = 'a', z = 'z';

    srand(mix());

    for (int i = 0; i < MAX_STR_LENG; i++)
    {
        string[i] = rand() % (z - a + 1) + a;
    }
}

int main(int argc, char *argv[])
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
#ifdef FIRST
    char *mess1 = calloc(MAX_STR_LENG, sizeof(char));
#endif
#ifdef SECOND
    char mess1[] = MESSAGE;
#endif
    char *mess2 = calloc(MAX_STR_LENG, sizeof(char));

    unsigned char md_value1[EVP_MAX_MD_SIZE], md_value2[EVP_MAX_MD_SIZE];
    unsigned int md_len1, md_len2;
    unsigned int exit_flag;
    unsigned long counter;

    if (argv[1] == NULL)
    {
        printf("Usage: mdtest digestname\n");
        exit(1);
    }

    md = EVP_get_digestbyname(argv[1]);
    if (md == NULL)
    {
        printf("Unknown message digest %s\n", argv[1]);
        exit(1);
    }

    mdctx = EVP_MD_CTX_new();

#ifdef FIRST
    randString(mess1);
#endif

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, mess1, strlen(mess1));
    EVP_DigestFinal_ex(mdctx, md_value1, &md_len1);

    exit_flag = 0;
    counter = 0;
    while (exit_flag == 0)
    {
        int comp = 0;

        randString(mess2);
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, mess2, strlen(mess2));
        EVP_DigestFinal_ex(mdctx, md_value2, &md_len2);

        comp = strncmp(md_value1, md_value2, MAX_BITS);

        counter++;

        if (comp == 0 && strncmp(mess1, mess2, MAX_STR_LENG) != 0)
        {
            EVP_MD_CTX_free(mdctx);
            exit_flag = 1;
        }

        printf("%lu, ", counter);
        for (int i = 0; i < MAX_BITS; i++)
        {
            printf("%02x", md_value1[i]);
        }
        printf(", ");
        for (int i = 0; i < MAX_BITS; i++)
        {
            printf("%02x", md_value2[i]);
        }
        printf("\n");
    }

    printf("\n\nDONE!!!\n");
    printf("%lu, mess1: %s, mess2: %s\n", counter, mess1, mess2);

    printf("mess1 digest is: ");
    for (int i = 0; i < md_len1; i++)
    {
        printf("%02x", md_value1[i]);
    }
    printf("\n");

    printf("mess2 digest is: ");
    for (int i = 0; i < md_len2; i++)
    {
        printf("%02x", md_value2[i]);
    }
    printf("\n");

    free(mess2);
#ifdef FIRST
    free(mess1);
#endif
    exit(0);
}
