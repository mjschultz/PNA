#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdint.h>

#include "pna.h"

#define PROC_NODE_STR "/proc/" PNA_PROCDIR "/" PNA_NETFILE
#define BUFSIZE 128

char *prog_name;

void usage()
{
    printf("%s <nets_file>", prog_name);
}

int main (int argc, char** argv)
{
    int c;
    char *nets_file;
    FILE *in_file, *out_file;

    uint32_t output[3];
    char buffer[BUFSIZE];

    prog_name = argv[0];

    if (argc != 2) {
        usage();
        exit(1);
    }

    nets_file = argv[1];
    in_file = fopen(nets_file, "r");
    if (!in_file) {
        printf("failed to open %s\n", nets_file);
        return -1;
    }

    while (fgets(buffer, BUFSIZE, in_file)) {
        if (!isdigit(buffer[0])) {
            continue;
        }

        /* tokenize the string */
        char *ip = strtok(buffer, "/\n");
        char *prefix = strtok(NULL, "/\n");
        char *net = strtok(NULL, "/\n");

        /* make sure we have all parts */
        if (!(ip && prefix && net)) {
            printf("bad string\n");
            printf("----\n%s\n----\n", buffer);
            return -1;
        }

        /* prep for insertion into kernel space */
        output[0] = htonl(inet_addr(ip));
        output[1] = atoi(prefix);
        output[2] = atoi(net);
        if (!(output[1] && output[2])) {
            printf("bad prefix (%s) or net_id (%s)\n", prefix, net);
            return -1;
        }

        /* write to kernel */
        out_file = fopen(PROC_NODE_STR, "w");
        if (!out_file) {
            printf("failed to open %s\n", PROC_NODE_STR);
            return -1;
        }
        fwrite((void *)output, sizeof(uint32_t), 3, out_file); 
        fclose(out_file);
    }

    fclose(in_file);
}
