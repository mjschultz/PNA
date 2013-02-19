#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdint.h>

#define PROC_NODE_STR "/proc/pna/net"

char *prog_name;

void usage()
{
  printf("%s -f <infilename", prog_name);
}

int main (int argc, char** argv)
{
  int c;
  char* infilename;

  prog_name = argv[0];

  while ((c = getopt(argc, argv, "f:")) != -1) {
    switch(c){
      case 'f':
        infilename = optarg;
        break;
      default:
        usage();
        return -1;
    }
  }

  FILE* infile = fopen(infilename, "r");
  if(!infile){
    printf("failed to open %s\n", infilename);
    return -1;
  }

  FILE* outfile = fopen(PROC_NODE_STR, "w");
  if(!outfile){
    printf("failed to open %s\n", PROC_NODE_STR);
    return -1;
  }

  uint32_t output[3];
  
  char buffer[100];
  while(fgets(buffer, 100, infile)){
    if(buffer[0] == '#')
      continue;
    if(buffer[0] == '\n')
      continue;
    if(buffer[0] == ' ')
      continue;
    char* ipstring = strtok(buffer, "/\n");
    char* prefix_string = strtok(NULL, "/\n");
    char* net_string = strtok(NULL, "/\n");
    if(!ipstring || !prefix_string || !net_string){
      printf("bad string\n", buffer);
      return -1;
    }
    output[1] = atoi(prefix_string);
    output[2] = atoi(net_string);
    if(!output[1] || !output[2]){
      printf("bad string %s or %s\n", prefix_string, net_string);
      return -1;
    }

    output[0] = htonl(inet_addr(ipstring));
    fwrite((void*)output, sizeof(uint32_t), 3, outfile); 
    fclose(outfile);
    FILE* outfile = fopen(PROC_NODE_STR, "w");
    if(!outfile){
      printf("failed to open %s\n", PROC_NODE_STR);
      return -1;
    }
  }
  fclose(infile);
  fclose(outfile); 
}
