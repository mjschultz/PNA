/* URL Packet Sniffer
 It needs to be able to grab the URL from the packets and look for "suspect" url"s.
 once the suspect url is found, then it should send a notification to the network
 admin with the IP address of the computer and what they were attempting.
*/

#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define N_REGEX 34

/* Predefine the two functions being used */
int alert_system(char *);
void packet_reader(void *payload);

/* List of Regualr Expressions */
char *reg_expr[N_REGEX] = {
"^null$",
"/\.\./\.\./\.\./",
"\.\./\.\./config\.sys",
"/\.\./\.\./\.\./autoexec\.bat",
"/\.\./\.\./windows/user\.dat",
"\\\x02\\\xb1",
"\\\x04\\\x01",
"\\\x05\\\x01",
"\\\x90\\\x02\\\xb1\\\x02\\\xb1",
"\\\x90\\\x90\\\x90\\\x90",
"\\\xff\\\xff\\\xff\\\xff",
"\\\xe1\\\xcd\\\x80",
"\\\xff\xe0\\\xe8\\\xf8\\\xff\\\xff\\\xff-m",
"\\\xc7f\\\x0c",
"\\\x84o\\\x01",
"\\\x81",
"\\\xff\\\xe0\\\xe8",
"\/c\+dir",
"\/c\+dir\+c",
"\.htpasswd",
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
"author\.exe",
"boot\.ini",
"cmd\.exe",
"c%20dir%20c",
"default\.ida",
"fp30reg\.dll",
"httpodbc\.dll",
"nsiislog\.dll",
"passwd$",
"root\.exe",
"shtml\.exe",
"win\.ini",
"xxxxxxxxxxxxxxxxxxxxxx"};

/*The alert system will print if one or more of the regular expressions apprear */
int alert_system(char *payload)
{

	/* set needed variables */
    int i, match;
    char errbuf[1024];
	regex_t regexes[N_REGEX];
	int ret;

    /* compile regexes -- should be in an initilization function */
    for (i = 0; i < N_REGEX; i++) {
        ret = regcomp(&regexes[i], reg_expr[i], 0);
        if (ret) {
            fprintf(stderr, "failed to compile regex\n");
            exit(1);
        }
    }

    
    /* check the recieved string against the set of regexes */
    for (i = 0; i < N_REGEX; i++) {
        match = regexec(&regexes[i], payload, 0, NULL, 0);
        if (REG_NOMATCH != match) {

            // match found, return match index
			printf("%s\n", reg_expr[i]);
			printf("Regular Expression found, contacting Network Admin\n");
			return 1;
        }

        else if (REG_NOMATCH == match) {
            /* no match here, continue to next regex */
            continue;

        }
        else {
            // catch odd-ball errors
            regerror(match, &regexes[i], errbuf, sizeof(errbuf));
            fprintf(stderr, "regex match failed: %s\n", errbuf);
            return -1;
        } 
    }

    return -1;
}

/*the packet reader, takes in the payload of the packet */
void packet_reader(void *payload)
{
	/* Make the index of the \r\n to catch the end of the GET*/
	char *index;

	/* Check to make sure we have a GET call, then index and grab */
	if(strstr(payload, "GET") != NULL && strstr(payload, "HTTP/1.") != NULL) {
	index = strstr(payload, "\r\n");
	index[0] = "\0";
	printf("payload\n");
	printf("%s\n",(char *)payload);
	alert_system((char *)payload);
	}
	else {
	printf("GET is not found\n");
	}
}
/* FIN */
