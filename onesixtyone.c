/*  onesixtyone version 0.3.3
    Copyright (C) 2002,2003  solareclipse@phreedom.org

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>

#ifndef INADDR_NONE			/* Solaris is broken */
#define INADDR_NONE -1
#endif

#define MAX_COMMUNITIES 16384
#define MAX_HOSTS 65535
#define MAX_COMMUNITY_SIZE 32

char* snmp_errors[] = {
  "NO ERROR",				/* 0 */
  "TOO BIG",				/* 1 */
  "NO SUCH NAME",			/* 2 */
  "BAD VALUE",			/* 3 */
  "READ ONLY",			/* 4 */
  "GENERIC ERROR",		/* 5 */
  "NO ACCESS",			/* 6 */
  "WRONG TYPE",			/* 7 */
  "WRONG LENGTH",			/* 8 */
  "WRONG ENCODING",		/* 9 */
  "WRONG VALUE",			/* 10 */
  "NO CREATION",			/* 11 */
  "INCONSISTENT VALUE",	/* 12 */
  "RESOURCE UNAVAILABLE",	/* 13 */
  "COMMIT FAILED",		/* 14 */
  "UNDO FAILED",			/* 15 */
  "AUTHORIZATION ERROR",	/* 16 */
  "NOT WRITABLE",			/* 17 */
  "INCONSISTENT NAME",	/* 18 */
};

struct {
  int debug;
  int log;
  int port;
  int print_ip;
  int quiet;
  long wait;
  FILE* log_fd;
} o;

int community_count = 2;
char* community[MAX_COMMUNITIES] = { "public", "private" };

int host_count = 0;
struct {
  int addr;
  char* sysDescr;
  /*	char* communities[];*/
} host[MAX_HOSTS];


void usage()
{
  int i;
  printf("onesixtyone 0.3.3 [options] <host> <community>\n");
  printf("  -c <communityfile> file with community names to try\n");
  printf("  -i <inputfile>     file with target hosts\n");
  printf("  -o <outputfile>    output log\n");
  printf("  -p                 specify an alternate destination SNMP port\n");
  printf("  -d                 debug mode, use twice for more information\n\n");
  printf("  -s                 short mode, only print IP addresses\n\n");
  printf("  -w n               wait n milliseconds (1/1000 of a second) between sending packets (default 10)\n");
  printf("  -q                 quiet mode, do not print log to stdout, use with -l\n");
  printf("host is either an IPv4 address or an IPv4 address and a netmask\n");
  printf("default community names are:");
  for (i = 0; i < community_count; i++) printf(" %s", community[i]);
  printf("\n\n");
  printf("Max number of hosts : \t\t%d\n", MAX_HOSTS);
  printf("Max community length: \t\t%d\n", MAX_COMMUNITY_SIZE);
  printf("Max number of communities: \t%d\n", MAX_COMMUNITIES);
  printf("\n\n");
  printf("examples: onesixtyone 192.168.4.0/24 public\n");
  printf("          onesixtyone -c dict.txt -i hosts -o my.log -w 100\n\n");
}

void read_communities(char* filename)
{
  FILE* fd;
  int i, c;
  int ch;

  if (o.debug > 0) printf("Using community file %s\n", filename);

  if ((fd = fopen(filename, "r")) == 0) {
    printf("Error opening community file %s\n", filename);
    exit(1);
  }

  const int max_c = MAX_COMMUNITY_SIZE - 1;
  for (i = 0; i < MAX_COMMUNITIES && !feof(fd); ++i) {
    char* ptr = (char*)malloc(MAX_COMMUNITY_SIZE);

    if (!ptr) {
        fprintf(stderr, "Failed to allocate memory for community string %d\n", i);
        exit(-1);
    }

    community[i] = ptr;

    community[i][0] = '\0';
    for (c = 0; (ch = fgetc(fd)) != EOF && !isspace(ch); ++c) {
      if (c < max_c) {
        community[i][c] = (char)ch;
        community[i][c + 1] = '\0';
      }
    }
    community[i][max_c] = '\0';
  }

  if (o.debug && i == MAX_COMMUNITIES) {
    printf("MAX_COMMUNITIES (%d) reached. Remaining communities will be skipped \n", i);
  }

  community_count = i;
  fclose(fd);
}

int add_host(const char *ipmask)
{
  int ret = -1;
  char *addr = NULL;
  char *slash;
  struct addrinfo hints;
  struct addrinfo *result = NULL;
  in_addr_t longtmp;
  unsigned long i, ips;
  struct in_addr startaddr;
  struct in_addr endaddr;
  int netmask = 32;

  addr = strdup(ipmask);
  slash = strchr(addr, '/');
  if (slash != NULL) {
    netmask = atoi(slash + 1);
    if (netmask <= 0 || netmask > 32) {
      goto OUT;
    }
    *slash = '\0';
  }


  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;	 /* Allow IPv4 */
  hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV; /* no dns */
  hints.ai_protocol = 0;			 /* IPv4 */
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  if (getaddrinfo(addr, NULL, &hints, &result) != 0) {
    goto OUT;
  }

  longtmp = ntohl(((struct sockaddr_in *)result->ai_addr)->sin_addr.s_addr);
  startaddr.s_addr = longtmp & (0 - (1 << (32 - netmask)));
  endaddr.s_addr = longtmp | ((1 << (32 - netmask)) - 1);
  if (startaddr.s_addr > endaddr.s_addr) {
    goto OUT;
  }

  ips = endaddr.s_addr - startaddr.s_addr + 1;
  for (i = 0; i < ips; i++) {
    if (host_count >= MAX_HOSTS) {
      goto OUT;
    }
    host[host_count++].addr = htonl(startaddr.s_addr++);
  }
  ret = 0;

OUT:
  free(addr);
  freeaddrinfo(result);
  return ret;
}

void read_hosts(char* filename)
{
  FILE* fd;
  char buf[100];
  int ch;
  size_t c;

  if (strcmp(filename, "-") == 0) {
    if (o.debug > 0) printf("Reading hosts from stdin\n");
    fd = stdin;
  }
  else {
    if (o.debug > 0) printf("Reading hosts from input file %s\n", filename);
    if ((fd = fopen(filename, "r")) == 0) {
      printf("Error opening input file %s\n", filename);
      exit(1);
    }
  }

  host_count = 0;
  c = 0; ch = 0;

  do {
    ch = fgetc(fd);
    if (ch == '\n' || ch == ' ' || ch == '\t' || ch == EOF) {
      buf[c] = '\0';
      if (c > 0) {			/* skip blank lines */
        if (add_host((const char*)&buf) == -1) {
          printf("Malformed IP address: %s\n", buf);
          exit(1);
        }
        c = 0;
      }
    }
    else if (ch != '\r') {
      buf[c++] = ch;
    }
    if (c > sizeof(buf) - 1) {
      printf("IP address too long\n");
      exit(1);
    }
  } while (ch != EOF);

  if (fd != stdin) fclose(fd);

  if (o.debug > 0) printf("%d hosts read from file\n", host_count);
}

void init_options(int argc, char *argv[])
{
  char community_filename[250];
  char input_filename[250];
  char log_filename[255];
  int input_file;
  int community_file;

  int arg, i;

  o.debug = 0;
  o.log = 0;
  o.port = 161;
  o.print_ip = 0;
  o.quiet = 0;
  o.wait = 10;
  input_file = 0;
  community_file = 0;

  o.log_fd = NULL;

  while ((arg = getopt(argc, argv, "c:di:o:p:s:w:q")) != EOF) {
    switch (arg) {
    case 'c':	community_file = 1;
      strncpy(community_filename, optarg, sizeof(community_filename));
      break;
    case 'd':	o.debug++;
      break;
    case 'i':	input_file = 1;
      strncpy(input_filename, optarg, sizeof(input_filename));
      break;
    case 'o':	o.log = 1;
      strncpy(log_filename, optarg, sizeof(log_filename));
      break;
    case 'p':
      if (strtol(optarg, NULL, 10) == 0) {
        printf("Malformed port: %s\n", optarg);
        exit(1);
      }
      else {
        o.port = strtol(optarg, NULL, 10);
      }
      break;
    case 's':	o.print_ip = 1;
      break;
    case 'w':  o.wait = atol(optarg);	/* convert to nanoseconds */
      break;
    case 'q':	o.quiet = 1;
      break;
    case '?':  usage();
      exit(1);
      break;
    }
  }

  if (o.debug) {
    if (o.debug > 0) printf("Debug level %d\n", o.debug);
  }

  if (!input_file) {
    if (optind >= argc) {
      usage();
      exit(1);
    }

    if (add_host((const char*)argv[optind++]) == -1) {
      printf("Malformed IP address: %s\n", argv[optind - 1]);
      exit(1);
    }

    if (o.debug > 0) printf("Target ip read from command line: %s\n", argv[optind - 1]);
  }
  else {
    read_hosts((char*)&input_filename);
  }

  if (community_file) {
    read_communities((char*)&community_filename);
  }

  if (optind < argc) {
    if (community_file) {
      usage();
      exit(1);
    }
    community[0] = argv[optind++];
    community_count = 1;
    if (o.debug > 0) printf("Community read from command line: %s\n", community[0]);;
  }

  if (optind < argc) {
    usage();
    exit(1);
  }

  if (o.log) {
    if ((o.log_fd = fopen(log_filename, "w")) == 0) {
      printf("Error opening log file %s\n", log_filename);
      exit(1);
    }
    printf("Logging to file %s\n", log_filename);
  }
  else if (o.quiet && !o.print_ip) {
    printf("Warning: quiet mode specified without logging, you will lose your scan results\n");
  }

  if (o.debug > 0) {
    printf("%d communities:", community_count);
    for (i = 0; i < community_count; i++)
      printf(" %s", community[i]);
    printf("\n");
  }

  if (o.debug > 0) printf("Waiting for %ld milliseconds between packets\n", o.wait);
}

int build_snmp_req(char* buf, size_t buf_size, char* target_community)
{
  int i;
  static int id;
  char object[] = "\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x0\x05\x00";

  if (21 + strlen(target_community) + strlen(object) > buf_size) {
    printf("SNMP packet length exceeded.\nCommunity: %s\nObject: %s\n", target_community, object);
    exit(1);
  }

  if (--id > 0x7ffe) id = 0;

  memset(buf, 0, buf_size);

  buf[0] = 0x30;
  buf[1] = 19 + strlen(target_community) + sizeof(object) - 1;

  // Version: 1
  buf[2] = 0x02;
  buf[3] = 0x01;
  buf[4] = 0x00;

  // Community
  buf[5] = 0x04;
  buf[6] = strlen(target_community);

  strcpy((buf + 7), target_community);
  i = 7 + strlen(target_community);

  // PDU type: GET
  buf[i++] = 0xa0;
  buf[i++] = 12 + sizeof(object) - 1;

  // Request ID
  buf[i++] = 0x02;
  buf[i++] = 0x04;
  buf[i++] = (char)((id >> 24) & 0xff);
  buf[i++] = (char)((id >> 16) & 0xff);
  buf[i++] = (char)((id >> 8) & 0xff);
  buf[i++] = (char)((id >> 0) & 0xff);

  // Error status: no error
  buf[i++] = 0x02;
  buf[i++] = 0x01;
  buf[i++] = 0x00;

  // Error index
  buf[i++] = 0x02;
  buf[i++] = 0x01;
  buf[i++] = 0x00;

  // Object ID
  memcpy((char*)&buf[i], &object, sizeof(object) - 1);
  i = i + sizeof(object) - 1;

  return (i);
}

void logr(char* fmt, ...)
{
  va_list args, args2;

  va_start(args, fmt);

  if (!o.quiet) {
    va_copy(args2, args);
    vprintf(fmt, args2);
    va_end(args2);
  }

  if (o.log)
    vfprintf(o.log_fd, fmt, args);

  va_end(args);
}

int parse_asn_length(u_char* buf, int buf_size, int* i)
{
  int len;
  if (*i >= buf_size) {
    logr("Unable to decode SNMP packet: buffer overflow\n");
    return -1;
  }

  if (buf[*i] < 0x81) {
    len = buf[*i];
    *i += 1;
  }
  else if (buf[*i] == 0x81) {
    *i += 1;
    if ((*i) + 1 > buf_size) {
      logr("Unable to decode SNMP packet: buffer overflow\n");
      return -1;
    }
    len = buf[*i];
    *i += 1;
  }
  else if (buf[*i] == 0x82) {
    *i += 1;
    if ((*i) + 2 > buf_size) {
      logr("Unable to decode SNMP packet: buffer overflow\n");
      return -1;
    }
    len = (buf[*i] << 8) + buf[(*i) + 1];
    *i += 2;
  }
  else if (buf[*i] == 0x83) {
    *i += 1;
    if ((*i) + 3 > buf_size) {
      logr("Unable to decode SNMP packet: buffer overflow\n");
      return -1;
    }
    len = (buf[*i] << 16) + (buf[(*i) + 1] << 8) + buf[(*i) + 2];
    *i += 3;
  }
  else if (buf[*i] == 0x84) {
    *i += 1;
    if ((*i) + 4 > buf_size) {
      logr("Unable to decode SNMP packet: buffer overflow\n");
      return -1;
    }
    len = (buf[*i] << 24) + (buf[(*i) + 1] << 16) + (buf[(*i) + 2] << 8) + buf[(*i) + 3];
    *i += 4;
  }
  else {
    logr("Unable to decode SNMP packet: wrong length\n");
    return -1;
  }

  if ((*i) + len > buf_size) {
    logr("Unable to decode SNMP packet: buffer overflow\n");
    return -1;
  }

  return len;
}

int skip_asn_length(u_char* buf, int buf_size, int* i)
{
  int ret;

  if ((ret = parse_asn_length(buf, buf_size, i)) > 0)
    *i += ret;

  return ret;
}

int parse_asn_integer(u_char* buf, int buf_size, int* i)
{
  int ret;

  if (*i >= buf_size) {
    logr("Unable to decode SNMP packet: buffer overflow\n");
    return -1;
  }

  if (buf[*i] == 0x81) {
    *i += 1;
    if (*i >= buf_size) {
      logr("Unable to decode SNMP packet: buffer overflow\n");
      return -1;
    }
  }

  if (buf[*i] == 0x01) {
    if ((*i) + 2 > buf_size) {
      logr("Unable to decode SNMP packet: buffer overflow\n");
      return -1;
    }
    ret = (int)buf[(*i) + 1];
    *i += 2;
  }
  else if (buf[*i] == 0x02) {
    if ((*i) + 3 > buf_size) {
      logr("Unable to decode SNMP packet: buffer overflow\n");
      return -1;
    }
    ret = ((int)buf[(*i) + 1] << 8) +
      (int)buf[(*i) + 2];
    *i += 3;
  }
  else if (buf[*i] == 0x04) {
    if ((*i) + 5 > buf_size) {
      logr("Unable to decode SNMP packet: buffer overflow\n");
      return -1;
    }
    ret = ((int)buf[(*i) + 1] << 24) +
      ((int)buf[(*i) + 2] << 16) +
      ((int)buf[(*i) + 3] << 8) +
      (int)buf[(*i) + 4];
    *i += 5;
  }
  else {
    logr("Unable to decode SNMP packet: unrecognized integer length\n");
    return -1;
  }

  return ret;
}

int print_asn_string(u_char* buf, int buf_size, int* i)
{
  int ret;
  int string_end;

  if ((ret = parse_asn_length(buf, buf_size, i)) == -1)
    return -1;
  else
    string_end = *i + ret;

  for (; *i < string_end; *i += 1) {
    if (buf[*i] < 0x20 || buf[*i] > 0x80)
      logr(" ");
    else
      logr("%c", buf[*i]);
  }

  return 0;
}

int parse_snmp_header(u_char* buf, int buf_size, int* i)
{
  if (*i >= buf_size) {
    logr("Unable to decode SNMP packet: buffer overflow\n");
    return -1;
  }

  if (buf[(*i)++] != 0x30) {
    logr("Unable to decode SNMP packet: wrong header\n");
    return -1;
  }

  if (parse_asn_length(buf, buf_size, i) < 0)
    return -1;

  return 0;
}

int parse_snmp_version(u_char* buf, int buf_size, int* i)
{
  int ret;

  if (*i >= buf_size) {
    logr("Unable to decode SNMP packet: buffer overflow\n");
    return -1;
  }

  if (buf[(*i)++] != 0x02) {
    logr("Unable to decode SNMP packet: snmp version invalid\n");
    return -1;
  }

  if ((ret = parse_asn_integer(buf, buf_size, i)) == -1)
    return -1;
  else if (ret != 0) {
    logr("Unable to decode SNMP packet: snmp version invalid\n");
    return -1;
  }

  return 0;
}

int parse_snmp_community(u_char* buf, int buf_size, int* i)
{
  if (*i >= buf_size) {
    logr("Unable to decode SNMP packet: buffer overflow\n");
    return -1;
  }

  if (buf[(*i)++] != 0x04) {
    logr("Unable to decode SNMP packet: community name not found\n");
    return -1;
  }

  logr("[");
  if (print_asn_string(buf, buf_size, i) == -1)
    return -1;
  logr("] ");

  return 0;
}

int parse_snmp_pdu(u_char* buf, int buf_size, int* i)
{
  if (*i >= buf_size) {
    logr("Unable to decode SNMP packet: buffer overflow\n");
    return -1;
  }

  if (buf[(*i)++] != 0xa2) {
    logr("Unable to decode SNMP packet: PDU type not RESPONSE (0xa2)\n");
    return -1;
  }

  if (parse_asn_length(buf, buf_size, i) < 0)
    return -1;

  return 0;
}

int parse_snmp_requestid(u_char* buf, int buf_size, int* i)
{
  if (*i >= buf_size) {
    logr("Unable to decode SNMP packet: buffer overflow\n");
    return -1;
  }

  if (buf[(*i)++] != 0x02) {
    logr("Unable to decode SNMP packet: request id invalid\n");
    return -1;
  }
  if (parse_asn_integer(buf, buf_size, i) < 0)
    return -1;

  return 0;
}

int parse_snmp_errorcode(u_char* buf, int buf_size, int* i)
{
  int ret;

  if (*i >= buf_size) {
    logr("Unable to decode SNMP packet: buffer overflow\n");
    return -1;
  }

  if (buf[(*i)++] != 0x02) {
    logr("Unable to decode SNMP packet: error code invalid\n");
    return -1;
  }
  if ((ret = parse_asn_integer(buf, buf_size, i)) < 0)
    return -1;
  if (ret != 0) {
    if (ret < 0 || ret > 18) {
      logr("Unable to decode SNMP packet: error code invalid\n");
      return -1;
    }
    logr("Host responded with error %s\n", snmp_errors[ret]);
    return -1;
  }

  return 0;
}

int parse_snmp_errorindex(u_char* buf, int buf_size, int* i)
{
  if (*i >= buf_size) {
    logr("Unable to decode SNMP packet: buffer overflow\n");
    return -1;
  }

  if (buf[(*i)++] != 0x02) {
    logr("Unable to decode SNMP packet: error index invalid\n");
    return -1;
  }
  if (parse_asn_integer(buf, buf_size, i) < 0)
    return -1;

  return 0;
}

int parse_snmp_objheader(u_char* buf, int buf_size, int* i)
{
  if (*i >= buf_size) {
    logr("Unable to decode SNMP packet: buffer overflow\n");
    return -1;
  }

  if (buf[(*i)++] != 0x30) {
    logr("Unable to decode SNMP packet: invalid object header\n");
    return -1;
  }
  if (parse_asn_length(buf, buf_size, i) < 0)
    return -1;

  return 0;
}

int parse_snmp_objheader6(u_char* buf, int buf_size, int* i)
{
  if (*i >= buf_size) {
    logr("Unable to decode SNMP packet: buffer overflow\n");
    return -1;
  }

  if (buf[(*i)++] != 0x06) {
    logr("Unable to decode SNMP packet: invalid object header\n");
    return -1;
  }
  if (skip_asn_length(buf, buf_size, i) < 0)
    return -1;

  return 0;
}

int parse_snmp_value(u_char* buf, int buf_size, int* i)
{
  if (*i >= buf_size) {
    logr("Unable to decode SNMP packet: buffer overflow\n");
    return -1;
  }

  if (buf[(*i)++] != 0x04) {
    logr("Unable to decode SNMP packet: invalid value\n");
    return -1;
  }
  if (print_asn_string(buf, buf_size, i) < 0)
    return -1;

  return 0;
}

void parse_snmp_response(u_char* buf, int buf_size)
{
  int i;

  i = 0;

  if (parse_snmp_header(buf, buf_size, &i) == -1) return;
  if (parse_snmp_version(buf, buf_size, &i) == -1) return;
  if (parse_snmp_community(buf, buf_size, &i) == -1) return;
  if (parse_snmp_pdu(buf, buf_size, &i) == -1) return;
  if (parse_snmp_requestid(buf, buf_size, &i) == -1) return;
  if (parse_snmp_errorcode(buf, buf_size, &i) == -1) return;
  if (parse_snmp_errorindex(buf, buf_size, &i) == -1) return;

  if (i + 3 <= buf_size && buf[i] == 0x00 && buf[i + 1] == 0x30 && buf[i + 2] == 0x20)	// Bug in an HP JetDirect
    i += 3;

  if (parse_snmp_objheader(buf, buf_size, &i) == -1) return;
  if (parse_snmp_objheader(buf, buf_size, &i) == -1) return;		// yes, this should be called twice
  if (parse_snmp_objheader6(buf, buf_size, &i) == -1) return;
  if (parse_snmp_value(buf, buf_size, &i) == -1) return;

  logr("\n");
}

/* Subtract the `struct timeval' values X and Y,
 * storing the result in RESULT.
 * Return 1 if the difference is negative, otherwise 0.
 */

int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y)
{
  int nsec;

  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait. tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

void receive_snmp(int sock, long wait, struct sockaddr_in* remote_addr)
{
  struct timeval tv_now, tv_until, tv_wait;
  unsigned int remote_addr_len;
  char buf[1500];
  int ret;
  fd_set fds;

  gettimeofday(&tv_now, NULL);
  tv_until.tv_sec = tv_now.tv_sec;
  tv_until.tv_usec = tv_now.tv_usec + wait * 1000;
  if (tv_until.tv_usec >= 1000000) {
    tv_until.tv_sec += tv_until.tv_usec / 1000000;
    tv_until.tv_usec = tv_until.tv_usec % 1000000;
  }

  tv_wait.tv_sec = wait / 1000;
  tv_wait.tv_usec = wait % 1000 * 1000;

  do {
    /* Put the socket into the fd set */
    FD_ZERO(&fds);
    FD_SET(sock, &fds);

    if ((ret = select(sock + 1, &fds, NULL, NULL, &tv_wait)) == -1) {
      printf("Error in pselect\n");
      exit(1);
    }
    else if (ret > 0) {
      memset(&buf, 0x0, sizeof(buf));
      remote_addr_len = sizeof(*remote_addr);

      ret = recvfrom(sock, &buf, sizeof(buf), 0, (struct sockaddr*)remote_addr, &remote_addr_len);
      if (ret < 0) {
        if (errno == ECONNRESET) {
          printf("%s ICMP unreach received\n", inet_ntoa(remote_addr->sin_addr));
        }
        else {
          printf("Error in recvfrom\n");
        }
      }
      logr("%s ", inet_ntoa(remote_addr->sin_addr));
      parse_snmp_response((u_char*)&buf, ret);
      if (o.print_ip) {
        int quiet = o.quiet;
        o.quiet = 0;
        logr("%s\n", inet_ntoa(remote_addr->sin_addr));
        o.quiet = quiet;
      }
      if (o.log) fflush(o.log_fd);
    }

    gettimeofday(&tv_now, NULL);
  } while (timeval_subtract(&tv_wait, &tv_until, &tv_now) == 0);
}

int main(int argc, char* argv[])
{
  struct sockaddr_in local_addr;
  struct sockaddr_in remote_addr;
  int sock;
  int ret;
  int c, i;
  char sendbuf[1500];
  int sendbuf_size;

  init_options(argc, argv);

  /* socket creation */
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    printf("Error creating socket\n");
    exit(1);
  }

  local_addr.sin_family = AF_INET;
  local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  local_addr.sin_port = htons(0);

  ret = bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr));
  if (ret < 0) {
    printf("Error binding socket\n");
    exit(1);
  }

  /* remote address */
  remote_addr.sin_family = AF_INET;
  remote_addr.sin_port = htons(o.port);

  if (!o.quiet) printf("Scanning %d hosts, %d communities\n", host_count, community_count);

  for (c = 0; c < community_count; c++) {
    if (o.debug > 0) printf("Trying community %s\n", community[c]);

    sendbuf_size = build_snmp_req((char*)&sendbuf, sizeof(sendbuf), community[c]);

    for (i = 0; i < host_count; i++) {
      remote_addr.sin_addr.s_addr = host[i].addr;
      if (o.debug > 1) printf("Sending to ip %s\n", inet_ntoa(*(struct in_addr*)&remote_addr.sin_addr.s_addr));

      ret = sendto(sock, &sendbuf, sendbuf_size, 0, (struct sockaddr*)&remote_addr, sizeof(remote_addr));
      if (ret < 0) {
        if (!o.quiet) printf("Error in sendto: %s\n", strerror(errno));
        /* exit(1); */
      }

      receive_snmp(sock, o.wait, &remote_addr);
    }
  }

  if (o.debug > 0) printf("All packets sent, waiting for responses.\n");

  /* wait for 5 seconds */
  receive_snmp(sock, 5000, &remote_addr);

  if (o.debug > 0) printf("done.\n");

  if (o.log) fclose(o.log_fd);

  return 0;
}
