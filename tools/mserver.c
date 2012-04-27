// Multicast Server
// written for LINUX
// Version 0.0.2
//
// Change: IP_MULTICAST_LOOP : Enable / Disable loopback for outgoing messages
// 
// Compile : gcc -o server server.c
//
// This code has NOT been tested
// 

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAXBUFSIZE 65536 // Max UDP Packet size is 64 Kbyte

void dump(const char* buf, size_t size)
{
    size_t pos;

    for (pos=0; pos<size; ++pos) {
    
        if ((pos & 0xf) == 0) {
            printf("%04x | ", pos & 0xFF); 
        }

        printf("%02x ", buf[pos] & 0xFF);
    
        // fill the end of the line if necessary
        if ((pos+1) == size) {
            size_t curr = pos;
            while ((curr & 0xf) != 0xf) {
                printf("   ");
                ++curr;
            }
        }

        // dump printable characters
        if ((pos & 0xf) == 0xf || (pos+1) == size) {
            printf("| ");
            size_t curr = pos & ~(0xf);
            size_t i;
            for (i=0; i<=0xf; ++i) {
                size_t tmp = curr + i;
                char     c;
                if (tmp < size) {
                    c = buf[tmp];
                } else {
                    c = 0;
                }

                if (isprint(c)) printf("%c", c);
                else printf("%c", '.');
            }
        }
    }
    printf("\n");
}

void usage()
{
    printf("Usage: mserver GROUP IP_ADDRESS\n");
}

int main(int argc, char* argv[])
{
   int sock, status, socklen;
   char buffer[MAXBUFSIZE];
   struct sockaddr_in saddr;
   struct ip_mreq imreq;

    if (argc < 3) {
        usage();
        return;
    }

   // set content of struct saddr and imreq to zero
   memset(&saddr, 0, sizeof(struct sockaddr_in));
   memset(&imreq, 0, sizeof(struct ip_mreq));

   // open a UDP socket
   sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
   if ( sock < 0 )
     perror("Error creating socket"), exit(0);

   saddr.sin_family = PF_INET;
   saddr.sin_port = htons(4096); // listen on port 4096
   // saddr.sin_addr.s_addr = inet_addr("10.0.0.1"); //htonl(INADDR_ANY); // bind socket to any interface
   // saddr.sin_addr.s_addr = inet_addr("10.0.0.1"); //htonl(INADDR_ANY); // bind socket to any interface
   saddr.sin_addr.s_addr = htonl(INADDR_ANY); // bind socket to any interface
   status = bind(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));

   if ( status < 0 )
     perror("Error binding socket to interface"), exit(0);

   imreq.imr_multiaddr.s_addr = inet_addr(argv[1]);
   //imreq.imr_interface.s_addr = inet_addr("10.0.1.1"); //INADDR_ANY; // use DEFAULT interface
   imreq.imr_interface.s_addr = inet_addr(argv[2]); //INADDR_ANY; // use DEFAULT interface

   // JOIN multicast group on default interface
   status = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
              (const void *)&imreq, sizeof(struct ip_mreq));

   socklen = sizeof(struct sockaddr_in);

   // receive packet from socket
   status = recvfrom(sock, buffer, MAXBUFSIZE, 0, 
                     (struct sockaddr *)&saddr, &socklen);

    for (;;) {
        status = recvfrom(sock, buffer, MAXBUFSIZE, 0,
                          (struct sockaddr *)&saddr, &socklen);

        if (status < 0) {
            fprintf(stderr, "(EE) Unable to recvfrom: %s\n", strerror(errno)); 
            return -1;
        }
    
        printf("%d bytes received\n", status);

        dump(buffer, status);
    }

    printf("++ received: %d\n", status);

   // shutdown socket
   shutdown(sock, 2);
   // close socket
   close(sock);

   return 0;
}
