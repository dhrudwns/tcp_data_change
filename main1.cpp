#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include <regex>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#define LIBNET_LIL_ENDIAN 1
#include "header.h"

using namespace std;
int flag=0, new_data_len;
unsigned char* new_data;

struct Pseudoheader {
	u_int32_t srcIP;
	u_int32_t destIP;
	u_int8_t reserved=0;
	u_int8_t protocol;
	u_int16_t TCPLen;	// ip_totallen - ip_hl*4
};

u_int16_t calculate(uint16_t* data, int dataLen)
{
	u_int16_t oddbyte, result;
	int sum=0;
	while(dataLen>1) {
		sum+=ntohs(*data++);
		dataLen-=2;
	}
	if(dataLen==1){
		oddbyte=0;
		*((u_char*)&oddbyte)=ntohs(*(u_char*)data);
		sum+=oddbyte;
	}
	sum = (sum>>16) + (sum & 0xffff);
	sum = (sum>>16) + (sum & 0xffff);
	result = (uint16_t)sum;	
	return result;
		
}

uint16_t calTCPChecksum(uint8_t *data,int dataLen)
{
    //make Pseudo Header
    struct Pseudoheader pseudoheader; //saved by network byte order

    //init Pseudoheader
    struct ipv4_hdr *iph=(struct ipv4_hdr*)data;
    struct tcp_hdr *tcph=(struct tcp_hdr*)(data+iph->ip_hl*4);

    memcpy(&pseudoheader.srcIP,&iph->ip_src,sizeof(pseudoheader.srcIP));
    memcpy(&pseudoheader.destIP,&iph->ip_dst,sizeof(pseudoheader.destIP));
    pseudoheader.protocol=iph->ip_p;
    pseudoheader.TCPLen=htons(dataLen-(iph->ip_hl*4));

    //Cal pseudoChecksum
    uint16_t pseudoResult=calculate((uint16_t*)&pseudoheader,sizeof(pseudoheader));

    //Cal TCP Segement Checksum
    tcph->th_sum=0; //set Checksum field 0
    uint16_t tcpHeaderResult=calculate((uint16_t*)tcph,ntohs(pseudoheader.TCPLen));

    uint16_t checksum, temp;
    temp = pseudoResult+tcpHeaderResult;
    temp = (temp >> 16) + (temp & 0xffff);
    temp = (temp >> 16) + (temp & 0xffff);
    checksum = ~temp;
    tcph->th_sum=checksum;
    return checksum;


}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
	 	if (i % 16 == 0)
			printf("\n");
			printf("%02x ", buf[i]);
	}
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    ret = nfq_get_payload(tb, &data);
    if(ret>=0){
    	struct ipv4_hdr *iph = (struct ipv4_hdr *)data;
    	if(iph->ip_p==6){
    		data+=(iph->ip_hl)*4;
		printf("%d", iph->ip_len);
    		struct tcp_hdr *tcph = (struct tcp_hdr *)data;
			if(ntohs(tcph->th_sport)==80){
    				 data+=(tcph->th_off)*4;
				 regex pattern("hacking");
				 string s_data;
				 s_data = (char*) data;
				 smatch m;
					 if(regex_search(s_data, m, pattern)) {
				 		regex find("hacking");
				 		s_data = regex_replace(s_data, find, "hooking");
				 		unsigned char* new_data = (unsigned char*)s_data.c_str();
				 		calTCPChecksum(new_data, ret);
				 		new_data_len = ret;
				 		flag=1;
					   }
			 		else
			 		{
				 		flag=0;
					 }
			}
	}
    }
	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");
    if(flag==1)
    	return nfq_set_verdict(qh, id, NF_ACCEPT, new_data_len, new_data);
    else
	    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
	



        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

