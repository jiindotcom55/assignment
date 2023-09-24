#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void got_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800은 IP 타입
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP) { // TCP 프로토콜만 처리
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl << 2));

            printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
            printf("Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("Dst IP: %s\n", inet_ntoa(ip->iph_destip));
            printf("Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("Dst Port: %d\n", ntohs(tcp->tcp_dport));
            printf("\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // TCP 패킷만 필터링
    bpf_u_int32 net;

    // step1
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "네트워크 디바이스를 열 수 없습니다: %s\n", errbuf);
        return 1;
    }

    // step2
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    //step3
    pcap_loop(handle, 0, got_packet, NULL);

    // step4 PCAP 핸들 닫기
    pcap_close(handle);

    return 0;
}