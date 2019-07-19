#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

struct ethernet{
    const u_char *dmac;
    const u_char *smac;
    const u_char *type;
};
struct ip{
    const u_char *protocol; //[9]
    const u_char *sip; //[12]
    const u_char *dip; //[16]
};
struct tcp{
    const u_char *sport;
    const u_char *dport;
    const u_char *data;
    int headerLength;
};


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void printMac(const char* what,const u_char* address){
    printf("%s ",what);
    for(int i=0;i<6;i++){
        if(i!=5) printf("%02x:",address[i]);
        else printf("%02x",address[i]);
    }
    printf("\n");
}

void printIp(const char* what,const u_char* address){
    printf("%s ",what);
    for(int i=0;i<4;i++){
        if(i!=3) printf("%d.",address[i]);
        else printf("%d",address[i]);
    }
    printf("\n");
}

void printPort(const char* what, const u_char* address){
    printf("%s ",what);
    uint8_t packet[] = {address[0],address[1]};
    uint16_t *p = reinterpret_cast<uint16_t *>(packet);
    uint16_t port = *p;
    printf("%d\n",ntohs(port));
}

void checkTcpData(const u_char* address){
    int size=0;
    printf("TCP Data: ");
    for(int i=0;address[i];i++){
        size++;
        if(i<10 && size!=0) printf("%02x ",address[i]);
    }
    if(size ==0) printf("null!!");
    printf("\nTCP DATA SIZE= %d\n",size);

}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    printf("=============================\n");
    struct ethernet eth;
    eth.dmac = &packet[0];
    eth.smac = &packet[6];
    eth.type = &packet[12];
    printMac("eth.dmac= ",eth.dmac);
    printMac("eth.smac= ",eth.smac);
    if(eth.type[0] != 0x08 && eth.type[1] != 0x00) continue; // ip check

    packet += 14;
    struct ip i;
    i.protocol = &packet[9];
    i.sip = &packet[12];
    i.dip = &packet[16];
    printIp("ip.sip= ",i.sip);
    printIp("ip.dip= ",i.dip);
    if(i.protocol[0] != 0x06) continue; //tcp check

    packet += 20;
    struct tcp p;
    p.sport = &packet[0];
    p.dport = &packet[2];

    p.headerLength = 4*(packet[12]/16); // for checking start index of tcp data(4bit)
    packet += p.headerLength;
    const u_char *startPointOfTcpData = packet;

   // printf("length: %d\n",p.headerLength);
    printPort("tcp.sport: ",p.sport);
    printPort("tcp.dport: ",p.dport);
    checkTcpData(startPointOfTcpData);

  }
  pcap_close(handle);
  return 0;
}
