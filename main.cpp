#define  WPCAP
#define  HAVE_REMOTE

#include "pcap.h"
#include "packetheader.h"


void packet_handler(const u_char *pkt_data, bpf_u_int32 len);


int main()
{
pcap_if_t *alldevs;
pcap_if_t *d;
int inum;
int i=0;
pcap_t *adhandle;
int res;
char errbuf[PCAP_ERRBUF_SIZE];
struct tm ltime;
char timestr[16];
struct pcap_pkthdr *header;
const u_char *pkt_data;
time_t local_tv_sec;

    /* Retrieve the device list on the local machine */
    if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):",i);
    scanf_s("%d", &inum);

    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

    /* Open the device */
    if ( (adhandle= pcap_open(d->name,          // name of the device
                              65536,            // portion of the packet to capture.
                                                // 65536 guarantees that the whole packet will be captured on all the link layers
                              PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
                              1000,             // read timeout
                              NULL,             // authentication on the remote machine
                              errbuf            // error buffer
                              ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;\
    }

    printf("\nlistening on %s...\n", d->description);

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    /* Retrieve the packets */
    while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0){

        if(res == 0)
            /* Timeout elapsed */
            continue;

        /* convert the timestamp to readable format */
        local_tv_sec = header->ts.tv_sec;
        localtime_s(&ltime, &local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);

        printf("#PACKET TIME : %s, %.6d LENGTH:%d\n", timestr, header->ts.tv_usec, header->len);

        /* Packet Parsing*/
        packet_handler(pkt_data, header->len);
    }

    if(res == -1){
        //printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        return -1;
    }

    return 0;
}

void packet_handler(const u_char *pkt_data, bpf_u_int32 len){
    struct libnet_ethernet_hdr *EtherHeader;
    struct libnet_ipv4_hdr *IPv4Header;
    struct libnet_tcp_hdr *TCPHeader;
    const u_char *pkt_data_pos;
    u_char data[1500];
    int i=0;


    /*Etherenet Header*/
    pkt_data_pos=pkt_data;
    EtherHeader=(libnet_ethernet_hdr*)(pkt_data_pos);
    printf("Destination MAC Address : %02X:%02X:%02X:%02X:%02X:%02X\n",
           EtherHeader->ether_dhost[0],
            EtherHeader->ether_dhost[1],
            EtherHeader->ether_dhost[2],
            EtherHeader->ether_dhost[3],
            EtherHeader->ether_dhost[4],
            EtherHeader->ether_dhost[5]);
    printf("Source MAC Address : %02X:%02X:%02X:%02X:%02X:%02X\n",
           EtherHeader->ether_shost[0],
            EtherHeader->ether_shost[1],
            EtherHeader->ether_shost[2],
            EtherHeader->ether_shost[3],
            EtherHeader->ether_shost[4],
            EtherHeader->ether_shost[5]);

    /*IPv4 Header*/
    if(htons(EtherHeader->ether_type)==0x0800)
    {
        pkt_data_pos+=sizeof(*EtherHeader);
        IPv4Header=(libnet_ipv4_hdr*)(pkt_data_pos);
        printf("Source IP Address : %d.%d.%d.%d\n",
               IPv4Header->ip_src[0],
               IPv4Header->ip_src[1],
                IPv4Header->ip_src[2],
                IPv4Header->ip_src[3]);
        printf("Destination IP Address : %d.%d.%d.%d\n",
               IPv4Header->ip_dst[0],
               IPv4Header->ip_dst[1],
                IPv4Header->ip_dst[2],
                IPv4Header->ip_dst[3]);


        /*TCP Header*/
        if(IPv4Header->ip_p==0x06)
        {
            pkt_data_pos+=IPv4Header->ip_hl*4;
            TCPHeader=(libnet_tcp_hdr*)(pkt_data_pos);
            printf("Source Port Number : %d\n", htons(TCPHeader->th_sport));
            printf("Destination Port Number : %d\n", htons(TCPHeader->th_dport));

            /*TCP DATA Part*/
            pkt_data_pos+=TCPHeader->th_off*4;
            int data_length = (int)(len)-14-IPv4Header->ip_hl*4-TCPHeader->th_off*4 ; //total length - ether,ip,tcp header length
            if(data_length>0)
            {
                printf("DATA : \n");
                memcpy_s(data,data_length,pkt_data_pos,data_length);
                for(i=0;i<data_length;i++)
                {
                    printf("%02x ",data[i]);
                    if(i%16==15)
                        printf("\n");
                }
                printf("\n");
            }

        }
    }
    printf("\n");
}
