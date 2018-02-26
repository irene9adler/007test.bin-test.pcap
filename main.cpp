#include <stdio.h>
#include "pcap.h"


int main()
{
    unsigned char ether[12]={0x00};
    unsigned char type[2] = {0x08,0x00};
    unsigned char buff[1514];//1514??
    FILE * fp;
    if(!fp = fopen("007test.bin","rb"))
        printf("file open err!\n");

    pcap_t * pcaphandle;

    pcap_dumper_t * pcapdump;
    struct pcap_pkthdr pkthdr;

    pcaphandle = pcap_open_dead();//参数含义
    if(!pcaphandle) printf("open dead failed!\n");

    pcapdump = pcap_dump_open(pcaphandle,"test.pcap");
    if(!pcapdump) printf("pcap dump failed!\n");

    int ip_length;
    char ch,len_h,len_l;
    while(getc(fp)==0x45)
    {
        fseek(fp,1L,SEEK_CUR);//1L??
        len_h = getc(fp);
        len_l = getc(fp);
        ip_length = len_h*256+len_l;
        fseek(fp,-4L,SEEK_CUR);
        memset(buff,0,sizeof(buff));
        memcpy(buff,ether,12);
        memcpy(buff+12,type,2);

        fread(buff,1L,ip_length,fp);
        pcap_dump((unsigned char*),&pcaphandle,buff);  //把     pcap_dumper_t * 强制转成unigned char *？
    }
    pcap_dump_close(pcaphandle);
    fclose(fp);

    return 0;
}
