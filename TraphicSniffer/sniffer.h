#pragma once
#ifndef SNIFFER_H
#define SNIFFER_H
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "Ws2_32.lib")

#include <WinSock2.h>
#include <fstream>
#include <iostream>

typedef struct IPHeader {
    UCHAR   iph_verlen;   // ������ � ����� ���������
    UCHAR   iph_tos;      // ��� �������
    USHORT  iph_length;   // ����� ����� ������
    USHORT  iph_id;       // �������������
    USHORT  iph_offset;   // ����� � ��������
    UCHAR   iph_ttl;      // ����� ����� ������
    UCHAR   iph_protocol; // ��������
    USHORT  iph_xsum;     // ����������� �����
    ULONG   iph_src;      // IP-����� �����������
    ULONG   iph_dest;     // IP-����� ����������
} IPHeader;

#define SIZE 65536
using namespace std;

class sniffer {
public:
    sniffer();
    sniffer(const char *file_name);
    void sniff();
    ~sniffer();

private:
    void socket_init();
    void write_log(char *buffer, fstream& file, IPHeader *hdr, IN_ADDR ia, WORD size);

    SOCKET sock;
    CHAR host_name[16];
    HOSTENT *phe;
    SOCKADDR_IN socket_addr;
    CHAR buffer[SIZE], file_name;

    bool log = false;

    fstream file;

    
};

#endif