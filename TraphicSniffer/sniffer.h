#pragma once
#ifndef SNIFFER_H
#define SNIFFER_H
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "Ws2_32.lib")

#include <WinSock2.h>
#include <fstream>
#include <iostream>

typedef struct IPHeader {
    UCHAR   iph_verlen;   // версия и длина заголовка
    UCHAR   iph_tos;      // тип сервиса
    USHORT  iph_length;   // длина всего пакета
    USHORT  iph_id;       // Идентификация
    USHORT  iph_offset;   // флаги и смещения
    UCHAR   iph_ttl;      // время жизни пакета
    UCHAR   iph_protocol; // протокол
    USHORT  iph_xsum;     // контрольная сумма
    ULONG   iph_src;      // IP-адрес отправителя
    ULONG   iph_dest;     // IP-адрес назначения
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