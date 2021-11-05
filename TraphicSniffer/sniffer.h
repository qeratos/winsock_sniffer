#pragma once
#ifndef SNIFFER_H
#define SNIFFER_H
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#if defined(_MSC_VER)
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "shlwapi.lib")
#endif 

#pragma comment(lib, "Ws2_32.lib")

#include <WinSock2.h>
#include <Windows.h>
#include <mmsystem.h>
#include <fstream>
#include <iostream>
#include <thread>

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
#define SIO_RCVALL 0x98000001

using namespace std;

class sniffer {
public:
    sniffer();
    sniffer(const char *file_name);
    sniffer(const char* file_name, bool advance_mode);
    void sniff();
    ~sniffer();

private:
    void advance_mode();
    void socket_init();
    void write_log(char *buffer, fstream& file, IPHeader *hdr, IN_ADDR ia, WORD size);

    SOCKET sock;
    CHAR host_name[16];
    HOSTENT *phe;
    SOCKADDR_IN socket_addr;
    CHAR buffer[SIZE], file_name;
    fstream file;
    thread thr;

    bool log = false, advance_mode_flag = false;
};

#endif