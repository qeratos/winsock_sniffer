#include "sniffer.h"
#define SIO_RCVALL 0x98000001


void sniffer::socket_init() {
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
		cout << "Error" << endl;
	}

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sock == INVALID_SOCKET) {
		cout << "INVALID SOCKET "  << WSAGetLastError()<< endl;
	}
	gethostname(host_name, sizeof(host_name));
	phe = gethostbyname(host_name);

	ZeroMemory(&socket_addr, sizeof(socket_addr));

	socket_addr.sin_family = AF_INET;
	socket_addr.sin_addr.s_addr = ((struct in_addr*)phe->h_addr_list[0])->s_addr;

	bind(sock, (SOCKADDR*)&socket_addr, sizeof(SOCKADDR));

	DWORD flag = TRUE;
	ioctlsocket(sock, SIO_RCVALL, &flag);


	//BOOL bOptVal = TRUE;
	//setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&bOptVal, sizeof(BOOL));
	
}

void sniffer::write_log(char *buffer, fstream& file, IPHeader* hdr, IN_ADDR ia, WORD size){
	file.write("--Packet start--\n\n", 18);
	CHAR* pszTargetIP = inet_ntoa(ia);
	file.write("To:", 4);
	file.write(pszTargetIP, lstrlen(pszTargetIP));

	ia.s_addr = hdr->iph_src;
	CHAR* pszSourceIP = inet_ntoa(ia);

	file.write("\tFrom:", 6);
	file.write(pszSourceIP, lstrlen(pszSourceIP));

	file.write("\tProtocol:", 10);

	switch (hdr->iph_protocol) {
	case IPPROTO_IP:
		file.write("IP\n", 4);
		break;

	case IPPROTO_ICMP:
		file.write("ICMP\n", 6);
		break;

	case IPPROTO_IGMP:
		file.write("IGMP\n", 6);
		break;

	case IPPROTO_GGP:
		file.write("GGP\n", 5);
		break;

	case IPPROTO_TCP:
		file.write("TCP\n", 5);
		break;

	case IPPROTO_PUP:
		file.write("PUP\n", 5);
		break;

	case IPPROTO_UDP:
		file.write("UDP\n", 5);
		break;

	case IPPROTO_IDP:
		file.write("IDP\n", 5);
		break;

	case IPPROTO_IPV6:
		file.write("IPv6\n", 6);
		break;

	case IPPROTO_ND:
		file.write("ND\n", 4);
		break;

	case IPPROTO_ICLFXBM:
		file.write("ICLFXBM\n", 9);
		break;

	case IPPROTO_ICMPV6:
		file.write("ICMPv6\n", 8);
		break;
	}

	CHAR szTemp[17];
	wsprintf(szTemp, "%d\n", size);

	file.write("Packet length: ", 15);
	file.write(szTemp, lstrlen(szTemp));
	

	file.write("Contents:\n", 13);
	file.write(&buffer[sizeof(IPHeader) * 2], size - sizeof(IPHeader) * 2);
	file.write("\n--Packet end--\n\n\r", 18);
}

sniffer::sniffer(){
	socket_init();
}

sniffer::sniffer(const char* file_name) {
	socket_init();
	file.open(file_name, std::ios::app);
	if (file.is_open()) {
		log = true;
	}
	else {
		cout << GetLastError() << endl;
	}
}

void sniffer::sniff() {
	bool flag = true;
	IN_ADDR in_addr;

	while(flag) {
		if (recv(sock, buffer, sizeof(buffer), 0) >= sizeof(IPHeader)) {
			IPHeader* hdr = (IPHeader*)buffer;
			WORD size = (hdr->iph_length << 8) + (hdr->iph_length >> 8);
			

			//if (size >= 60 && size <= 1500) {
				in_addr.s_addr = hdr->iph_dest;
				if (log == true) {
					write_log(buffer, file, hdr, in_addr, size);
				}

				in_addr.s_addr = hdr->iph_dest;
				CHAR* target_ip = inet_ntoa(in_addr);
				cout << "To: " << target_ip << " | ";

				in_addr.s_addr = hdr->iph_src;
				CHAR* source_ip = inet_ntoa(in_addr);
				cout << "From: " << source_ip << " | ";

				switch (hdr->iph_protocol) {
				case IPPROTO_IP:
					cout << "IP";
					break;

				case IPPROTO_ICMP:
					cout << "ICMP";
					break;

				case IPPROTO_TCP:
					cout << "TCP";
					break;

				case IPPROTO_UDP:
					cout << "UDP";
					break;


				case IPPROTO_IPV6:
					cout << "IPV6";
					break;

				}
				cout << endl;
			//}
		}
	}
}

sniffer::~sniffer(){
	file.close();
	closesocket(sock);
	WSACleanup();
}
