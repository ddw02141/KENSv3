/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

// GIT TEST
//GIT TEST 2

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include <E/Networking/TCP/E_TCPApplication.hpp>
#include <E/Networking/E_Host.hpp>
#include <netinet/in.h>
#include <E/Networking/E_RoutingInfo.hpp>
#include <assert.h>
#include <map>
#include <deque>



namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{
	this->host = host;
	this->sockfd = -1;
	this->accept_status = 0;
	this->close_status = 0;
	this->bind_status = 0;
	this->connect_status = 0;
	this->listen_status = 0;
	this->accept_status = 0;
	this->getsockname_status = 0;
	this->getpeername_status = 0;
	this->sock_mapping = std::map<pid_sockfd, Sock*>();
	this->client_server_mapping = std::map<Ip_port*, Ip_port*>();
	this->clients = std::deque<std::pair<bool, Ip_port*> >();
	this->INADDR_ANY_PORTS = std::deque<unsigned short>();
	this->connect_lock = false;
	this->accept_lock = 0;
	this->connect_blockedUUID = 999;
	this->accept_blockedUUIDs = std::deque<UUID>();
	this->accept_blockedSAs = std::deque<struct sockaddr*>();
	// this->seqNum = 22;
	// this->ackNum = 0;
}

TCPAssignment::~TCPAssignment()
{
	this->accept_blockedUUIDs.clear();
	this->accept_blockedSAs.clear();
	this->sock_mapping.clear();
	this->client_server_mapping.clear();
	this->clients.clear();
	this->INADDR_ANY_PORTS.clear();
	
}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

pid_sockfd* TCPAssignment::find_pid_sockfd_by_Ip_port_and_status(uint8_t dest_ip[4], unsigned short dest_port, Sock_status sock_status){
	// printf("find (%s, %u) %d\n", ipInt2ipCharptr(dest_ip), dest_port, sock_status);
	char *destIP = ipInt2ipCharptr(dest_ip);
	unsigned short destPort = dest_port;
	// dest : (192.168.0.7, 3879)
	std::map<pid_sockfd, Sock*>::iterator it;
	for(it=this->sock_mapping.begin(); it!=this->sock_mapping.end(); ++it){
		printf("element (%d, %d) : (%s:%u) status : %d\n", it->first.first, it->first.second, it->second->ip_port->ipAddr, it->second->ip_port->port, it->second->sock_status);
		if(( strcmp(it->second->ip_port->ipAddr, destIP) == 0 || strcmp(it->second->ip_port->ipAddr, "0.0.0.0") == 0) &&
			it->second->ip_port->port == destPort && it->second->sock_status==sock_status) // If the sockfd is bound
		{
			// printf("Success\n");
			return (pid_sockfd*)&(it->first);
		}
		// }
	}
	// printf("Fail\n");
	return NULL;

}

void TCPAssignment::send_new_packet(Sock* s, uint8_t src_ip[4], unsigned short src_port, uint8_t dest_ip[4], unsigned short dest_port, int Flags, bool Simultaneous){
	printf("send_new_packet\n");

	uint32_t src_ip32 = u32from8(src_ip);
	uint32_t dest_ip32 = u32from8(dest_ip);
	src_port = htons(src_port);
	dest_port = htons(dest_port);
	// unsigned short client_port; 
	// unsigned short server_port; 
	// client_port = client_ip_port_ptr->port;
	// server_port = server_ip_port_ptr->port;
	// client_port = htons(client_port);
	// server_port = htons(server_port);
	uint8_t *tcp_seg = (uint8_t*)malloc(sizeof(uint8_t)*20);
	// int Flags = 1<<1; // SYN
	Packet* myPacket = allocatePacket(54);
	myPacket->writeData(14+12, &src_ip32, 4);
	myPacket->writeData(14+16, &dest_ip32, 4);
	myPacket->writeData(14+20, &src_port, 2);
	myPacket->writeData(14+22, &dest_port, 2);
	unsigned short windowSize = 51200;
	windowSize = htons(windowSize);
	myPacket->writeData(48, &windowSize, 2);

	// uint32_t seqNumtoSend = htonl(this->seqNum);
	// myPacket->writeData(14+24, &seqNumtoSend, 4);
	// if(!Simultaneous) this->seqNum++;

	// uint32_t ackNum = htonl(this->ackNum);
	// myPacket->writeData(14+28, &ackNum, 4);
	uint32_t seqNumtoSend = htonl(s->seqNum);
	myPacket->writeData(14+24, &seqNumtoSend, 4);
	if(!Simultaneous) s->seqNum++;
	printf("s->seqNum : %u\n", s->seqNum);
	printf("s->ackNum : %u\n", s->ackNum);
	uint32_t ackNum = htonl(s->ackNum);
	myPacket->writeData(14+28, &ackNum, 4);

	// seqNum = ntohl(seqNum);
	// seqNum++;
	// seqNum = htonl(seqNum);
	// myPacket->writeData(14+28, &seqNum, 4);
	// if( Flags & 1) Flags = Flags | ACK;
	// Flags = Flags | ACK;
	// printf("write Flags : %d\n", Flags);
	myPacket->writeData(14+33, &Flags, 1);
	// uint16_t headerlength16 = 5;
	uint8_t headerlength8 = 5<<4;
	// headerlength16 = htons(headerlength16);
	// headerlength8 = (uint8_t)headerlength16;
	myPacket->writeData(46, &headerlength8, 1);
	// printf("headerlength8 : %x\n", headerlength8);
	uint16_t myPacket_checksum = 0;
	myPacket->writeData(50, &myPacket_checksum, 2);
	myPacket->readData(14+20, tcp_seg, 20);
	// uint32_t server_ip32 = server_ip[0] | (server_ip[1] << 8) | (server_ip[2] << 16) | (server_ip[3] << 24);

	myPacket_checksum = NetworkUtil::tcp_sum(src_ip32, dest_ip32, tcp_seg, 20);
	// printf("myPacket before change checksum : %x\n", myPacket_checksum);
	myPacket_checksum = ~myPacket_checksum;
	// printf("myPacket checksum Field : %x\n", myPacket_checksum);
	myPacket_checksum = htons(myPacket_checksum);
	myPacket->writeData(50, &myPacket_checksum, 2);

	// Verify
	myPacket->readData(14+20, tcp_seg, 20);
	myPacket_checksum = NetworkUtil::tcp_sum(src_ip32, dest_ip32, tcp_seg, 20);
	// printf("myPacket after change checksum : %x\n", myPacket_checksum);

	// IP Module will fill rest of IP header, 
	// send it to correct networ interface
	this->sendPacket("IPv4", myPacket);
}

void TCPAssignment::send_answer_packet(Sock* s, Packet* packet, uint8_t src_ip[4], unsigned short src_port, uint8_t dest_ip[4], unsigned short dest_port, int flagReceived, bool Simultaneous){
	printf("send_answer_packet\n");
	uint32_t seqNumReceived, ackNumReceived, seqNum, ackNum;
	uint8_t *tcp_seg = (uint8_t*)malloc(sizeof(uint8_t)*20);
	packet->readData(14+24, &seqNumReceived, 4);
	packet->readData(14+20, tcp_seg, 20);
	uint32_t src_ip32 = u32from8(src_ip);
	uint32_t dest_ip32 = u32from8(dest_ip);

	int SYN = !!(flagReceived & (1<<1));
	int ACK = !!(flagReceived & (1<<4));
	int FIN = !!(flagReceived & 1);
	int Flags = 0;
	
	Packet* myPacket = this->clonePacket(packet);
	
	src_port = htons(src_port);
	dest_port = htons(dest_port);
	
	
	myPacket->writeData(14+12, dest_ip, 4);
	myPacket->writeData(14+16, src_ip, 4);
	myPacket->writeData(14+20, &dest_port, 2);
	myPacket->writeData(14+22, &src_port, 2);

	if(SYN && !ACK) {
		// SYN -> SYNACK
		Flags = flagReceived | (1<<4);
	}
	else if(SYN && ACK) {
		// SYNACK -> ACK
		Flags = (1<<4);
	}
	else if(FIN && ACK){
		// FINACK -> ACK
		Flags = (1<<4);
	}

	// seqNum = htonl(this->seqNum);
	// myPacket->writeData(14+24, &seqNum , 4);
	// if(!(Flags== (1<<4)) && !Simultaneous) this->seqNum++;
	seqNum = htonl(s->seqNum);
	printf("s->seqNum : %u\n", s->seqNum);
	myPacket->writeData(14+24, &seqNum , 4);
	// if(!(Flags== (1<<4)) && !Simultaneous) s->seqNum++;
	if(!(Flags==(1<<4))) s->seqNum++;
	printf("s->seqNum after add : %u\n", s->seqNum);
	seqNumReceived = ntohl(seqNumReceived);
	seqNumReceived++;

	
	
	if((SYN && !ACK) || (SYN && ACK) || (FIN && ACK)){
		// SYN || SYNACK || FINACK
		// this->ackNum = seqNumReceived;
		s->ackNum = seqNumReceived;
		printf("s->ackNum : %u\n", s->ackNum);
		ackNum = htonl(seqNumReceived);

		myPacket->writeData(14+28, &ackNum, 4);
	}
	
	// if( Flags & 1) Flags = Flags | ACK;
	
	// printf("write Flags : %d\n", Flags);
	myPacket->writeData(14+33, &Flags, 1);
	uint16_t myPacket_checksum = 0;
	myPacket->writeData(50, &myPacket_checksum, 2);
	myPacket->readData(14+20, tcp_seg, 20);
	myPacket_checksum = NetworkUtil::tcp_sum(dest_ip32, src_ip32, tcp_seg, 20);
	// printf("myPacket before change checksum : %x\n", myPacket_checksum);
	myPacket_checksum = ~myPacket_checksum;
	myPacket_checksum = htons(myPacket_checksum);
	// printf("myPacket checksum Field : %x\n", myPacket_checksum);
	myPacket->writeData(50, &myPacket_checksum, 2);

	// Verify
	myPacket->readData(14+20, tcp_seg, 20);
	myPacket_checksum = NetworkUtil::tcp_sum(dest_ip32, src_ip32, tcp_seg, 20);
	// printf("myPacket after change checksum : %x\n", myPacket_checksum);

	// IP Module will fill rest of IP header, 
	// send it to correct networ interface
	this->sendPacket("IPv4", myPacket);
}


void TCPAssignment::connect_block(UUID syscallUUID){
	// printf("connect_block\n");
	this->connect_lock = true;
	this->connect_blockedUUID = syscallUUID;
}

void TCPAssignment::connect_unblock(int status){
	// printf("connect_unblock\n");
	SystemCallInterface::returnSystemCall(this->connect_blockedUUID, status);
	this->connect_lock = false;
	this->connect_blockedUUID = 999;
}

void TCPAssignment::accept_block(UUID syscallUUID, int pid, struct sockaddr* sa){
	printf("accept_block(%lu, %d)\n", syscallUUID, pid);
	this->accept_lock++;
	this->accept_blockedUUIDs.push_back(syscallUUID);
	this->accept_blockedSAs.push_back(sa);
}

bool TCPAssignment::lazy_accept(UUID syscallUUID, struct sockaddr* addr, int pid, Ip_port* server_ip_port, Ip_port* client_ip_port){

	// This is lazy_accept
	// This is from accept_unblock
	uint8_t server_ip[4];
	ipCharptr2ipInt(server_ip_port->ipAddr,server_ip);
	pid_sockfd* Pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(server_ip, server_ip_port->port, SC_SYN_RCVD);
	if(Pid_sockfd==NULL){
		printf("lazy accept : Pid_sockfd == NULL\n");
		return false;
	}
	ip_port2sa(addr, server_ip_port);
	SystemCallInterface::returnSystemCall(syscallUUID, Pid_sockfd->second);
	return true;
	
}

void TCPAssignment::accept_unblock(uint8_t src_ip[4], unsigned short src_port, uint8_t dest_ip[4], unsigned short dest_port){
	printf("accept_unblock on (%s:%u)\n", ipInt2ipCharptr(dest_ip), dest_port);
		

	pid_sockfd* Pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(dest_ip, dest_port,SC_SYN_RCVD);
	if(Pid_sockfd==NULL){
		printf("Pid_sockfd==NULL\n");
		return;
	}
	Ip_port* client_ip_port = (Ip_port*)malloc(sizeof(Ip_port));
	client_ip_port->ipAddr = ipInt2ipCharptr(src_ip);
	client_ip_port->port = src_port;
	Ip_port* server_ip_port = (Ip_port*)malloc(sizeof(Ip_port));
	server_ip_port->ipAddr = ipInt2ipCharptr(dest_ip);
	server_ip_port->port = dest_port;
	bool success = lazy_accept(this->accept_blockedUUIDs.front(), this->accept_blockedSAs.front(), Pid_sockfd->first, 
		server_ip_port, client_ip_port);
	if(success) {
		printf("accept_unblock success : %d\n", success);
		this->sock_mapping[*Pid_sockfd]->backlog--;
		this->sock_mapping[*Pid_sockfd]->sock_status = SC_ESTAB_SERVER;
	}

	this->accept_lock--;
	this->accept_blockedUUIDs.pop_front();
	this->accept_blockedSAs.pop_front();
	return;
}

void TCPAssignment::u8from32 (uint8_t u8[4], uint32_t u32){
    u8[0] = (uint8_t)u32;
    u8[1] = (uint8_t)(u32>>=8);
    u8[2] = (uint8_t)(u32>>=8);
    u8[3] = (uint8_t)(u32>>=8);
}

uint32_t TCPAssignment::u32from8 (uint8_t u8[4]){
	uint32_t u32 = u8[0] | (u8[1] << 8) | (u8[2] << 16) | (u8[3] << 24);
	return u32;
}

char* TCPAssignment::ipInt2ipCharptr(uint8_t ip_buffer[4]){
	char *ipAddress = (char*)malloc(15); // xxx.xxx.xxx.xxx
	char *ipAddress_frag = (char*)malloc(3); // xxx
	sprintf(ipAddress_frag, "%u", ip_buffer[0]);
	strcpy(ipAddress, ipAddress_frag);
	strcat(ipAddress, ".");

	sprintf(ipAddress_frag, "%u", ip_buffer[1]);
	strcat(ipAddress, ipAddress_frag);
	strcat(ipAddress, ".");

	sprintf(ipAddress_frag, "%u", ip_buffer[2]);
	strcat(ipAddress, ipAddress_frag);
	strcat(ipAddress, ".");

	sprintf(ipAddress_frag, "%u", ip_buffer[3]);
	strcat(ipAddress, ipAddress_frag);

	return ipAddress;
}

void TCPAssignment::ipCharptr2ipInt(char* ipCharptr, uint8_t ipInt[4]){
	std::string ipString = ipCharptr;
	size_t pos = 0;
	int idx = 0;
	std::string token;
	while((pos = ipString.find("."))!= std::string::npos){
		token = ipString.substr(0, pos);	
		sscanf(token.c_str(), "%u", &ipInt[idx++]); 
		ipString.erase(0, pos+1);
	}
	sscanf(ipString.c_str(), "%u", &ipInt[idx]); 
	return;
}

struct Ip_port* TCPAssignment::sa2ip_port(struct sockaddr* sa){
	struct sockaddr_in* sin = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
	sin = (struct sockaddr_in*)sa;
	char *ipAddress = inet_ntoa(sin->sin_addr);
	unsigned short port = ntohs(sin->sin_port);
	// printf("IP address: %s Port : %d\n", ipAddress, port);
	struct Ip_port *ip_port = (struct Ip_port *)malloc(sizeof(struct Ip_port));
	ip_port->ipAddr = ipAddress;
	ip_port->port = port;
	// ip_port *p = (ip_port*)malloc(sizeof(ip_port));
	// p->first = ipAddress;
	// p->second = port;
	// return p;
	return ip_port;
}

void TCPAssignment::ip_port2sa(struct sockaddr* sa, struct Ip_port* p){
	struct sockaddr_in* sin;
	sin = (struct sockaddr_in*)sa;
	inet_aton(p->ipAddr, &(sin->sin_addr)); 
	sin->sin_port = htons(p->port);
	sin->sin_family = AF_INET;
}




int TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused, int protocol){
	
	// return socket(param1, param2, param3);
	// SystemCallInterface::SystemCallInterface(domain, protocol, this->host);
	
	int sockfd = createFileDescriptor(pid);
	// printf("syscall_socket(%lu, pid : %d, sockfd : %d)\n", syscallUUID, pid, sockfd);

	Sock *sock = (Sock *)malloc(sizeof(Sock));
	sock->sock_status = SC_CLOSED;
	sock->ip_port = NULL;
	sock->peer_ip_port = NULL;
	sock->backlog = 0;
	sock->maxBacklog = 0;
	sock->seqNum = 0;
	sock->ackNum = 0;
	this->sock_mapping[std::make_pair(pid, sockfd)] = sock;
	return sockfd;
}

void TCPAssignment::close_socket(Ip_port* caller_ip_port){
	printf("close_socket(%s,%u)\n", caller_ip_port->ipAddr, caller_ip_port->port);
	uint8_t caller_ip[4];
	ipCharptr2ipInt(caller_ip_port->ipAddr, caller_ip);
	// Client
	pid_sockfd* Pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(caller_ip, caller_ip_port->port, SC_TIME_WAIT);
	if(Pid_sockfd==NULL) {
		// Server
		Pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(caller_ip, caller_ip_port->port, SC_LAST_ACK);

	}
	if(Pid_sockfd==NULL){
		printf("close_socket : Pid_sockfd==NULL\n");
		return;
	}

	this->sock_mapping.erase(std::make_pair(Pid_sockfd->first, Pid_sockfd->second));
	removeFileDescriptor(Pid_sockfd->first, Pid_sockfd->second);
	shutdown(Pid_sockfd->second, 2);
}

int TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd){
	// printf("syscall_close(%lu, pid : %d, sockfd : %d)\n", syscallUUID, pid, fd);
	if(sock_mapping.count(std::make_pair(pid, fd))==0) return -1;
	Sock *s = sock_mapping[std::make_pair(pid, fd)];
	Ip_port *caller_ip_port = s->ip_port;
	uint8_t caller_ip[4];
	uint8_t peer_ip[4];
	if(caller_ip_port==NULL){
		removeFileDescriptor(pid, fd);
		shutdown(fd, 2);
		return 0;
	}
	
	else if(s->sock_status==SC_ESTAB_CLIENT || s->sock_status==SC_ESTAB_SERVER){
		printf("syscall_close : ");
		if(s->sock_status==SC_ESTAB_CLIENT) {
			printf("SC_ESTAB_CLIENT\n");
		}
		else {
			printf("SC_ESTAB_SERVER\n");
		}
		// Ip_port* peer_ip_port;
		// if(s->sock_status==SC_ESTAB_CLIENT) peer_ip_port = this->client_server_mapping[caller_ip_port];
		// else peer_ip_port = s->peer_ip_port;
		Ip_port* peer_ip_port = s->peer_ip_port;
		if(peer_ip_port==NULL) {
			this->sock_mapping.erase(std::make_pair(pid, fd));
			removeFileDescriptor(pid, fd);
			shutdown(fd, 2);
			return 0;
		}
		ipCharptr2ipInt(caller_ip_port->ipAddr, caller_ip);
		ipCharptr2ipInt(peer_ip_port->ipAddr, peer_ip);
		unsigned short caller_port = caller_ip_port->port;
		unsigned short peer_port = peer_ip_port->port;
		int Flags = 1; //FIN	
		Flags = Flags | (1<<4); //FINACK

		send_new_packet(s, caller_ip, caller_port, peer_ip, peer_port, Flags, false);

		if(s->sock_status==SC_ESTAB_CLIENT) {
			// printf("SC_ESTAB_CLIENT\n");
			s->sock_status = SC_FIN_WAIT1;
		}
		// Maybe wrong
		else {
			// printf("SC_ESTAB_SERVER\n");
			// s->sock_status = SC_LAST_ACK;
			;
		}

	}
	else if(s->sock_status==SC_CLOSE_WAIT){
		printf("syscall_close : SC_CLOSE_WAIT\n");
		// server only
		// printf("(%s:%u)\n", caller_ip_port->ipAddr, caller_ip_port->port);
		// close_socket(caller_ip_port);
		// printf("(%s, %u)\n", caller_ip_port->ipAddr, caller_ip_port->port);
		// // (0.0.0.0, 9999)
		uint8_t client_ip[4];
		uint8_t server_ip[4];
		Ip_port *server_ip_port = caller_ip_port;
		Ip_port* client_ip_port = s->peer_ip_port;
		if(client_ip_port==NULL){
			printf("client_ip_port==NULL\n");
			close_socket(caller_ip_port);
			return 0;
		}
		ipCharptr2ipInt(client_ip_port->ipAddr, client_ip);
		// printf("client ip : %s\n", client_ip_port->ipAddr);
		// printf("server ip : %s\n", server_ip_port->ipAddr);
		// if(strcmp(server_ip_port->ipAddr, "0.0.0.0")==0){
		// 	pid_sockfd* client_pid_sockfd = find_pid_sockfd_by_Ip_port(client_ip, client_ip_port->port);
		// 	if(client_pid_sockfd!=NULL){
		// 		Sock* sock = this->sock_mapping[*client_pid_sockfd];
		// 		printf("%s\n", sock->peer_ip_port->ipAddr);
		// 		strcpy(server_ip_port->ipAddr, sock->peer_ip_port->ipAddr);
		// 	}
		// }

		// printf("(%s:%u)\n", server_ip_port->ipAddr, server_ip_port->port);
		// if(this->client_server_mapping.count(caller_ip_port)!=0){
		// 	client_ip_port = this->client_server_mapping[caller_ip_port];
		// }
		// else{
		// 	std::map<Ip_port*, Ip_port*>::iterator it;
		// 	for(it=this->client_server_mapping.begin(); it!=this->client_server_mapping.end(); ++it){
		// 		// if(it->second->sock_status==SC_LISTEN || it->second->sock_status==SC_SYN_RCVD){
		// 		// printf("element : (%s:%d)\n", it->second->ip_port->ipAddr, it->second->ip_port->port);
		// 		if((strcmp(it->first->ipAddr, "0.0.0.0") == 0 ) &&
		// 			(it->first->port == server_ip_port->port)) // If the sockfd is bound
		// 		{
		// 			client_ip_port = it->second;
		// 			break;
		// 		}
		// 		// }
		// 	}
		// }
		
		// uint8_t client_ip[4];
		ipCharptr2ipInt(client_ip_port->ipAddr, client_ip);
		ipCharptr2ipInt(server_ip_port->ipAddr, server_ip);
		unsigned short client_port = client_ip_port->port;
		unsigned short server_port = server_ip_port->port;
		int Flags = 1; //FIN	
		Flags = Flags | (1<<4); //FINACK

		// if(strcmp(server_ip_port->ipAddr, "0.0.0.0")==0){
		// 	pid_sockfd* client_pid_sockfd = find_pid_sockfd_by_Ip_port(client_ip, client_port);
		// 	if(client_pid_sockfd==NULL) printf("cannot find client socket!@!@\n");
		// 	Sock *client_sock = sock_mapping[*client_pid_sockfd];
		// 	printf("client's peer ipAddr : %s\n", client_sock->peer_ip_port->ipAddr);
		// 	ipCharptr2ipInt(client_sock->peer_ip_port->ipAddr, server_ip);
		// }


		send_new_packet(s, server_ip, server_port, client_ip, client_port, Flags, false);

		s->sock_status = SC_LAST_ACK;

	}
	// else if(s->sock_status==SC_ESTAB_SERVER){
	// 	printf("syscall_close : SC_ESTAB_SERVER\n");
	// 	close_socket(caller_ip_port);
	// 	return 0;
	// }
	else{
		printf("syscall_close : else %d\n", s->sock_status);
		printf("(%s:%u)\n", caller_ip_port->ipAddr, caller_ip_port->port);

			// INADDR rule fix if needed
		if(caller_ip_port!=NULL){
			unsigned short port = caller_ip_port->port;
			if(strcmp(caller_ip_port->ipAddr, "0.0.0.0")==0){
				if(!this->INADDR_ANY_PORTS.empty()){
					auto it = find(this->INADDR_ANY_PORTS.begin(), this->INADDR_ANY_PORTS.end(), port);
					if(it != this->INADDR_ANY_PORTS.end()){
						this->INADDR_ANY_PORTS.erase(it);
					}
				}
			}
		}

		this->sock_mapping.erase(std::make_pair(pid, fd));
		removeFileDescriptor(pid, fd);
		shutdown(fd, 2);
		return 0;
	}

	// // INADDR rule fix if needed
	// if(caller_ip_port!=NULL){
	// 	struct sockaddr* sa = (struct sockaddr*)malloc(sizeof(struct sockaddr));
	// 	ip_port2sa(sa, caller_ip_port);
	// 	struct sockaddr_in* sin = (struct sockaddr_in*)sa;
	// 	// inet_aton(p->first, &(sin->sin_addr));
	// 	unsigned short port = caller_ip_port->port;
	// 	if(ntohl(sin->sin_addr.s_addr) == INADDR_ANY){
	// 		auto it = find(this->INADDR_ANY_PORTS.begin(), this->INADDR_ANY_PORTS.end(), port);
	// 		if(it != this->INADDR_ANY_PORTS.end()){
	// 			this->INADDR_ANY_PORTS.erase(it);
	// 		}
	// 	}
	// }

	// sock_mapping.erase(std::make_pair(pid, fd));
	// removeFileDescriptor(pid, fd);
	// shutdown(fd, 2);
	return 0;
}

int TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen){
	printf("syscall_bind(%lu, pid : %d, sockfd : %d)\n", syscallUUID, pid, sockfd);

	if(this->sock_mapping.count(std::make_pair(pid, sockfd))==0){
		// printf("Socket first then bind\n");
		return -1;
	}

	if(this->sock_mapping[std::make_pair(pid, sockfd)]->sock_status != SC_CLOSED){
		// printf("Bind already Exists in sockfd %d => %s:%d\n", 
		// 	sockfd, this->sock_mapping_mapping[sockfd]->first, this->sock_mapping_mapping[sockfd]->second);
		return -1;
	}

	struct sockaddr_in* sin;
	sin = (struct sockaddr_in*)addr;
	unsigned short port = ntohs(sin->sin_port);
	printf("bind port : %u\n", port);
	if(!this->INADDR_ANY_PORTS.empty()){
		auto it = find(this->INADDR_ANY_PORTS.begin(), this->INADDR_ANY_PORTS.end(), port);
		if(it != this->INADDR_ANY_PORTS.end()){
			// printf("Same Port with INADDR_ANY!!!\n");
			return -1;
		}
	}


	
	
	
	if(ntohl(sin->sin_addr.s_addr) == INADDR_ANY){ // INADDR_ANY
		std::map<pid_sockfd, Sock*>::iterator it;
		for(it=sock_mapping.begin(); it!=sock_mapping.end(); ++it){
			if(it->second->sock_status == SC_BOUND) // If the sockfd is bound
			{
				if( it->second->ip_port->port == port){
					return -1;
				}
			}
		}

		
		this->INADDR_ANY_PORTS.push_back(port);
		// printf("this->INADDR_ANY_PORTS push_back %d\n", port);
	}
	
	// printf("dst_p\n");
	Ip_port *dst_p = sa2ip_port(addr);
	Ip_port *new_ip_port = (Ip_port *)malloc(sizeof(Ip_port));
	new_ip_port->ipAddr = (char *)malloc(sizeof(16));
	Sock *sock = (Sock *)malloc(sizeof(Sock));

	sock->sock_status = SC_BOUND;
	// Fix sock_mapping values changing Issue
	memcpy(new_ip_port->ipAddr, dst_p->ipAddr, 16);
	// 
	new_ip_port->port = dst_p->port;
	sock->ip_port = new_ip_port;
	
	// printf("dst_p : (%s:%u)\n", dst_p->ipAddr, dst_p->port);

	this->sock_mapping[std::make_pair(pid, sockfd)] = sock;

	return 0;
}

int TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *server_addr, socklen_t addrlen){
	printf("syscall_connect(%lu, %d, %d)\n", syscallUUID, pid, sockfd);
	// int RoutingInfo::getRoutingTable(const uint8_t* ip_addr)
	if(this->sock_mapping.count(std::make_pair(pid, sockfd))==0){
		// printf("Socket first then connect\n");
		return -1;
	}
	Sock *sock = this->sock_mapping[std::make_pair(pid, sockfd)];
	printf("sock status : %d\n", sock->sock_status);
	uint8_t client_ip[4];
	uint8_t server_ip[4];
	if(sock->sock_status==SC_CLOSED){
		struct sockaddr_in* sin;
		sin = (struct sockaddr_in*)server_addr;
		uint8_t* casted_server_addr = (uint8_t*)(&(sin->sin_addr));
		unsigned short client_implicit_port = (this->host)->getRoutingTable(casted_server_addr);
		// printf("client_implicit_port : %u\n", client_implicit_port);

		bool implicitBindSuccess = this->host->getIPAddr(client_ip, client_implicit_port);
		if(!implicitBindSuccess) return -1;
		
		char* client_ipAddress = TCPAssignment::ipInt2ipCharptr(client_ip);
		Ip_port* client_ip_port_ptr = (struct Ip_port*)malloc(sizeof(struct Ip_port));
		client_ip_port_ptr->ipAddr = client_ipAddress;
		client_ip_port_ptr->port = (unsigned short)client_implicit_port;

		
		// this->sock_mapping[std::make_pair(pid, sockfd)] = client_sock;
		
		Ip_port* server_ip_port_ptr = sa2ip_port(server_addr);
		if(this->client_server_mapping.count(server_ip_port_ptr)!=0){
			// printf("Connect Already Exist\n");
			return -1;
		}

		// Delete Later
		this->client_server_mapping[server_ip_port_ptr] = client_ip_port_ptr;
		this->client_server_mapping[client_ip_port_ptr] = server_ip_port_ptr;

		uint32_t server_ip32 = sin->sin_addr.s_addr;
		u8from32(server_ip, server_ip32);
		unsigned short client_port = client_ip_port_ptr->port;
		unsigned short server_port = server_ip_port_ptr->port;
		int Flags = 1<<1; // SYN
		
		send_new_packet(sock, client_ip, client_port, server_ip, server_port, Flags, false);
		
		// SC_LISTEN => SC_SYN_SENT
		// client_sock = this->sock_mapping[std::make_pair(pid, sockfd)];
		sock->ip_port = client_ip_port_ptr;
		sock->sock_status = SC_SYN_SENT;

		connect_block(syscallUUID);

		return 0;
	}
	else if(sock->sock_status==SC_BOUND){
		// SimultaneousConnect
		struct sockaddr_in* sin;
		sin = (struct sockaddr_in*)server_addr;
		uint8_t* casted_server_addr = (uint8_t*)(&(sin->sin_addr));
		unsigned short client_implicit_port = (this->host)->getRoutingTable(casted_server_addr);
		// printf("client_implicit_port : %u\n", client_implicit_port);

		
		Ip_port* client_ip_port_ptr = sock->ip_port;
		
		// this->sock_mapping[std::make_pair(pid, sockfd)] = client_sock;
		
		// Delete Later From here
		Ip_port* server_ip_port_ptr = sa2ip_port(server_addr);
		if(this->client_server_mapping.count(server_ip_port_ptr)!=0){
			// printf("Connect Already Exist\n");
			return -1;
		}
		this->client_server_mapping[server_ip_port_ptr] = client_ip_port_ptr;
		this->client_server_mapping[client_ip_port_ptr] = server_ip_port_ptr;
		// to here

		uint32_t server_ip32 = sin->sin_addr.s_addr;
		u8from32(server_ip, server_ip32);
		ipCharptr2ipInt(client_ip_port_ptr->ipAddr, client_ip);
		unsigned short client_port = client_ip_port_ptr->port;
		unsigned short server_port = server_ip_port_ptr->port;
		int Flags = 1<<1; // SYN
		
		send_new_packet(sock, client_ip, client_port, server_ip, server_port, Flags, true);
		
		// SC_LISTEN => SC_SYN_SENT
		// client_sock = this->sock_mapping[std::make_pair(pid, sockfd)];
	
		
		// sock->ip_port = client_ip_port_ptr;
		sock->sock_status = SC_SYN_SENT;

		connect_block(syscallUUID);

		return 0;

	}
	// Success -> 0 Fail -> -1
}

int TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog){
	printf("syscall_listen(%lu, %d, %d)\n", syscallUUID, pid, sockfd);
	if(this->sock_mapping.count(std::make_pair(pid, sockfd))==0){
		// printf("Socket first then listen\n");
		return -1;
	}
	Sock *serverSock = this->sock_mapping[std::make_pair(pid, sockfd)];
	serverSock->sock_status = SC_LISTEN;
	serverSock->maxBacklog = backlog;
	printf("maxBacklog : %d\n", backlog);
	serverSock->backlog = 0;
	serverSock->seqNum = 0;
	serverSock->ackNum = 0;
	
	return 0;
}


int TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	printf("syscall_accept(%lu, %d, %d)\n", syscallUUID, pid, sockfd);

	if(this->sock_mapping.count(std::make_pair(pid, sockfd))==0){
		printf("Socket first then accept\n");
		return -1;
	}
	Sock *sock = this->sock_mapping[std::make_pair(pid, sockfd)];	
	
	uint8_t conn_ip[4];
	ipCharptr2ipInt(sock->ip_port->ipAddr, conn_ip);
	printf("find (%s, %u) status %d\n", sock->ip_port->ipAddr, sock->ip_port->port, SC_SYN_RCVD);
	pid_sockfd* conn_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(conn_ip, sock->ip_port->port,SC_SYN_RCVD);
	if(conn_pid_sockfd==NULL)
		conn_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(conn_ip, sock->ip_port->port,SC_CLOSE_WAIT);
			
	if(sock->backlog <= sock->maxBacklog){
		// int connfd;
		// connfd = createFileDescriptor(pid);
		// printf("connfd : %d\n", connfd);
		if(!this->clients.empty() && conn_pid_sockfd!=NULL){
			// bool success = lazy_accept(syscallUUID, addr, pid, sock->ip_port, NULL, false);
			
			// This is not lazy_accept
			// This is from syscall_accept directly because their exist at least one client in this->clients.
			std::pair<bool, Ip_port*> p = this->clients.front();
			Ip_port* client_ip_port = p.second;
			this->clients.pop_front();
			ip_port2sa(addr, sock->ip_port);
			// int connfd;
			// connfd = createFileDescriptor(pid);
			// printf("connfd : %d\n", connfd);
			// uint8_t conn_ip[4];
			// ipCharptr2ipInt(sock->ip_port->ipAddr, conn_ip);
			// printf("find (%s, %u) status %d\n", sock->ip_port->ipAddr, sock->ip_port->port, SC_SYN_RCVD);
			// pid_sockfd* conn_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(conn_ip, sock->ip_port->port,SC_SYN_RCVD);
			// if(conn_pid_sockfd==NULL)
			// 	conn_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(conn_ip, sock->ip_port->port,SC_CLOSE_WAIT);
			// if(conn_pid_sockfd==NULL){
			// 	printf("conn_pid_sockfd NULL?!?@!@!@\n");
			// 	// print 찍어보니 (0,0) : SC_LISTEND (0,1) : SC_CLOSE_WAIT
			// 	return -1;
			// }
				
			Sock *conn_sock = this->sock_mapping[*conn_pid_sockfd];
			// if(conn_sock->sock_status==SC_SYN_RCVD)
				conn_sock->sock_status = SC_ESTAB_SERVER;
			// 애매
			conn_sock->peer_ip_port = client_ip_port;
			// newsock->ip_port = sock->ip_port;
			// newsock->backlog = 0;
			// newsock->maxBacklog = 0;
			// newsock->seqNum = sock->seqNum;
			// newsock->ackNum = sock->ackNum;
			// printf("sock->seqNum : %u newsock->seqNum : %u\n", sock->seqNum, newsock->seqNum);
			// printf("sock->ackNum : %u newsock->ackNum : %u\n", sock->ackNum, newsock->ackNum);
			// // printf("client ip_port : (%s, %u)\n", client_ip_port->ipAddr, client_ip_port->port);
			// // printf("pid_sockfd : (%d, %d)\n", pid, connfd);
			// // printf("%u %u %u %u\n", htons(46759), htons(21053), htons(33500), htons(9999));
			// this->sock_mapping[std::make_pair(pid, connfd)] = newsock;
			
			// if(it->first) sock->backlog--;
			if(conn_sock->sock_status==SC_SYN_RCVD)
				sock->backlog--;
			SystemCallInterface::returnSystemCall(syscallUUID, conn_pid_sockfd->second);
			printf("not lazy_accept => Success\n");
			
		}
		else{
			accept_block(syscallUUID, pid, addr);
		}
	
	}
	
	return 0;
}


int TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	// printf("syscall_getsockname(%lu, %d, %d)\n", syscallUUID, pid, sockfd);
	if(this->sock_mapping.count(std::make_pair(pid, sockfd))==0){
		// printf("Sockname does not exist!\n");
		return -1;
	}
	if(this->sock_mapping[std::make_pair(pid, sockfd)]->sock_status==SC_CLOSED){
		// printf("Socket exists but not bind\n");
		return -1;
	}
	Sock *sock = this->sock_mapping[std::make_pair(pid, sockfd)];
	Ip_port *p = sock->ip_port;
	// printf("p->first : %s p->second : %d\n", 
	// this->sock_mapping_mapping[sockfd]->first, this->sock_mapping_mapping[sockfd]->second);
	ip_port2sa(addr, p);

	return 0;
}

int TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	// printf("syscall_getpeername(%lu, %d, %d)\n", syscallUUID, pid, sockfd);
	
	if(this->sock_mapping.count(std::make_pair(pid, sockfd))==0){
		// printf("Not bound sockfd %d\n", sockfd);
		return -1;
	}
	Sock *caller_sock = this->sock_mapping[std::make_pair(pid, sockfd)];
	Ip_port* caller_ip_port = caller_sock->ip_port;
	// printf("server (%s, %d)\n", server_ip_port->first, server_ip_port->second);
	// printf("server from scratch (%s, %d)\n", this->sock_mapping_mapping[sockfd]->first, 
	// 	this->sock_mapping_mapping[sockfd]->second);
	if(this->client_server_mapping.count(caller_ip_port)==0){
		// printf("No peer with (%s, %d)\n", caller_ip_port->ipAddr, caller_ip_port->port);
		return -1;
	}
	Ip_port* peer_ip_port = this->client_server_mapping[caller_ip_port];
	ip_port2sa(addr, peer_ip_port);
	return 0;
}


void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		// 	syscallUUID, pid, param.param1_int, param.param2_int, param.param3_int);
		// this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		// TCPAssignment::syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int, param.param3_int);
		this->sockfd = this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int, param.param3_int);
		// printf("this->sockfd : %d\n", this->sockfd);
		SystemCallInterface::returnSystemCall(syscallUUID, this->sockfd);
		break;
	case CLOSE:
		// printf("CLOSE\n");
		// printf("syscallUUID : %d pid : %d param.param1_int : %d\n", 
		// 	syscallUUID, pid, param.param1_int);
		this->close_status = this->syscall_close(syscallUUID, pid, param.param1_int);
		SystemCallInterface::returnSystemCall(syscallUUID, this->close_status);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->connect_status = this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		if(this->connect_status==-1)
			SystemCallInterface::returnSystemCall(syscallUUID, this->connect_status);
		break;
	case LISTEN:
		this->listen_status = this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		SystemCallInterface::returnSystemCall(syscallUUID, this->listen_status);	
		break;
	case ACCEPT:
		this->accept_status = this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		if(this->accept_status==-1)
			SystemCallInterface::returnSystemCall(syscallUUID, this->connect_status);
		break;
	case BIND:
		this->bind_status = this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		// printf("this->bind_status : %d\n", this->bind_status);
		SystemCallInterface::returnSystemCall(syscallUUID, this->bind_status);
		break;
	case GETSOCKNAME:
		this->getsockname_status = this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		SystemCallInterface::returnSystemCall(syscallUUID, this->getpeername_status);

		break;
	case GETPEERNAME:
		this->getpeername_status = this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		SystemCallInterface::returnSystemCall(syscallUUID, this->getpeername_status);

		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	// fromModule : IPv4
	// src_ip : 10.0.1.4 dest_ip : 192.168.0.7
	// sizeof(packet->buffer) : 8
	// printf("************* packetArrived ******************\n");
	uint8_t src_ip[4];
	uint8_t dest_ip[4];
	unsigned short src_port;
	unsigned short dest_port;
	int flagReceived;

	packet->readData(14+12, src_ip, 4);
	packet->readData(14+16, dest_ip, 4);
	packet->readData(14+20, &src_port, 2);
	packet->readData(14+22, &dest_port, 2);
	packet->readData(14+33, &flagReceived, 1);
	// printf("SYN : %d\n", Flags & 1);
	// printf("ACK : %d\n", !!(Flags & (1<<4)));
	int SYN = !!(flagReceived & (1<<1));
	int ACK = !!(flagReceived & (1<<4));
	int FIN = !!(flagReceived & 1);

	src_port = ntohs(src_port);
	dest_port = ntohs(dest_port);

	Ip_port* client_ip_port = (Ip_port*)malloc(sizeof(Ip_port));
	Ip_port* server_ip_port = (Ip_port*)malloc(sizeof(Ip_port));
	client_ip_port->ipAddr = ipInt2ipCharptr(src_ip);
	client_ip_port->port = src_port;
	server_ip_port->ipAddr = ipInt2ipCharptr(dest_ip);
	server_ip_port->port = dest_port;
	pid_sockfd *server_pid_sockfd = (pid_sockfd *)malloc(sizeof(pid_sockfd));
	pid_sockfd *client_pid_sockfd = (pid_sockfd *)malloc(sizeof(pid_sockfd));
	// server_pid_sockfd = find_pid_sockfd_by_Ip_port(dest_ip, dest_port);

	bool Simultaneous = false;
	int connfd = -1;

	// pid_sockfd *client_pid_sockfd = find_pid_sockfd_by_Ip_port(src_ip, src_port);
	// printf("from (%s, %u) to (%s, %u)\n", client_ip_port->ipAddr, client_ip_port->port, server_ip_port->ipAddr, server_ip_port->port);

	if(SYN && !ACK){
		printf("SYN\n");
		// LISTEN하고 있는 애를 찾아서
		// 이녀석의 backlog를 올려주나?
		// backlog값을 넘지 않는다면?
		// pid_sockfd 찾아서 LISTEN => SC_SYN_RCVD
		server_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(dest_ip, dest_port, SC_LISTEN);
		if(server_pid_sockfd==NULL){
			// SimultaneuosConnect
			printf("SYN with Simul\n");
			server_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(dest_ip, dest_port, SC_SYN_SENT);
		}
			
		
		
		if(server_pid_sockfd==NULL) {
			printf("server_pid_sockfd NULL?\n");
			return;
		}
		Sock* server_sock = this->sock_mapping[*server_pid_sockfd];

		// Change "0.0.0.0" to real address
		if(strcmp(server_sock->ip_port->ipAddr, "0.0.0.0")==0){
			char* real_server_ipAddr = ipInt2ipCharptr(dest_ip);
			strcpy(server_sock->ip_port->ipAddr, real_server_ipAddr);
		} 

		if((server_sock->sock_status==SC_LISTEN) && (server_sock->backlog >= server_sock->maxBacklog)){
			printf("(%d, %d) : %d %d\n", server_pid_sockfd->first, server_pid_sockfd->second, this->sock_mapping[*server_pid_sockfd]->backlog, this->sock_mapping[*server_pid_sockfd]->maxBacklog);
			printf("backlog problem\n");
			return;
		}
		else {
			bool f = true;
			if(!this->clients.empty()){
				for(auto it=this->clients.begin(); it!=this->clients.end();it++){
					if(strcmp(it->second->ipAddr, client_ip_port->ipAddr)==0 &&
						it->second->port == client_ip_port->port){
						f = false;
						break;			
					}
				}
			}
			
			if(f) {
				printf("push clients (%s:%u)\n", client_ip_port->ipAddr, client_ip_port->port);
				this->clients.push_back(std::make_pair(true, client_ip_port));
				this->sock_mapping[*server_pid_sockfd]->backlog++;
			}


		}
		
		// Make duplicated SC_SYN_RCVD socket 
		Sock *newsock = (Sock *)malloc(sizeof(Sock));
		newsock->ip_port = server_ip_port;
		newsock->peer_ip_port = client_ip_port;
		newsock->sock_status = SC_SYN_RCVD;
		newsock->backlog = 0;
		newsock->maxBacklog = 0;
		newsock->seqNum = server_sock->seqNum;
		newsock->ackNum = server_sock->ackNum;
		connfd = createFileDescriptor(server_pid_sockfd->first);
		printf("connfd after receive SYN : %d\n", connfd);
		this->sock_mapping[std::make_pair(server_pid_sockfd->first, connfd)] = newsock;
		printf("(%d, %d) <-> (%s, %u) status %d\n", server_pid_sockfd->first, connfd,
			server_ip_port->ipAddr, server_ip_port->port, newsock->sock_status);
		
	}
	else if(SYN && ACK){
		printf("SYNACK\n");
		// pid_sockfd 찾아서 SC_SYN_SENT => SC_ESTAB
		server_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(dest_ip, dest_port, SC_SYN_SENT);
		if(server_pid_sockfd==NULL){
			printf("SYNACK with Simul\n");
			Simultaneous = true;
			server_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(dest_ip, dest_port, SC_SYN_RCVD);	
		}
		if(server_pid_sockfd!=NULL){
			Sock *sock = this->sock_mapping[*server_pid_sockfd];
			sock->sock_status = SC_ESTAB_CLIENT;
			sock->peer_ip_port = client_ip_port;
			connect_unblock(0);	
		}
		
		// if(this->connect_lock) accept_unblock();
	}

	else if(FIN && ACK) {
		printf("FINACK\n");
		// client
		server_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(dest_ip, dest_port, SC_FIN_WAIT2);
		// again client
		if(server_pid_sockfd==NULL)
			server_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(dest_ip, dest_port, SC_FIN_WAIT1);	
		// again again client
		if(server_pid_sockfd==NULL)
			server_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(dest_ip, dest_port, SC_ESTAB_CLIENT);	
		// server
		if(server_pid_sockfd==NULL)
			server_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(dest_ip, dest_port, SC_ESTAB_SERVER);	
		if(server_pid_sockfd==NULL) {
			return;
		}	
		if(this->sock_mapping.count(*server_pid_sockfd)==0) return;
		Sock *sock = this->sock_mapping[*server_pid_sockfd];
		printf("sock_status : %d\n", sock->sock_status);
		if(sock->sock_status==SC_FIN_WAIT2){
			// client side
			printf("SC_FIN_WAIT2\n");
			sock->sock_status=SC_TIME_WAIT;
			
		}
		else if(sock->sock_status==SC_ESTAB_SERVER){
			// server side
			printf("SC_ESTAB_SERVER\n");
			sock->sock_status = SC_CLOSE_WAIT;
		}

		// return;
		
	}

	else if(ACK){
		printf("ACK\n");	
		// SYN - SYNACK - ACK
		server_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(dest_ip, dest_port, SC_SYN_RCVD);
		if(server_pid_sockfd==NULL)
			// SimultaneousConnect
			server_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(dest_ip, dest_port, SC_ESTAB_SERVER);

		// client FIN - ACK
		if(server_pid_sockfd==NULL)
			server_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(dest_ip, dest_port, SC_FIN_WAIT1);
		// server FIN - ACK
		if(server_pid_sockfd==NULL)
			server_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(dest_ip, dest_port, SC_LAST_ACK);

		if(server_pid_sockfd==NULL) return;	
		if(this->sock_mapping.count(*server_pid_sockfd)==0) return;
		Sock *sock = this->sock_mapping[*server_pid_sockfd];
		// printf("(%d, %d) : %d\n", server_pid_sockfd->first, server_pid_sockfd->second, sock->sock_status);
		if(sock->sock_status==SC_SYN_RCVD){
			// 3-way handshaking - server side
			bool f = true;
			bool isSYN = false;
			
			if(!this->clients.empty()){
				for(auto it=this->clients.begin(); it!=this->clients.end();it++){
					if(strcmp(it->second->ipAddr, client_ip_port->ipAddr)==0 &&
						it->second->port == client_ip_port->port){
						std::pair<bool, Ip_port*> p = *it;
						f = false;
						isSYN = p.first;
						if(isSYN) p.first = false;
						break;			
					}
				}
			}
			if(f) {
				this->clients.push_back(std::make_pair(true, client_ip_port));
				
			}
			else if(!f && isSYN){
				if(this->accept_lock) 
					accept_unblock(src_ip, src_port, dest_ip, dest_port);
				sock->sock_status = SC_ESTAB_SERVER;
				pid_sockfd* listen_pid_sockfd = find_pid_sockfd_by_Ip_port_and_status(dest_ip, dest_port, SC_LISTEN);
				if(listen_pid_sockfd!=NULL){
					this->sock_mapping[*listen_pid_sockfd]->backlog--;
					printf("backlog changed!\n");
					printf("(%d, %d) : backlog %d maxBacklog %d\n", listen_pid_sockfd->first, listen_pid_sockfd->second, 
						this->sock_mapping[*listen_pid_sockfd]->backlog, this->sock_mapping[*listen_pid_sockfd]->maxBacklog);
				}
				
					
			}			
			

			// if(this->accept_lock) accept_unblock(src_ip, src_port, dest_ip, dest_port);
			// sock->sock_status = SC_ESTAB_SERVER;
			return;
		}
		else if(sock->sock_status==SC_FIN_WAIT1){
			// 4-way handshaking - client side
			printf("SC_FIN_WAIT1 -> SC_FIN_WAIT2\n");
			sock->sock_status=SC_FIN_WAIT2;
			
			
		}

		return;
		
	}
	Sock *sock = this->sock_mapping[*server_pid_sockfd];
	// if(connfd==-1) printf("sock : (%d, %d)\n", server_pid_sockfd->first, server_pid_sockfd->second);
	// if(connfd!=-1){
	// 	Sock *listen_sock = this->sock_mapping[*server_pid_sockfd];
	// 	sock = this->sock_mapping[std::make_pair(server_pid_sockfd->first, connfd)];
	// 	printf("sock : (%d, %d)\n", server_pid_sockfd->first, connfd);
	// }
	
	send_answer_packet(sock, packet, src_ip, src_port, dest_ip, dest_port, flagReceived, Simultaneous);

	if(connfd!=-1){
		Sock *conn_sock = this->sock_mapping[std::make_pair(server_pid_sockfd->first, connfd)];
		conn_sock->seqNum = sock->seqNum;
		conn_sock->ackNum = sock->ackNum;
	}
	// given packet is my responsibility
	this->freePacket(packet);

	
	if(FIN && ACK && sock->sock_status==SC_TIME_WAIT) {
		Time t = TimeUtil::makeTime(120, TimeUtil::SEC);
		TimerModule::addTimer(server_ip_port, t);
	}

	return;

}

void TCPAssignment::timerCallback(void* payload)
{
	printf("timerCallback\n");
	// Packet* packet = (Packet*)payload;
	// printf("A\n");
	// uint8_t src_ip[4];
	// uint8_t dest_ip[4];
	// unsigned short src_port;
	// unsigned short dest_port;
	// int flagReceived;
	// printf("B\n");
	// packet->readData(14+12, src_ip, 4);
	// printf("B1\n");
	// packet->readData(14+16, dest_ip, 4);
	// printf("B2\n");
	// packet->readData(14+20, &src_port, 2);
	// printf("B3\n");
	// packet->readData(14+22, &dest_port, 2);
	// printf("B4\n");
	// packet->readData(14+33, &flagReceived, 1);
	// printf("B5\n");
	// src_port = ntohs(src_port);
	// dest_port = ntohs(dest_port);
	// printf("D\n");
	// Ip_port* client_ip_port = (Ip_port*)malloc(sizeof(Ip_port));
	// Ip_port* server_ip_port = (Ip_port*)malloc(sizeof(Ip_port));
	// client_ip_port->ipAddr = ipInt2ipCharptr(dest_ip);
	// client_ip_port->port = dest_port;
	// server_ip_port->ipAddr = ipInt2ipCharptr(src_ip);
	// server_ip_port->port = src_port;
	// printf("E\n");
	Ip_port* client_ip_port = (Ip_port*)payload;
	if(client_ip_port!=NULL) close_socket(client_ip_port);

	// SystemCallInterface::returnSystemCall(this->connect_blockedUUID, this->connfds.front());
	// this->connfds.pop();
	// this->accept_lock = false;
	// this->accept_blockedUUID = 888;
}


}
