/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

// GIT TEST
//GIT TEST 2

#include <E/E_Common.hpp>
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


namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{
	this->host = host;
	this->sockfd = 0;
	this->close_status = 0;
	this->bind_status = 0;
	this->connect_status = 0;
	this->getsockname_status = 0;
	this->getpeername_status = 0;
	this->sockfd_pair_mapping = std::map<int, ip_port*>();
	this->server_client_mapping = std::map<ip_port*, ip_port*>();
	this->INADDR_ANY_PORTS = std::vector<unsigned short>();
	this->lock = false;
	this->blockedUUID = 999;
}

TCPAssignment::~TCPAssignment()
{
	this->sockfd_pair_mapping.clear();
	this->server_client_mapping.clear();
	this->INADDR_ANY_PORTS.clear();

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::block(UUID syscallUUID){
	printf("block\n");
	this->lock = true;
	this->blockedUUID = syscallUUID;
	// Time t = TimeUtil::makeTime(100, TimeUtil::MSEC);
	// TimerModule::addTimer(&syscallUUID, t);
}

void TCPAssignment::unblock(int status){
	printf("unblock\n");
	SystemCallInterface::returnSystemCall(this->blockedUUID, status);
	this->lock = false;
	this->blockedUUID = 999;
}

void TCPAssignment::u8from32 (uint8_t u8[4], uint32_t u32){
    u8[3] = (uint8_t)u32;
    u8[2] = (uint8_t)(u32>>=8);
    u8[1] = (uint8_t)(u32>>=8);
    u8[0] = (uint8_t)(u32>>=8);
}

uint32_t TCPAssignment::u32from8 (uint8_t u8[4]){
	uint32_t u32 = u8[0] | (u8[1] << 8) | (u8[2] << 16) | (u8[3] << 24);
	return u32;
}

// void TCPAssignment::TimerCallback(void* payload){
// 	printf("hello\n");
// }


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

	printf("Converted ipAddress : %s strlen(ipAddress) = %d\n", ipAddress, (int)strlen(ipAddress));
	return ipAddress;
}

ip_port* TCPAssignment::sa2ip_port(struct sockaddr* sa){
	struct sockaddr_in* sin = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
	sin = (struct sockaddr_in*)sa;
	char *ipAddress = inet_ntoa(sin->sin_addr);
	unsigned short port = ntohs(sin->sin_port);
	// printf("IP address: %s Port : %d\n", ipAddress, port);
	ip_port *p = (ip_port*)malloc(sizeof(ip_port));
	p->first = ipAddress;
	p->second = port;
	return p;
}

void TCPAssignment::ip_port2sa(struct sockaddr* sa, ip_port* p){
	struct sockaddr_in* sin;
	sin = (struct sockaddr_in*)sa;
	inet_aton(p->first, &(sin->sin_addr)); 
	sin->sin_port = htons(p->second);
	sin->sin_family = AF_INET;
}

int TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused, int protocol){
	// return socket(param1, param2, param3);
	// SystemCallInterface::SystemCallInterface(domain, protocol, this->host);
	
	int sockfd = createFileDescriptor(pid);
	sockfd_pair_mapping[sockfd] = NULL;
	return sockfd;
}
	
int TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd){

	if(sockfd_pair_mapping.count(fd)==0) return -1;
	ip_port *p = sockfd_pair_mapping[fd];
	if(p!=NULL){
		struct sockaddr* sa = (struct sockaddr*)malloc(sizeof(struct sockaddr));
		ip_port2sa(sa, p);
		struct sockaddr_in* sin = (struct sockaddr_in*)sa;
		// inet_aton(p->first, &(sin->sin_addr));
		unsigned short port = p->second;
		if(ntohl(sin->sin_addr.s_addr) == INADDR_ANY){
			auto it = find(this->INADDR_ANY_PORTS.begin(), this->INADDR_ANY_PORTS.end(), port);
			if(it != this->INADDR_ANY_PORTS.end()){
				this->INADDR_ANY_PORTS.erase(it);
			}
		}
	}
	sockfd_pair_mapping.erase(fd);
	removeFileDescriptor(pid, fd);
	// shutdown(fd, 2);
	return errno == 0 ? 0 : -1;
}

int TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen){
	printf("syscall_bind(%u, %d, %d)\n", syscallUUID, pid, sockfd);
	if(this->sockfd_pair_mapping.count(sockfd)==0){
		// printf("Socket first then bind\n");
		return -1;
	}
	if(this->sockfd_pair_mapping[sockfd]!=NULL){
		// printf("Bind already Exists in sockfd %d => %s:%d\n", 
			// sockfd, this->sockfd_pair_mapping[sockfd]->first, this->sockfd_pair_mapping[sockfd]->second);
		return -1;
	}
	struct sockaddr_in* sin;
	sin = (struct sockaddr_in*)addr;
	unsigned short port = ntohs(sin->sin_port);
	if(!this->INADDR_ANY_PORTS.empty()){
		auto it = find(this->INADDR_ANY_PORTS.begin(), this->INADDR_ANY_PORTS.end(), port);
		if(it != this->INADDR_ANY_PORTS.end()){
			// printf("Same Port with INADDR_ANY!!!\n");
			return -1;
		}
	}

	
	
	
	if(ntohl(sin->sin_addr.s_addr) == INADDR_ANY){ // INADDR_ANY
		std::map<int, ip_port*>::iterator it;
		for(it=sockfd_pair_mapping.begin(); it!=sockfd_pair_mapping.end(); ++it){
			if(it->second != NULL) // If the sockfd is bound
			{
				if( it->second->second == port){
					return -1;
				}
			}
		}

		
		this->INADDR_ANY_PORTS.push_back(port);
		// printf("this->INADDR_ANY_PORTS push_back %d\n", port);
	}
	
	// printf("dst_p\n");
	ip_port *dst_p = sa2ip_port(addr);
	this->sockfd_pair_mapping[sockfd] = dst_p;

	printf("Bind sockfd %d => (%s, %d)\n", sockfd, dst_p->first, dst_p->second);
	printf("Bind Check : (%s, %d)\n", this->sockfd_pair_mapping[sockfd]->first,
	this->sockfd_pair_mapping[sockfd]->second);
	printf("Iterating\n");
	std::map<int, ip_port*>::iterator it;
	for(it=this->sockfd_pair_mapping.begin(); it!=this->sockfd_pair_mapping.end(); ++it){
		printf("%d => (%s, %d)\n", it->first, it->second->first, it->second->second);
	}
	
	// printf("dst_p->first : %s\n", dst_p->first);
	// this->server_client_mapping[p] = dst_p;
	// this->client_server_mapping[dst_p] = p;
	
	// if(this->server_client_mapping.count(this->server_client_mapping[addr])!=0) return -1;
	// int res = bind(sockfd, addr, addrlen);
	// printf("sockfd : %d res : %d errno : %d\n", sockfd, res, errno);

	return 0;
}

int TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *server_addr, socklen_t addrlen){
	printf("syscall_connect(%u, %d, %d)\n", syscallUUID, pid, sockfd);
	// int RoutingInfo::getRoutingTable(const uint8_t* ip_addr)
	if(this->sockfd_pair_mapping.count(sockfd)==0){
		printf("Socket first then connect\n");
		return -1;
	}
	struct sockaddr_in* sin;
	sin = (struct sockaddr_in*)server_addr;
	uint8_t* casted_server_addr = (uint8_t*)(&(sin->sin_addr));
	int client_implicit_port = (this->host)->getRoutingTable(casted_server_addr);
	printf("client_implicit_port : %d\n", client_implicit_port);
	uint8_t client_ip[4];
	uint8_t server_ip[4];
	bool implicitBindSuccess = this->host->getIPAddr(client_ip, client_implicit_port);
	if(!implicitBindSuccess) return -1;
	
	char* client_ipAddress = TCPAssignment::ipInt2ipCharptr(client_ip);
	ip_port* client_ip_port_ptr = (ip_port*)malloc(sizeof(ip_port));
	client_ip_port_ptr->first = client_ipAddress;
	client_ip_port_ptr->second = (unsigned short)client_implicit_port;

	// Implicit bind
	struct sockaddr* client_addr = (struct sockaddr*)malloc(sizeof(struct sockaddr));
	ip_port2sa(client_addr, client_ip_port_ptr);
	this->sockfd_pair_mapping[sockfd] = client_ip_port_ptr;
	// int bind_status = syscall_bind(syscallUUID, pid, sockfd, client_addr, sizeof(struct sockaddr));
	// if(bind_status==-1) return -1;
	// Impliccit bind ends
	
	ip_port* server_ip_port_ptr = sa2ip_port(server_addr);
	if(this->server_client_mapping.count(server_ip_port_ptr)!=0){
		printf("Connect Already Exist\n");
		return -1;
	}
	this->server_client_mapping[server_ip_port_ptr] = client_ip_port_ptr;
	this->server_client_mapping[client_ip_port_ptr] = server_ip_port_ptr;
	printf("make mapping server <-> client (%s, %d) <-> (%s, %d)\n", 
		server_ip_port_ptr->first, server_ip_port_ptr->second, client_ip_port_ptr->first, client_ip_port_ptr->second);

	uint32_t client_ip32 = u32from8(client_ip);
	uint32_t server_ip32 = sin->sin_addr.s_addr;
	u8from32(server_ip, server_ip32);
	unsigned short client_port; 
	unsigned short server_port; 
	client_port = client_ip_port_ptr->second;
	server_port = server_ip_port_ptr->second;
	client_port = htons(client_port);
	server_port = htons(server_port);
	uint32_t seqNum;
	uint8_t *tcp_seg = (uint8_t*)malloc(sizeof(uint8_t)*20);
	int Flags = 1<<1; // SYN
	int ACK = 1<<4;
	Packet* myPacket = allocatePacket(54);
	myPacket->writeData(14+12, &client_ip32, 4);
	myPacket->writeData(14+16, &server_ip32, 4);
	myPacket->writeData(14+20, &client_port, 2);
	myPacket->writeData(14+22, &server_port, 2);
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
	printf("headerlength8 : %x\n", headerlength8);
	uint16_t myPacket_checksum = 0;
	myPacket->writeData(50, &myPacket_checksum, 2);
	myPacket->readData(14+20, tcp_seg, 20);
	// uint32_t server_ip32 = server_ip[0] | (server_ip[1] << 8) | (server_ip[2] << 16) | (server_ip[3] << 24);

	myPacket_checksum = NetworkUtil::tcp_sum(client_ip32, server_ip32, tcp_seg, 20);
	printf("myPacket before change checksum : %x\n", myPacket_checksum);
	myPacket_checksum = ~myPacket_checksum;
	printf("myPacket checksum Field : %x\n", myPacket_checksum);
	myPacket_checksum = htons(myPacket_checksum);
	myPacket->writeData(50, &myPacket_checksum, 2);

	// Verify
	myPacket->readData(14+20, tcp_seg, 20);
	myPacket_checksum = NetworkUtil::tcp_sum(client_ip32, server_ip32, tcp_seg, 20);
	printf("myPacket after change checksum : %x\n", myPacket_checksum);

	// IP Module will fill rest of IP header, 
	// send it to correct networ interface
	this->sendPacket("IPv4", myPacket);

	block(syscallUUID);

	return 0;

	// Success -> 0 Fail -> -1
}

int TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	// int res = getsockname(sockfd, addr, addrlen);
	// printf("getsockname : %d sockfd : %d errno : %d\n", res, sockfd, errno);
	printf("syscall_getsockname(%u, %d, %d)\n", syscallUUID, pid, sockfd);
	if(this->sockfd_pair_mapping.count(sockfd)==0){
		printf("Sockname does not exist!\n");
		return -1;
	}
	if(this->sockfd_pair_mapping[sockfd]==NULL){
		printf("Socket exists but not bind\n");
		return -1;
	}
	ip_port *p = this->sockfd_pair_mapping[sockfd];
	printf("p->first : %s p->second : %d\n", 
	this->sockfd_pair_mapping[sockfd]->first, this->sockfd_pair_mapping[sockfd]->second);
	ip_port2sa(addr, p);

	return 0;
}

int TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	printf("syscall_getpeername(%u, %d, %d)\n", syscallUUID, pid, sockfd);
	// Iterating : 0 => (10.0.1.4, 0)
	// printf("Iterating\n");
	// std::map<int, ip_port*>::iterator it;
	// for(it=this->sockfd_pair_mapping.begin(); it!=this->sockfd_pair_mapping.end(); ++it){
	// 	printf("%d => (%s, %d)\n", it->first, it->second->first, it->second->second);
	// }
	// struct sockaddr *server_addr = (struct sockaddr *)malloc(sizeof(struct sockaddr));
	// socklen_t *server_addrlen_ptr = (socklen_t *)malloc(sizeof(socklen_t));
	// socklen_t server_addrlen = sizeof(struct sockaddr);
	// server_addrlen_ptr = &server_addrlen;
	// int getsockname_status = TCPAssignment::syscall_getsockname(syscallUUID, pid, sockfd, 
	// 							server_addr, server_addrlen_ptr);
	// if(getsockname_status==-1){
	// 	printf("Getsockname for given sockfd failed\n");
	// 	return -1;
	// }
	if(this->sockfd_pair_mapping.count(sockfd)==0){
		printf("Not bound sockfd %d\n", sockfd);
		return -1;
	}
	ip_port* caller_ip_port = this->sockfd_pair_mapping[sockfd];
	// printf("server (%s, %d)\n", server_ip_port->first, server_ip_port->second);
	// printf("server from scratch (%s, %d)\n", this->sockfd_pair_mapping[sockfd]->first, 
	// 	this->sockfd_pair_mapping[sockfd]->second);
	if(this->server_client_mapping.count(caller_ip_port)==0){
		printf("No peer with (%s, %d)\n", caller_ip_port->first, caller_ip_port->second);
		return -1;
	}
	ip_port* peer_ip_port = this->server_client_mapping[caller_ip_port];
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
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
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
	printf("************* packetArrived ******************\n");
	uint8_t src_ip[4];
	uint8_t dest_ip[4];
	unsigned short src_port;
	unsigned short dest_port;
	uint32_t seqNum;
	uint8_t *tcp_seg = (uint8_t*)malloc(sizeof(uint8_t)*20);
	int Flags;
	
	packet->readData(14+33, &Flags, 1);
	// printf("SYN : %d\n", Flags & 1);
	// printf("ACK : %d\n", !!(Flags & (1<<4)));
	int SYN = !!(Flags & (1<<1));
	int ACK = !!(Flags & (1<<4));
	int FIN = !!(Flags & 1);
	if(FIN) {
		printf("FIN\n");
		return;
	}
	else if(!SYN && ACK){
		printf("ACK\n");
		return;
	}
	else if(SYN && ACK){
		// packet->readData(14+12, src_ip, 4);
		// packet->readData(14+16, dest_ip, 4);
		// packet->readData(14+20, &src_port, 2);
		// packet->readData(14+22, &dest_port, 2);
		
		// printf("src (%s, %u) <-> dest (%s, %u)\n", ipInt2ipCharptr(src_ip), ntohs(src_port), 
		// 	ipInt2ipCharptr(dest_ip), ntohs(dest_port));
		unblock(0);
	}
	printf("After checking\n");
	// Case SYN & SYNACK

	packet->readData(14+12, src_ip, 4);
	packet->readData(14+16, dest_ip, 4);
	packet->readData(14+20, &src_port, 2);
	packet->readData(14+22, &dest_port, 2);
	packet->readData(14+24, &seqNum, 4);


	packet->readData(14+20, tcp_seg, 20);
	uint32_t src_ip32 = u32from8(src_ip);
	uint32_t dest_ip32 = u32from8(dest_ip);
	
	// Verfiy packet's checksum
	uint16_t packet_checksum = NetworkUtil::tcp_sum(src_ip32, dest_ip32, tcp_seg, 20);
	printf("packet_checksum : %x\n", packet_checksum);
	// if(packet_checksum != 0xFFFF) return;
	
	
	// char* src_ip_Charptr = ipInt2ipCharptr(src_ip);
	// char* dest_ip_Charptr = ipInt2ipCharptr(dest_ip);
	// printf("src_ip : %s dest_ip : %s\n", src_ip_Charptr, dest_ip_Charptr);
	// Prepare to sent
	Packet* myPacket = this->clonePacket(packet);
	// Swap src and dest
	// printf("src_port : %u dest_port : %u\n", ntohs(src_port), ntohs(dest_port));
	myPacket->writeData(14+12, dest_ip, 4);
	myPacket->writeData(14+16, src_ip, 4);
	myPacket->writeData(14+20, &dest_port, 2);
	myPacket->writeData(14+22, &src_port, 2);
	// printf("seqNum : %u\n", seqNum);
	seqNum = ntohl(seqNum);
	seqNum++;
	// printf("ackNum : %u\n", seqNum);
	seqNum = htonl(seqNum);
	// printf("ackNum : %u\n", seqNum);
	myPacket->writeData(14+28, &seqNum, 4);
	// if( Flags & 1) Flags = Flags | ACK;
	if(SYN && !ACK) {
		printf("SYN\n");
		Flags = Flags | (1<<4);
	}
	else if(SYN && ACK) {
		printf("SYNACK\n");
		Flags = (1<<4);
	}
	// printf("write Flags : %d\n", Flags);
	myPacket->writeData(14+33, &Flags, 1);
	uint16_t myPacket_checksum = 0;
	myPacket->writeData(50, &myPacket_checksum, 2);
	myPacket->readData(14+20, tcp_seg, 20);
	myPacket_checksum = NetworkUtil::tcp_sum(dest_ip32, src_ip32, tcp_seg, 20);
	printf("myPacket before change checksum : %x\n", myPacket_checksum);
	myPacket_checksum = ~myPacket_checksum;
	myPacket_checksum = htons(myPacket_checksum);
	printf("myPacket checksum Field : %x\n", myPacket_checksum);
	myPacket->writeData(50, &myPacket_checksum, 2);

	// Verify
	myPacket->readData(14+20, tcp_seg, 20);
	myPacket_checksum = NetworkUtil::tcp_sum(dest_ip32, src_ip32, tcp_seg, 20);
	printf("myPacket after change checksum : %x\n", myPacket_checksum);

	// IP Module will fill rest of IP header, 
	// send it to correct networ interface
	this->sendPacket("IPv4", myPacket);

	// given packet is my responsibility
	this->freePacket(packet);

	return;

}

void TCPAssignment::timerCallback(void* payload)
{

}


}
