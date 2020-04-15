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
	this->connfds = std::queue<int>(); 
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
	this->INADDR_ANY_PORTS = std::vector<unsigned short>();
	this->connect_lock = false;
	this->accept_lock = false;
	this->connect_blockedUUID = 999;
	this->accept_blockedUUID = 888;
	this->seqNum = 22;
}

TCPAssignment::~TCPAssignment()
{
	this->sock_mapping.clear();
	this->client_server_mapping.clear();
	// Map iterating 하면서 clear 해야함
	auto it = this->clients.begin();
	this->clients.clear();
	this->INADDR_ANY_PORTS.clear();
	std::queue<int> empty;
	std::swap(this->connfds, empty);
}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::connect_block(UUID syscallUUID){
	// printf("connect_block\n");
	this->connect_lock = true;
	this->connect_blockedUUID = syscallUUID;
	// Time t = TimeUtil::makeTime(100, TimeUtil::MSEC);
	// TimerModule::addTimer(&syscallUUID, t);
}

void TCPAssignment::connect_unblock(int status){
	// printf("connect_unblock\n");
	SystemCallInterface::returnSystemCall(this->connect_blockedUUID, status);
	this->connect_lock = false;
	this->connect_blockedUUID = 999;
}

void TCPAssignment::accept_block(UUID syscallUUID, int connfd){
	// printf("accept_block(%lu, %d)\n", syscallUUID, connfd);
	this->accept_lock = true;
	this->accept_blockedUUID = syscallUUID;
	this->connfds.push(connfd);
	// Time t = TimeUtil::makeTime(100, TimeUtil::MSEC);
	// TimerModule::addTimer(&syscallUUID, t);
}

void TCPAssignment::accept_unblock(){
	// printf("accept_unblock\n");
	if(this->connfds.empty())
		SystemCallInterface::returnSystemCall(this->connect_blockedUUID, -1);
	else{
		// printf("unblock success with %d\n", this->connfds.front());
		// Time t = TimeUtil::makeTime(100, TimeUtil::MSEC);
		// TimerModule::addTimer(sock, t);
		SystemCallInterface::returnSystemCall(this->connect_blockedUUID, this->connfds.front());
		this->connfds.pop();
	}
	this->accept_lock = false;
	this->accept_blockedUUID = 888;
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

pid_sockfd* TCPAssignment::find_pid_sockfd_by_Ip_port(uint8_t dest_ip[4], unsigned short dest_port){
	Ip_port* dest_ip_port = (struct Ip_port*)malloc(sizeof(struct Ip_port));
	char *destIP = ipInt2ipCharptr(dest_ip);
	unsigned short destPort = ntohs(dest_port);
	// dest : (192.168.0.7, 3879)
	std::map<pid_sockfd, Sock*>::iterator it;
	for(it=sock_mapping.begin(); it!=sock_mapping.end(); ++it){
		// if(it->second->sock_status==SC_LISTEN || it->second->sock_status==SC_SYN_RCVD){
		if(( strcmp(it->second->ip_port->ipAddr, destIP) == 0 || strcmp(it->second->ip_port->ipAddr, "0.0.0.0") == 0) &&
			it->second->ip_port->port == destPort) // If the sockfd is bound
		{
			return (pid_sockfd*)&(it->first);
		}
		// }
	}

	return NULL;

}


int TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused, int protocol){
	// return socket(param1, param2, param3);
	// SystemCallInterface::SystemCallInterface(domain, protocol, this->host);
	
	int sockfd = createFileDescriptor(pid);
	Sock *sock = (Sock *)malloc(sizeof(Sock));
	sock->sock_status = SC_CLOSED;
	sock->ip_port = NULL;
	this->sock_mapping[std::make_pair(pid, sockfd)] = sock;
	return sockfd;
}
	
int TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd){

	if(sock_mapping.count(std::make_pair(pid, fd))==0) return -1;
	Sock *s = sock_mapping[std::make_pair(pid, fd)];
	Ip_port *p = s->ip_port;
	if(p!=NULL){
		struct sockaddr* sa = (struct sockaddr*)malloc(sizeof(struct sockaddr));
		ip_port2sa(sa, p);
		struct sockaddr_in* sin = (struct sockaddr_in*)sa;
		// inet_aton(p->first, &(sin->sin_addr));
		unsigned short port = p->port;
		if(ntohl(sin->sin_addr.s_addr) == INADDR_ANY){
			auto it = find(this->INADDR_ANY_PORTS.begin(), this->INADDR_ANY_PORTS.end(), port);
			if(it != this->INADDR_ANY_PORTS.end()){
				this->INADDR_ANY_PORTS.erase(it);
			}
		}
	}
	sock_mapping.erase(std::make_pair(pid, fd));
	removeFileDescriptor(pid, fd);
	// shutdown(fd, 2);
	return errno == 0 ? 0 : -1;
}

int TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen){
	// printf("syscall_bind(%lu, %d, %d)\n", syscallUUID, pid, sockfd);
	if(this->sock_mapping.count(std::make_pair(pid, sockfd))==0){
		// printf("Socket first then bind\n");
		return -1;
	}
	if(this->sock_mapping[std::make_pair(pid, sockfd)]->sock_status != SC_CLOSED){
		// printf("Bind already Exists in sockfd %d => %s:%d\n", 
			// sockfd, this->sock_mapping_mapping[sockfd]->first, this->sock_mapping_mapping[sockfd]->second);
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
	Sock *sock = (Sock *)malloc(sizeof(Sock));
	sock->sock_status = SC_BOUND;
	sock->ip_port = dst_p;
	this->sock_mapping[std::make_pair(pid, sockfd)] = sock;

	// printf("Bind sockfd %d => (%s, %d)\n", sockfd, dst_p->first, dst_p->second);
	// printf("Bind Check : (%s, %d)\n", this->sock_mapping_mapping[sockfd]->first,
	// this->sock_mapping_mapping[sockfd]->second);
	// printf("Iterating\n");
	// std::map<int, ip_port*>::iterator it;
	// for(it=this->sock_mapping_mapping.begin(); it!=this->sock_mapping_mapping.end(); ++it){
	// 	printf("%d => (%s, %d)\n", it->first, it->second->first, it->second->second);
	// }
	
	// printf("dst_p->first : %s\n", dst_p->first);
	// this->client_server_mapping[p] = dst_p;
	// this->client_server_mapping[dst_p] = p;
	
	// if(this->client_server_mapping.count(this->client_server_mapping[addr])!=0) return -1;
	// int res = bind(sockfd, addr, addrlen);
	// printf("sockfd : %d res : %d errno : %d\n", sockfd, res, errno);

	return 0;
}

int TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *server_addr, socklen_t addrlen){
	// printf("syscall_connect(%lu, %d, %d)\n", syscallUUID, pid, sockfd);
	// int RoutingInfo::getRoutingTable(const uint8_t* ip_addr)
	if(this->sock_mapping.count(std::make_pair(pid, sockfd))==0){
		// printf("Socket first then connect\n");
		return -1;
	}
	struct sockaddr_in* sin;
	sin = (struct sockaddr_in*)server_addr;
	uint8_t* casted_server_addr = (uint8_t*)(&(sin->sin_addr));
	int client_implicit_port = (this->host)->getRoutingTable(casted_server_addr);
	// printf("client_implicit_port : %d\n", client_implicit_port);
	uint8_t client_ip[4];
	uint8_t server_ip[4];
	bool implicitBindSuccess = this->host->getIPAddr(client_ip, client_implicit_port);
	if(!implicitBindSuccess) return -1;
	
	char* client_ipAddress = TCPAssignment::ipInt2ipCharptr(client_ip);
	Ip_port* client_ip_port_ptr = (struct Ip_port*)malloc(sizeof(struct Ip_port));
	client_ip_port_ptr->ipAddr = client_ipAddress;
	client_ip_port_ptr->port = (unsigned short)client_implicit_port;

	// Implicit bind
	Sock *client_sock = (Sock *)malloc(sizeof(Sock));
	client_sock->sock_status = SC_BOUND;
	client_sock->ip_port = client_ip_port_ptr;
	this->sock_mapping[std::make_pair(pid, sockfd)] = client_sock;
	// struct sockaddr* client_addr = (struct sockaddr*)malloc(sizeof(struct sockaddr));
	// ip_port2sa(client_addr, client_ip_port_ptr);
	// int bind_status = syscall_bind(syscallUUID, pid, sockfd, client_addr, sizeof(struct sockaddr));
	// if(bind_status==-1) return -1;
	// Impliccit bind ends
	
	Ip_port* server_ip_port_ptr = sa2ip_port(server_addr);
	if(this->client_server_mapping.count(server_ip_port_ptr)!=0){
		// printf("Connect Already Exist\n");
		return -1;
	}
	this->client_server_mapping[server_ip_port_ptr] = client_ip_port_ptr;
	this->client_server_mapping[client_ip_port_ptr] = server_ip_port_ptr;
	// printf("make mapping server <-> client\n(%s, %d) <-> (%s, %d)\n", 
	// 	server_ip_port_ptr->ipAddr, server_ip_port_ptr->port, 
	// 	client_ip_port_ptr->ipAddr, client_ip_port_ptr->port);

	uint32_t client_ip32 = u32from8(client_ip);
	uint32_t server_ip32 = sin->sin_addr.s_addr;
	u8from32(server_ip, server_ip32);
	unsigned short client_port; 
	unsigned short server_port; 
	client_port = client_ip_port_ptr->port;
	server_port = server_ip_port_ptr->port;
	client_port = htons(client_port);
	server_port = htons(server_port);
	uint8_t *tcp_seg = (uint8_t*)malloc(sizeof(uint8_t)*20);
	int Flags = 1<<1; // SYN
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
	// printf("headerlength8 : %x\n", headerlength8);
	uint16_t myPacket_checksum = 0;
	myPacket->writeData(50, &myPacket_checksum, 2);
	myPacket->readData(14+20, tcp_seg, 20);
	// uint32_t server_ip32 = server_ip[0] | (server_ip[1] << 8) | (server_ip[2] << 16) | (server_ip[3] << 24);

	myPacket_checksum = NetworkUtil::tcp_sum(client_ip32, server_ip32, tcp_seg, 20);
	// printf("myPacket before change checksum : %x\n", myPacket_checksum);
	myPacket_checksum = ~myPacket_checksum;
	// printf("myPacket checksum Field : %x\n", myPacket_checksum);
	myPacket_checksum = htons(myPacket_checksum);
	myPacket->writeData(50, &myPacket_checksum, 2);

	// Verify
	myPacket->readData(14+20, tcp_seg, 20);
	myPacket_checksum = NetworkUtil::tcp_sum(client_ip32, server_ip32, tcp_seg, 20);
	// printf("myPacket after change checksum : %x\n", myPacket_checksum);

	// IP Module will fill rest of IP header, 
	// send it to correct networ interface
	this->sendPacket("IPv4", myPacket);

	
	// SC_LISTEN => SC_SYN_SENT
	client_sock = this->sock_mapping[std::make_pair(pid, sockfd)];
	client_sock->sock_status = SC_SYN_SENT;

	connect_block(syscallUUID);

	return 0;

	// Success -> 0 Fail -> -1
}

int TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog){
	// printf("syscall_listen(%lu, %d, %d)\n", syscallUUID, pid, sockfd);
	if(this->sock_mapping.count(std::make_pair(pid, sockfd))==0){
		// printf("Socket first then listen\n");
		return -1;
	}
	Sock *serverSock = this->sock_mapping[std::make_pair(pid, sockfd)];
	serverSock->sock_status = SC_LISTEN;
	serverSock->maxBacklog = backlog;
	serverSock->backlog = 0;
	
	return 0;
}
int TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	// printf("syscall_accept(%lu, %d, %d)\n", syscallUUID, pid, sockfd);
	if(this->sock_mapping.count(std::make_pair(pid, sockfd))==0){
		// printf("Socket first then accept\n");
		return -1;
	}
	int connfd;
	Sock *sock = this->sock_mapping[std::make_pair(pid, sockfd)];	
	std::deque<std::pair<bool, Ip_port*> >::iterator it;
	if(sock->backlog <= sock->maxBacklog){
		if(!this->clients.empty()){
		for(it=this->clients.begin(); it!=this->clients.end(); ++it){
			if(	strcmp(sock->ip_port->ipAddr, "0.0.0.0")==0 || 
				strcmp(sock->ip_port->ipAddr, it->second->ipAddr)==0 && 
				(it->second->port==sock->ip_port->port)){
					std::pair<bool, Ip_port*> p = this->clients.front();
					bool isSYN = p.first;
					Ip_port* client_ip_port = p.second;
					this->clients.pop_front();

					ip_port2sa(addr, client_ip_port);
					// ip_port2sa(addr, sock->ip_port);

					connfd = createFileDescriptor(pid);
					// printf("connfd : %d\n", connfd);

					Sock *newsock = (Sock *)malloc(sizeof(Sock));
					newsock->sock_status = SC_ESTAB;
					newsock->ip_port = sock->ip_port;
					// printf("client ip_port : (%s, %u)\n", client_ip_port->ipAddr, client_ip_port->port);
					// printf("pid_sockfd : (%d, %d)\n", pid, connfd);
					// printf("%u %u %u %u\n", htons(46759), htons(21053), htons(33500), htons(9999));
					this->sock_mapping[std::make_pair(pid, connfd)] = newsock;
					if(it->first) sock->backlog--;
					SystemCallInterface::returnSystemCall(syscallUUID, connfd);
					return 0;
				}		
			}
		}
	
	}
	// accept_block(syscallUUID, connfd);	
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
	uint32_t seqNum;
	uint8_t *tcp_seg = (uint8_t*)malloc(sizeof(uint8_t)*20);
	int Flags;

	packet->readData(14+12, src_ip, 4);
	packet->readData(14+16, dest_ip, 4);
	packet->readData(14+20, &src_port, 2);
	packet->readData(14+22, &dest_port, 2);
	packet->readData(14+33, &Flags, 1);
	// printf("SYN : %d\n", Flags & 1);
	// printf("ACK : %d\n", !!(Flags & (1<<4)));
	int SYN = !!(Flags & (1<<1));
	int ACK = !!(Flags & (1<<4));
	int FIN = !!(Flags & 1);

	char *destIP;
	unsigned short destPort;
	Ip_port* client_ip_port = (Ip_port*)malloc(sizeof(Ip_port));
	Ip_port* server_ip_port = (Ip_port*)malloc(sizeof(Ip_port));
	client_ip_port->ipAddr = ipInt2ipCharptr(src_ip);
	client_ip_port->port = ntohs(src_port);
	server_ip_port->ipAddr = ipInt2ipCharptr(dest_ip);
	server_ip_port->port = ntohs(dest_port);
	pid_sockfd *server_pid_sockfd = (pid_sockfd *)malloc(sizeof(pid_sockfd));
	// printf("***(%s, %u) --> (%s, %u)***\n", ipInt2ipCharptr(src_ip), ntohs(src_port),
	// 	ipInt2ipCharptr(dest_ip), ntohs(dest_port));
	if(SYN && !ACK){
		// printf("SYN\n");
		// LISTEN하고 있는 애를 찾아서
		// 이녀석의 backlog를 올려주나?
		// backlog값을 넘지 않는다면?
		// pid_sockfd 찾아서 LISTEN => SC_SYN_RCVD
		server_pid_sockfd = find_pid_sockfd_by_Ip_port(dest_ip, dest_port);
		if(server_pid_sockfd==NULL){
			;
			// printf("NULL : find_pid_sockfd_by_Ip_port(%s, %u)\n",
			// 	ipInt2ipCharptr(dest_ip), dest_port);
		}
		else{
			if(this->sock_mapping[*server_pid_sockfd]->backlog
				>= this->sock_mapping[*server_pid_sockfd]->maxBacklog){
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
					this->clients.push_back(std::make_pair(true, client_ip_port));
					this->sock_mapping[*server_pid_sockfd]->backlog++;
				}


			}
			// }
		}
	}
	else if(SYN && ACK){
		// printf("SYNACK\n");
		// pid_sockfd 찾아서 SC_SYN_SENT => SC_ESTAB
		server_pid_sockfd = find_pid_sockfd_by_Ip_port(dest_ip, dest_port);
		if(server_pid_sockfd==NULL){
			// printf("NULL : find_pid_sockfd_by_Ip_port(%s, %u)\n",
			// 	ipInt2ipCharptr(dest_ip), dest_port);
		}
		else{
			Sock *sock = this->sock_mapping[*server_pid_sockfd];
			sock->sock_status = SC_ESTAB;
			connect_unblock(0);	
		}
		
		// if(this->connect_lock) accept_unblock();
	}

	else if(!SYN && ACK){
		// printf("ACK\n");	
		server_pid_sockfd = find_pid_sockfd_by_Ip_port(dest_ip, dest_port);	
		bool f = true;
		bool isSYN = false;
		if(server_pid_sockfd==NULL){
			;
			// printf("NULL : find_pid_sockfd_by_Ip_port(%s, %u)\n",
			// 	ipInt2ipCharptr(dest_ip), dest_port);
		}
		else{
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
				this->sock_mapping[*server_pid_sockfd]->backlog--;
			}
			
			// for(int i=0;i<dq.size();i++)
			return;
		}
		
	}
	else if(FIN) {
		// printf("FIN\n");
		
		return;
	}

	// printf("After checking\n");
	// Case SYN & SYNACK

	
	packet->readData(14+24, &seqNum, 4);
	packet->readData(14+20, tcp_seg, 20);
	uint32_t src_ip32 = u32from8(src_ip);
	uint32_t dest_ip32 = u32from8(dest_ip);
	
	// Verfiy packet's checksum
	uint16_t packet_checksum = NetworkUtil::tcp_sum(src_ip32, dest_ip32, tcp_seg, 20);
	// printf("packet_checksum : %x\n", packet_checksum);
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
		Flags = Flags | (1<<4);
	}
	else if(SYN && ACK) {
		Flags = (1<<4);
	}
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

	// given packet is my responsibility
	this->freePacket(packet);

	return;

}

void TCPAssignment::timerCallback(void* payload)
{
	// printf("timerCallback\n");
	// SystemCallInterface::returnSystemCall(this->connect_blockedUUID, this->connfds.front());
	// this->connfds.pop();
	// this->accept_lock = false;
	// this->accept_blockedUUID = 888;
}


}
