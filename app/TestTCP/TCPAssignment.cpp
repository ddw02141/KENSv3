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
	this->getsockname_status = 0;
	this->getpeername_status = 0;
	this->sockfd_pair_mapping = std::map<int, ip_port*>();
	this->INADDR_ANY_PORTS = std::vector<unsigned short>();
}

TCPAssignment::~TCPAssignment()
{
	this->sockfd_pair_mapping.clear();
	this->INADDR_ANY_PORTS.clear();
}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

ip_port* TCPAssignment::sa_to_pair(struct sockaddr* sa){
	struct sockaddr_in* sin;
	sin = (struct sockaddr_in*)sa;
	char *ipAddress = inet_ntoa(sin->sin_addr);
	unsigned short port = ntohs(sin->sin_port);
	// printf("IP address: %s Port : %d\n", ipAddress, port);
	ip_port *p = (ip_port*)malloc(sizeof(ip_port));
	*p = std::make_pair(ipAddress, port);
	return p;
}

int TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused, int protocol){
	// return socket(param1, param2, param3);
	// SystemCallInterface::SystemCallInterface(domain, protocol, this->host);
	
	int sockfd = createFileDescriptor(pid);
	sockfd_pair_mapping[sockfd] = NULL;
	return sockfd;
}
	
int TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd){
	// return shutdown(param1, 2);
	// struct sockaddr *sa;
	// socklen_t salen;
	// syscall_getpeername(syscallUUID, pid, fd, 
	// static_cast<struct sockaddr *>((void*)(sa)), static_cast<socklen_t*>((void*)(salen)));
	// pair p = TCPAssignment::sa_to_pair(sa);
	// this->server_client_mapping.erase(p);
	// this->client_server_mapping.erase(p);
	// for(auto element:server_client_mapping){

	// }
	// for(auto element:client_server_mapping){
		
	// }
	// this->sockfd_pair_mapping.erase(fd);
	if(sockfd_pair_mapping.count(fd)==0) return -1;
	ip_port *p = sockfd_pair_mapping[fd];
	if(p!=NULL){
		struct sockaddr_in* sin = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
		inet_aton(p->first, &(sin->sin_addr));
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
		
		this->INADDR_ANY_PORTS.push_back(port);
		// printf("this->INADDR_ANY_PORTS push_back %d\n", port);
	}
	
	// printf("dst_p\n");
	ip_port *dst_p = sa_to_pair(addr);
	this->sockfd_pair_mapping[sockfd] = dst_p;
	
	
	// printf("dst_p->first : %s\n", dst_p->first);
	// this->server_client_mapping[p] = dst_p;
	// this->client_server_mapping[dst_p] = p;
	
	// if(this->server_client_mapping.count(this->server_client_mapping[addr])!=0) return -1;
	// int res = bind(sockfd, addr, addrlen);
	// printf("sockfd : %d res : %d errno : %d\n", sockfd, res, errno);

	return 0;
}

int TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	// int res = getsockname(sockfd, addr, addrlen);
	// printf("getsockname : %d sockfd : %d errno : %d\n", res, sockfd, errno);
	if(this->sockfd_pair_mapping.count(sockfd)==0){
		// printf("Sockname does not exist!\n");
		return -1;
	}
	if(this->sockfd_pair_mapping[sockfd]==NULL){
		// printf("Socket exists but not bind\n");
		return -1;
	}
	ip_port *p = this->sockfd_pair_mapping[sockfd];
	struct sockaddr_in* sin;
	sin = (struct sockaddr_in*)addr;
	inet_aton(p->first, &(sin->sin_addr)); 
	sin->sin_port = htons(p->second);
	sin->sin_family = AF_INET;

	return 0;
}

int TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	int res = getpeername(sockfd, addr, addrlen);
	// printf("getpeername : %d errno : %d\n", res, errno);
	return errno == 0 ? 0 : -1;
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
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
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

}

void TCPAssignment::timerCallback(void* payload)
{

}


}
