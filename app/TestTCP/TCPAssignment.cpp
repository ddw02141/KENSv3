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
	this->getpeername_status = 0;
	this->mapping = std::map<struct sockaddr*, struct sockaddr*>();
}

TCPAssignment::~TCPAssignment()
{
	this->mapping.clear();
}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

struct sockaddr_in* TCPAssignment::sa_to_sin(struct sockaddr* sa){
	struct sockaddr_in* sin;
	std::memset(sin, 0, sizeof *sin);
	std::memcpy(sin, sa, sizeof(*sa));
	return sin;
	// char *ipAddress = inet_ntoa(sin->sin_addr);
	// unsigned short port = sin->sin_port;
	// // printf("IP address: %s Port : %d\n", s, sin->sin_port);
	// return std::make_pair(ipAddress, port);
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused, int protocol){
	// return socket(param1, param2, param3);
	// SystemCallInterface::SystemCallInterface(domain, protocol, this->host);
	do{
		this->sockfd = createFileDescriptor(pid);
	}while(this->sockfd < 3);
	// printf("this->sockfd in syscall_socket: %d\n", this->sockfd);
	// socket(domain, type__unused, protocol);
	struct sockaddr *addr;
	socklen_t addrlen;
	// printf("this->sockfd : %d\n", this->sockfd);
	syscall_getpeername(syscallUUID, pid, this->sockfd, 
	static_cast<struct sockaddr *>((void*)(addr)), static_cast<socklen_t*>((void*)(addrlen)));
	this->mapping[addr] = NULL;
	return;
}
	
int TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd){
	// return shutdown(param1, 2);
	struct sockaddr *addr;
	socklen_t addrlen;
	// printf("this->sockfd : %d\n", this->sockfd);
	syscall_getpeername(syscallUUID, pid, fd, 
	static_cast<struct sockaddr *>((void*)(addr)), static_cast<socklen_t*>((void*)(addrlen)));
	this->mapping.erase(addr);
	removeFileDescriptor(pid, fd);
	// shutdown(fd, 2);
	return errno == 0 ? 0 : -1;
}

int TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen){
	int res = bind(sockfd, addr, addrlen);
	printf("sockfd : %d res : %d errno : %d\n", sockfd, res, errno);
	return res == 0 ? 0 : -1;
}

int TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	int res = getpeername(sockfd, addr, addrlen);
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
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int, param.param3_int);
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
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		SystemCallInterface::returnSystemCall(syscallUUID, this->bind_status);
		break;
	case GETSOCKNAME:
		//this->syscall_getsockname(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
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
