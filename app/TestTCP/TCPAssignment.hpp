/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

//JIN BRANCH TEST222



#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>
#include <stdbool.h>
#include <E/E_Common.hpp>

typedef std::pair<char*, unsigned short> pair; 

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
	
private:

private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual pair* sa_to_pair(struct sockaddr* sa);
	virtual int syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused, int protocol);
	virtual int syscall_close(UUID syscallUUID, int pid, int fd);
	virtual int syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen);
	virtual int syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	virtual int syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	virtual ~TCPAssignment();
	int sockfd;
	int close_status;
	int bind_status;
	int getsockname_status;
	int getpeername_status;
	Host *host;
	std::map<pair, pair> server_client_mapping;
	std::map<pair, pair> client_server_mapping;
	std::map<int, pair*> sockfd_pair_mapping;
	std::vector<unsigned short> INADDR_ANY_PORTS;

protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
