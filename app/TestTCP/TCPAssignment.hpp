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
#include <E/E_TimerModule.hpp>
#include <E/E_TimeUtil.hpp>


typedef std::pair<char*, unsigned short> ip_port; 

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule, public RoutingInfo
{
	
private:

private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual char* ipInt2ipCharptr(uint8_t ip_buffer[4]);
	virtual ip_port* sa2ip_port(struct sockaddr* sa);
	virtual void ip_port2sa(struct sockaddr* sa, ip_port* p);
	virtual void u8from32 (uint8_t u8[4], uint32_t u32);
	virtual uint32_t u32from8 (uint8_t u8[4]);
	virtual int syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused, int protocol);
	virtual int syscall_close(UUID syscallUUID, int pid, int fd);
	virtual int syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen);
	virtual int syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen);
	virtual int syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	virtual int syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	virtual void block(UUID syscallUUID);
	virtual void unblock(int status);

	// virtual void TimerCallback(void* payload);
	virtual ~TCPAssignment();
	int sockfd;
	int close_status;
	int bind_status;
	int connect_status;
	int getsockname_status;
	int getpeername_status;
	bool lock;
	UUID blockedUUID;
	Host *host;
	std::map<int, ip_port*> sockfd_pair_mapping;
	std::map<ip_port*, ip_port*> server_client_mapping; 
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
