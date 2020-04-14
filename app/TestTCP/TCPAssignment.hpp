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

typedef std::pair<int, int> pid_sockfd;
typedef enum {
	SC_BOUND,
	SC_LISTEN, 
	SC_SYN_SENT, 
	SC_SYN_RCVD, 
	SC_ESTAB,
	SC_FIN_WAIT1,
	SC_FIN_WAIT2,
	SC_CLOSE_WAIT,
	SC_CLOSING,
	SC_LAST_ACK,
	SC_TIME_WAIT,
	SC_CLOSED,
}Sock_status;

typedef struct Ip_port{
	char* ipAddr;
	unsigned short port;
	Ip_port(char* ip, unsigned short p): ipAddr(ip), port(p) {}
	Ip_port(): ipAddr(NULL), port(0){}
}Ip_port;

typedef struct Sock{
	Sock_status sock_status;
	struct Ip_port *ip_port;
	int maxBacklog;
	int backlog;
	Sock(Sock_status ss, struct Ip_port *ip_port) : sock_status(ss), ip_port(ip_port){}
	Sock(): sock_status(SC_CLOSED), ip_port(NULL), maxBacklog(0), backlog(0) {}
}Sock;

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
	virtual struct Ip_port* sa2ip_port(struct sockaddr* sa);
	virtual void ip_port2sa(struct sockaddr* sa, struct Ip_port *p);
	virtual void u8from32 (uint8_t u8[4], uint32_t u32);
	virtual uint32_t u32from8 (uint8_t u8[4]);
	virtual pid_sockfd* find_pid_sockfd_by_Ip_port(uint8_t dest_ip[4], unsigned short dest_port);

	virtual int syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused, int protocol);
	virtual int syscall_close(UUID syscallUUID, int pid, int fd);
	virtual int syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen);
	virtual int syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen);
	virtual int syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	virtual int syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	virtual int syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
	virtual int syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);

	virtual void connect_block(UUID syscallUUID);
	virtual void connect_unblock(int status);
	virtual void accept_block(UUID syscallUUID, int connfd);
	virtual void accept_unblock();

	// virtual void TimerCallback(void* payload);
	virtual ~TCPAssignment();
	int sockfd;
	std::queue<int> connfds;
	int seqNum;
	int close_status;
	int bind_status;
	int connect_status;
	int getsockname_status;
	int getpeername_status;
	int listen_status;
	int accept_status;
	bool connect_lock;
	bool accept_lock;
	UUID connect_blockedUUID;
	UUID accept_blockedUUID;
	Host *host;
	std::map<pid_sockfd, Sock*> sock_mapping;
	std::map<Ip_port*, Ip_port*> client_server_mapping; 
	std::map<Ip_port*, std::deque<Ip_port*> > server_client_mapping;
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
