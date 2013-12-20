#include <stdio.h>
#include <string.h>
#include <string>
#include <time.h>
#include "ToyTunnel.h"

extern void SendToClient(sockaddr* dst_addr, const char* buf, int len);
extern void SendToTunnel(const char* buf, int len);

ToyTunnel::ToyTunnel(sockaddr_in addr, string vpn_ip)
{
    memcpy(&m_addr_in, &addr, sizeof(sockaddr_in));
    m_pAddr = (sockaddr*)&m_addr_in;
    m_vpnIp = vpn_ip;
    m_lastRecvTime = time(NULL);
}

void ToyTunnel::Send(const char* buf, int len)
{
	SendToClient(m_pAddr, buf, len);
}

void ToyTunnel::Recv(const char* packet, int len)
{
	m_lastRecvTime = time(NULL);
	if (*packet == 0) {
		// control packet, current only for auth and keep alive
		// so here must be keep alive, return the same control packet
		Send(packet, len);
	} else {
		SendToTunnel(packet, len);
	}
}

bool ToyTunnel::Alive()
{
	uint32_t now = time(NULL);
	if (now - m_lastRecvTime > TUNNEL_TIMEOUT) {
		return false;
	}
	return true;
}