#include <string>
#include <stdint.h>
using namespace std;

class IpManager {
public:
    IpManager();
    ~IpManager();

    bool SetIpRange(string ipStart, uint32_t ipNum);
    string AssignNewIp();
    void ReleaseIp(string ip);

private:
	uint32_t m_IpOffset;
	uint32_t m_IpStart;
	uint32_t m_MaxClient;
	uint32_t m_CurrentClient;
	bool* m_IpInUse;
};