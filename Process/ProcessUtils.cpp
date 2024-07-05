#include "ProcessUtils.hpp"

namespace Process
{
	bool setDebugPrivilege() noexcept
	{
		bool bRet{ false };
		HANDLE hToken{ INVALID_HANDLE_VALUE };
		LUID luid{};

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
			{
				TOKEN_PRIVILEGES tokenPriv{};
				tokenPriv.PrivilegeCount = 1;
				tokenPriv.Privileges[0].Luid = luid;
				tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				bRet = AdjustTokenPrivileges(hToken, false, &tokenPriv, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
			}
		}
		
		return bRet;
	}

	std::vector<SigByte> getSigBytePattern(const std::vector<short>& pattern)
	{
		std::vector<SigByte> result{};

		for (const short currByte : pattern)
		{
			if (currByte < 0 || currByte > 0xFF)
			{
				result.push_back({ static_cast<char>(0x0), '?' });
			}
			else
			{
				result.push_back({ static_cast<char>(currByte), 'x' });
			}
		}

		return result;
	}
}