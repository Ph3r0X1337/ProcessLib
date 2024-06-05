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
}
