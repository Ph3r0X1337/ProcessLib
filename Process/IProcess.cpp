#include "IProcess.hpp"

char* IProcessA::findPatternInBuffer(const char* const pStart, const DWORD scanSize, const std::vector<Process::SigByte>& signature, bool& patternFound) const noexcept
{
	if (!pStart || !scanSize || !signature.size() || scanSize < signature.size())
	{
		patternFound = false;
		return nullptr;
	}

	for (const char* pCurrChar{ const_cast<const char*>(pStart) }; pCurrChar < (pStart + (scanSize - signature.size())); ++pCurrChar)
	{
		const char* pCharIt{ pCurrChar };
		bool found{ true };

		for (const Process::SigByte& currSigByte : signature)
		{
			switch (currSigByte.maskChar)
			{
			case 'x':
			{
				if (currSigByte.patternChar != *pCharIt++)
				{
					found = false;
				}
				continue;
			}
			case '?':
			{
				++pCharIt;
				continue;
			}
			default:
			{
				patternFound = false;
				return nullptr;
			}
			}
		}

		if (found)
		{
			patternFound = true;
			return const_cast<char*>(pCurrChar);
		}
	}

	patternFound = false;
	return nullptr;
}

char* IProcessW::findPatternInBuffer(const char* const pStart, const DWORD scanSize, const std::vector<Process::SigByte>& signature, bool& patternFound) const noexcept
{
	if (!pStart || !scanSize || !signature.size() || scanSize < signature.size())
	{
		patternFound = false;
		return nullptr;
	}

	for (const char* pCurrChar{ const_cast<const char*>(pStart) }; pCurrChar < (pStart + (scanSize - signature.size())); ++pCurrChar)
	{
		const char* pCharIt{ pCurrChar };
		bool found{ true };

		for (const Process::SigByte& currSigByte : signature)
		{
			switch (currSigByte.maskChar)
			{
			case 'x':
			{
				if (currSigByte.patternChar != *pCharIt++)
				{
					found = false;
				}
				continue;
			}
			case '?':
			{
				++pCharIt;
				continue;
			}
			default:
			{
				patternFound = false;
				return nullptr;
			}
			}
		}

		if (found)
		{
			patternFound = true;
			return const_cast<char*>(pCurrChar);
		}
	}

	patternFound = false;
	return nullptr;
}
