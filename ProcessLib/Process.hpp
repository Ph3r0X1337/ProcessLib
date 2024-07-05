#pragma once

#include "IProcess.hpp"
#include "ExtProcess.hpp"
#include "LocalProcess.hpp"

#ifdef NDEBUG
#ifdef _WIN64
#pragma comment(lib, "ProcessLib/ProcessR64.lib")
#else
#pragma comment(lib, "ProcessLib/ProcessR86.lib")
#endif
#else
#ifdef _WIN64
#pragma comment(lib, "ProcessLib/ProcessD64.lib")
#else
#pragma comment(lib, "ProcessLib/ProcessD86.lib")
#endif
#endif

#ifndef UNICODE
#define MExtProcess ExtProcessA
#define MLocalProcess LocalProcessA
#else
#define MExtProcess ExtProcessW
#define MLocalProcess LocalProcessW
#endif