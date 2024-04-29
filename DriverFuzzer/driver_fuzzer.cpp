#include "driver_fuzzer.h"

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>

#include <windows.h>

MyProgram::DriverFuzzer::
DriverFuzzer(std::string sDriverName) : m_sDriverName(sDriverName) {}

BOOL
MyProgram::DriverFuzzer::
AutoFuzzing() {
  HANDLE hDriver = INVALID_HANDLE_VALUE;
  DWORD cbRet;
  DWORD dwBuffer = 0;
  BOOL bRes = FALSE;
  DWORD dwFunctionMax = 1 << 13; // Function ID takes 12 bits in CTL_CODE
  const std::vector<DWORD> methods = {
    METHOD_BUFFERED, METHOD_IN_DIRECT, METHOD_OUT_DIRECT, METHOD_NEITHER
  };

  const std::vector<DWORD> accesses = {
    FILE_ANY_ACCESS, FILE_READ_ACCESS, FILE_WRITE_ACCESS
  };

  hDriver = CreateFileA(
    m_sDriverName.data(),
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_SYSTEM,
    NULL
  );

  if (hDriver == INVALID_HANDLE_VALUE) {
    _LogErrorCode("CreateFileA failed", GetLastError());
    return FALSE;
  }

  for (DWORD dwFunction = 0; dwFunction < dwFunctionMax; ++dwFunction) {
    std::cout << "Hop";
    for (const auto& dwMethod : methods) {
      for (const auto& dwAccess : accesses) {
        for (DWORD64 i = 0; i <= 0xffffffff; ++i) {
          dwBuffer = i;

          bRes = DeviceIoControl(
            hDriver,
            CTL_CODE(FILE_DEVICE_UNKNOWN, dwFunction, dwMethod, dwAccess),
            &dwBuffer, sizeof(dwBuffer), NULL, 0, &cbRet, NULL
          );
          if (!bRes) {
            if (GetLastError() != ERROR_INVALID_FUNCTION) {
              std::string sErrMsg = "Sending ";
              sErrMsg += _GetCTLCODEMessage(dwFunction, dwMethod, dwAccess);
              sErrMsg += " failed";
              _LogErrorCode(sErrMsg, GetLastError());
            }
          } else {
            std::string sMsg = "Sending ";
            sMsg += _GetCTLCODEMessage(dwFunction, dwMethod, dwAccess);
            sMsg += " succeeded";
            _Log(sMsg);
          }
        }
      }
    }
  }


  CloseHandle(hDriver);

  return TRUE;
}

void
MyProgram::DriverFuzzer::
_LogErrorCode(std::string sErrorMsg, DWORD dwErrorCode) {
  std::stringstream ssMsg;

  ssMsg.fill('0');

  ssMsg << sErrorMsg
    << " ERROR_CODE: 0x" << std::setw(8) << std::hex << dwErrorCode;

  _Log(ssMsg.str(), LOG_STATUS::LOG_ERR);
}

void
MyProgram::DriverFuzzer::
_Log(std::string sMsg, LOG_STATUS dwStatus) {
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
_GetCTLCODEMessage(DWORD dwFunction, DWORD dwMethod, DWORD dwAccess) {
  std::stringstream sStr;

  sStr.fill('0');

  sStr << "CTL_CODE(0x22, 0x" << std::hex
    << std::setw(4) << dwFunction << ", 0x"
    << std::setw(2) << dwMethod << ", 0x" 
    << std::setw(2) << dwAccess << ")";

  return sStr.str();
}
