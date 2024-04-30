#ifndef _DRIVER_FUZZER_H
#define _DRIVER_FUZZER_H

#include <iostream>
#include <string>
#include <unordered_set>

#include <windows.h>

namespace MyProgram {
class DriverFuzzer {

 public:
  DriverFuzzer(std::string sDriverName);
  ~DriverFuzzer();

  BOOL IsOpen() const;

  BOOL AutoFuzzIOCTLs();
  BOOL AutoFuzzIOCTLBuffer(
    DWORD dwDeviceType,
    DWORD dwFunction,
    DWORD dwMethod,
    DWORD dwAccess
  );

 private:
  enum class LOG_STATUS { LOG_INFO, LOG_ERR };

  VOID _CheckIOCTL(
    DWORD dwDeviceType,
    DWORD dwFunction,
    DWORD dwMethod,
    DWORD dwAccess,
    LPVOID lpInputBuffer,
    DWORD dwInputBufferSize,
    LPVOID lpOutputBuffer,
    DWORD dwOutputBufferSize,
    const std::unordered_set<DWORD>& usSkippableErrors
  );

  VOID _LogErrorCode(std::string sErrorMsg, DWORD dwErrorCode) const ;
  VOID _Log(std::string sMsg, LOG_STATUS dwStatus = LOG_STATUS::LOG_INFO) const;
  const std::string _GetCTLCODEMessage(
    DWORD dwDeviceType,
    DWORD dwFunction,
    DWORD dwMethod,
    DWORD dwAccess
  ) const;

  HANDLE m_hDriver;
};
} // namespace MyProgram

#endif // _DRIVER_FUZZER_H