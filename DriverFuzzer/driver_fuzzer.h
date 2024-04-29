#ifndef _DRIVER_FUZZER_H
#define _DRIVER_FUZZER_H

#include <iostream>
#include <string>

#include <windows.h>

namespace MyProgram {
class DriverFuzzer {

 public:
  DriverFuzzer(std::string sDriverName);

  BOOL AutoFuzzing();

  ~DriverFuzzer() = default;

 private:
  enum class LOG_STATUS { LOG_INFO, LOG_ERR };

  void _LogErrorCode(std::string sErrorMsg, DWORD dwErrorCode);
  void _Log(std::string sMsg, LOG_STATUS dwStatus = LOG_STATUS::LOG_INFO);
  const std::string _GetCTLCODEMessage(
    DWORD dwFunction,
    DWORD dwMethod,
    DWORD dwAccess
  );

  std::string m_sDriverName;

};
} // namespace MyProgram

#endif // _DRIVER_FUZZER_H