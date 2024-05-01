#include <iostream>

#include "driver_fuzzer.h"

#define LEVEL '\t'

inline void Usage() {
  std::cout << "Program for fuzzing config file\n"
    << "Valid parameters for execution:\n"
    << LEVEL << "0 - Exit program\n"
    << LEVEL << "1 - Autofuzzing IOCTL codes\n"
    << LEVEL << "2 - Autofuzzing IOCTL buffer\n"
    << LEVEL << "3 - Exploit driver vulnerability\n"
   ;
}

int main(int argc, const char** argv) {
  UNREFERENCED_PARAMETER(argc);
  UNREFERENCED_PARAMETER(argv);

  size_t choice = 0;

  MyProgram::DriverFuzzer fuzzer("\\\\.\\HackSysExtremeVulnerableDriver_mbks");

  while (true) {
    system("cls");
    Usage();

    std::cout << "Input command: ";
    std::cin >> choice;

    switch (choice) {
    case 0: { return 0; }
    case 1:
      fuzzer.AutoFuzzIOCTLs();
      break;
    case 2: {
      DWORD dwDeviceType = 0;
      DWORD dwFunction = 0;
      DWORD dwMethod = 0;
      DWORD dwAccess = 0;
      
      std::cout << "Input Device type value (hex): ";
      std::cin >> std::hex >> dwDeviceType;
      std::cout << "Input function value (hex): ";
      std::cin >> std::hex >> dwFunction;
      std::cout << "Input method value (hex): ";
      std::cin >> std::hex >> dwMethod;
      std::cout << "Input access value (hex): ";
      std::cin >> std::hex >> dwAccess;

      fuzzer.AutoFuzzIOCTLBuffer(dwDeviceType, dwFunction, dwMethod, dwAccess);
    }
    break;

    case 3:
      fuzzer.ExploitVulnerability();
      break;
    }

    system("pause");
  }
}