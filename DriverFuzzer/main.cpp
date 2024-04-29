#include <iostream>

#include "driver_fuzzer.h"

int main(int arhc, const char** argv) {

  MyProgram::DriverFuzzer fuzzer("\\\\.\\HackSysExtremeVulnerableDriver_mbks");
  
  std::cout << fuzzer.AutoFuzzing() << '\n';

}