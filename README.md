# Metanoia g.fast SFP modem (MT-5321) firmware loader

I got my hands on a Huawei g.fast SFP module model DU8000, typically provided by ISPs in Switzerland with their routers.
I wanted to use it on my own router. Unfortunately, the modem does not have a flash chip and requires the firmware
to be loaded manually. I extracted it from the Swisscom Internet Box Plus (``firmware_package.b`` file) and looked at
the communication protocol.

The firmware is loaded using the Ethernet Boot Management protocol [1]. Once plugged in, the SFP module responds to Ethernet
packets with type 0x6120. The format is not documented anywhere but can be recovered fairly easily from the ``libmetanoia.so``
library in the router's firmware.

I initially reverse-engineered the firmware upload part and got stuck there. It turned out that after the firmware is uploaded,
the modem needs to receive a sequence of commands to start working. I have got some inspiration from [3], a Golang implementation.
I took the missing commands from there.

## Tested hardware

- It works on Debian 12 using the TPLink MC220L media converter.
- It works on the EdgeRouter 4 as well. You will need to cross-compile for MIPS.

## Build

You will need a C++23 compiler. I tested with Clang 19 on Debian 12.

```bash
$ cmake -DCMAKE_CXX_COMPILER="clang++-19" .
$ make
```

For a MIPS build to run on EdgeRouter 4:

```bash
# First build the LLVM toolchain. We need the C++ library.
$ git clone https://github.com/llvm/llvm-project.git
$ cd llvm-project
$ git checkout llvmorg-19.1.7
$ CC=clang-19 CXX=clang++-19 cmake  -G Ninja -S llvm -B ../llvm-build  -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS=clang -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind"  -DLLVM_RUNTIME_TARGETS="mips-linux-gnu"
$ ninja -C ../llvm-build/ runtimes

# Use the toolchain to build to firmware loader.
$ cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="-mcpu=mips32 -static --target=mips-linux-gnu" -DCMAKE_CXX_COMPILER=/path/to/llvm-build/bin/clang++ .
$ make
```

## Notes

- The MT5321 module can be reset using the TX_Disable pin of the SFP module. I have no idea how to access that pin from
  stock Linux using any of the hardware I have. I wonder if this requires a special board, like the one ISPs have in their routers.
  It could be useful to reset the module if it gets stock.
- The firmware loader will enter a loop to print log data sent by the module. Closing it does not appear to impact
  operations. Normal network traffic will still pass fine.


Here is a sample output of ``ethtool -m`` after the SFP module is plugged in but before attempting to load the firmware:

```console
Identifier                                : 0x03 (SFP)
Extended identifier                       : 0x04 (GBIC/SFP defined by 2-wire interface ID)
Connector                                 : 0x22 (RJ45)
Transceiver codes                         : 0x00 0x00 0x00 0x08 0x00 0x00 0x00 0x00 0x00
Transceiver type                          : Ethernet: 1000BASE-T
Encoding                                  : 0x01 (8B/10B)
BR, Nominal                               : 0MBd
Rate identifier                           : 0x00 (unspecified)
Length (SMF,km)                           : 0km
Length (SMF)                              : 0m
Length (50um)                             : 0m
Length (62.5um)                           : 0m
Length (Copper)                           : 0m
Length (OM3)                              : 0m
Laser wavelength                          : 0nm
Vendor name                               : METANOIA
Vendor OUI                                : 00:00:00
Vendor PN                                 : MT5321
Vendor rev                                : 0001
Option values                             : 0x08 0x00
Option                                    : Retimer or CDR implemented
BR margin, max                            : 0%
BR margin, min                            : 0%
Vendor SN                                 :
Date code                                 : ________
```

## Related work

[1] VDSL2 And G.Fast SFP For Any-PHY Platform [US20160241293A1](https://patents.google.com/patent/US20160241293A1/en).

[2] Utilities for working with Metanoia/Proscend [VDSL2 SFP Modems](https://github.com/jimdigriz/mt5311/).
    The EBM protocol for that modem is different from the MT5321.

[3] Golang implementation of the boot and management protocol for the MT5321 [work](https://github.com/lorenz/metanoia-ebm).

[4] Firmware for Swisscom [routers](https://github.com/TheRaphael0000/SwisscomFirmwares). They took them offline unfortunately.




