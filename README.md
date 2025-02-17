This is a firmware loader for the Metanoia g.fast SFP modem (MT5321).

I got my hands on a Huawei g.fast SFP module model DU8000, typically provided by ISPs in Switzerland with their routers.
I wanted to use it on my own router. Unfortunately, the modem does not have a flash chip and requires the firmware
to be loaded manually. I extracted it from the Swisscom Internet Box Plus (``firmware.b`` file) and looked at
the communication protocol.

The firmware is loaded using the Ethernet Boot Management protocol [1]. Once plugged in, the SFP module responds to Ethernet
packets with type 0x6120. The format is not documented anywhere but can be recovered fairly easily from the ``libmetanoia.so``
library in the router's firmware.

I have got some inspiration from [3], a Golang implementation.

Notes

- This is work in progress. The initial prototype works on Debian 12 using the TPLink MC220L media converter.
- The MT5321 module can be reset using the TX_Disable pin of the SFP module. I have no idea how to access that pin from
  stock Linux using any of the hardware I have. I wonder if this requires a special board, like the one ISPs have in their routers.


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

Related work

[1] VDSL2 And G.Fast SFP For Any-PHY Platform [US20160241293A1](https://patents.google.com/patent/US20160241293A1/en).

[2] Utilities for working with Metanoia/Proscend [VDSL2 SFP Modems](https://github.com/jimdigriz/mt5311/).
    The EBM protocol for that modem is different from the MT5321.

[3] Golang implementation of the boot and management protocol for the MT5321 [work](https://github.com/lorenz/metanoia-ebm).

[4] Firmware for Swisscom [routers](https://github.com/TheRaphael0000/SwisscomFirmwares). They took them offline unfortunately.
