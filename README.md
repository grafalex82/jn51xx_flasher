# NXP JN51xx microcontroller family flashing tool

This repository has a simple cross-platform tool  to flash NXP JN51xx microcontrollers. Right now, it only works with JN5169. It might be updated to work with JN5179 and JN5189 microcontrollers in the future. The repository also includes tools to capture and analyze the flashing process. This helps in adding support for new microcontrollers.

# Flashing Tool

The flashing tool offers these advantages over the official NXP JN51xxProgrammer.exe tool:
- It is written in Python and works on all operating systems.
- It is simple and lightweight
- It can flash devices connected over a network, not just ones connected to the computer's COM port.
- The protocol and algorithm is well documented.

Usage:
```
usage: jn51xx_flasher.py [-h] [-p PORT] [-s SERVER] [-v [{none,protocol,raw}]] {read,write,verify} file

Flash NXP JN5169 device

positional arguments:
  {read,write,verify}   Action to perform: read, write, verify
  file                  Firmware file to flash

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Serial port
  -s SERVER, --server SERVER
                        Remote flashing server
  -v [{none,protocol,raw}], --verbose [{none,protocol,raw}]
                        Set verbosity level
```

The following features are not supported at the moment, but their support may be added in future:
- External flash support
- AES encoding
- Setting brown out voltage, bootloader code protection, JTAG settings

# Sniffing/Dumping Tool

To study and record the flashing process, a sniffer/dumper tool was created. This tool acts like a middleman between two COM ports. One port connects to the flashing tool and the other to the device.

Here's how they connect:
```
JN51xxProgrammer.exe <-> COM1 <-> COM2 <-> Sniffer/Dumper <-> COM3 <-> Device
```

COM1 and COM2 are fake COM ports bridged together (you can make these using the HHD Virtual Serial Port Tools on Windows). COM3 is the real COM port connected to the microcontroller you want to program. 

Though this setup might seem complex, it actually makes it easier to capture and understand the flashing protocol than using just a COM port sniffer or a logic analyzer. Using bridged COM ports approach allows making the sniffing tool as a COM-port client, rather than emulating the COM port itself.


Usage:
```
usage: jn51xx_sniffer.py [-h] [-v [{none,protocol,raw}]] srcport dstport

Proxy and dump JN5169 flashing messages

positional arguments:
  srcport               Source serial port (flasher side)
  dstport               Destination serial port (device side)

options:
  -h, --help            show this help message and exit
  -v [{none,protocol,raw}], --verbose [{none,protocol,raw}]
                        Set verbosity level
```

Remember, the device needs to be in bootloader mode for this tool to work.

# Emulator

In order to simplify flash tool development, a chip emulator was created. The emulator is a simple application that mimics the chip's bootloader, and provide the same responses as the real chip would make. The emulator  allows to exercise original flash tool in different modes without having to flash the real microcontroller, and therefore avoid risk of damaging the device with an incorrect message.

Usage:
```
usage: jn51xx_emulator.py [-h] [-v [{none,protocol,raw}]] port

Emulate NXP JN5169 device

positional arguments:
  port                  Serial port

options:
  -h, --help            show this help message and exit
  -v [{none,protocol,raw}], --verbose [{none,protocol,raw}]
                        Set verbosity level
```

The tool works as a COM port client. A pair of bridged COM ports are needed to let the flash tool communicate with the emulator:

```
JN51xxProgrammer.exe <-> COM1 <-> COM2 <-> Emulator
```

# Protocol description

The flashing protocol is partly explained in the NXP document titled ["JN51xx Boot Loader Operation" (JN-AN-1003)](https://www.nxp.com/docs/en/application-note/JN-AN-1003.pdf). However, not all messages are covered in this document. Some were figured out by looking at the data sniffed or by examining the source code of the JN51xxProgrammer.exe program.

The protocol works by sending and receiving messages. The flashing tool starts the conversation. Messages are binary packets and have this structure:
- 1 byte for the message's length (number of bytes the rest of the message, including the checksum)
- 1 byte for the type of message
- The message data, which varies in length depending on the type of message
- 1 byte for the checksum (XOR of all bytes preceding CRC, starting the message length byte)

The full list of messages supported by tools above can be found in [jn51xx_dumper.py](jn51xx_dumper.py) file.

Here's what happens when the JN51xxProgrammer.exe talks to a microcontroller:
- It asks for the Chip ID to know which chip it's dealing with.
- It looks at a special memory location (0x01001500) to read a specific memory setting (this isn't in the documentation).
- It tries out different external flash memory types to see which ones are connected.
- It reads an overridden MAC address from memory address 0x01001570.
- It reads the factory-set MAC address from memory address 0x01001580.
- It reads some data from 0x01001400 (this isn't in the documentation).
- It reads chip settings from memory address 0x01001510.

To flash firmware, the tool:
- Selects the internal flash.
- Erases the flash and checks that it's empty.
- Writes data in 128-byte parts. It writes from the end to the start to prevent the microcontroller from running an incomplete firmware.
- Resets the microcontroller.

To read firmware, the tool:
- Select the internal flash.
- Reads data from the flash in 128-byte parts.
- Resets the microcontroller.

Reading and writing EEPROM is done differently. The flash tool uploads a special program to the microcontroller's RAM. This program lets it read and write EEPROM.

Here are some examples of how the tool communicates with a microcontroller:
- [Flash firmware to the microcontroller](examples/flash_write.txt)
- [Read firmware from the microcontroller](examples/flash_read.txt)
- [Some devices may protect firmware from reading](examples/flash_read_forbidden.txt) by zeroing some bits in the configuration word at 0x01001510
- [Read EEPROM](examples/eeprom_read.txt)
- [Write EEPROM](examples/eeprom_write.txt)

# Support

This project is being developed for free as a pet project. However you may consider supporting the project with a small donate.

<a href="https://www.buymeacoffee.com/grafalex" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>
