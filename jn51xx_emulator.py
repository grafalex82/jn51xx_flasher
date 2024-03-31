import serial
import struct
import argparse

from jn51xx_protocol import *

class Emulator:
    def __init__(self, port, verbose="none"):
        self.ser = serial.Serial(port, baudrate=38400, timeout=1)
        self.verbose = verbose                                 

        self.flash_data = [0xff] * (512 * 1024)  # 512KB of flash memory (JN5169)


    def sendResponse(self, msgtype, data):
        # Message header and data
        msglen = len(data) + 2
        msg = struct.pack("<BB", msglen, msgtype)
        msg += data
        msg += calcCRC(msg).to_bytes(1, 'big')

        if self.verbose != "none":
            dumpMessage(">", msglen, msgtype, msg[2:], self.verbose == "raw")

        self.ser.write(msg)


    def emulateGetChipId(self, data):
        chipID = CHIP_ID_JN5169
        bootloaderVer = 0x000b0002
        resp = struct.pack('>BII', 0, chipID, bootloaderVer)
        self.sendResponse(GET_CHIP_ID_RESPONSE, resp)


    def emulateRAMData(self, addr, len):
        if addr == MEMORY_CONFIG_ADDRESS:
            return struct.pack(">IIII", 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff)

        if addr == FACTORY_MAC_ADDRESS:
            return struct.pack("<BBBBBBBB", 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88)
        
        if addr == OVERRIDEN_MAC_ADDRESS:
            return struct.pack("<BBBBBBBB", 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
        
        if addr == CHIP_SETTINGS_ADDRESS:
            return struct.pack(">IIII", 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff)
        
        print(f"Warning: Attempt to read {len} bytes at unknown address 0x{addr:08x}")
        return bytes(len)


    def emulateRAMRead(self, req):
        addr, len = struct.unpack("<IH", req)
        resp = struct.pack('>B', 0)
        resp += self.emulateRAMData(addr, len)

        self.sendResponse(RAM_READ_RESPONSE, resp)


    def emulateSelectFlashType(self, req):
        flash, addr = struct.unpack("<BI", req)
    
        status = 0 if flash == 8 else 0xff  #Emulating only internal flash
        resp = struct.pack("<B", status)
        self.sendResponse(SELECT_FLASH_TYPE_RESPONSE, resp)


    def emulateFlashErase(self, req):
        self.flash_data = [0xff] * (512 * 1024)  # Fill with all 0xff's

        resp = struct.pack("<B", 0)
        self.sendResponse(FLASH_ERASE_RESPONSE, resp)


    def emulateReset(self, req):
        resp = struct.pack("<B", 0)
        self.sendResponse(RESET_RESPONSE, resp)


    def emulateChangeBaudRate(self, req):
        # Calculate the new baud rate
        divisor = req[0]
        baudrate = None
        match divisor:
            case 1: baudrate = 1000000
            case 2: baudrate = 500000
            case 9: baudrate = 115200
            case 26: baudrate = 38400

        # Send the response
        status = 0 if baudrate is not None else 0xff
        resp = struct.pack("<B", status)
        self.sendResponse(CHANGE_BAUD_RATE_RESPONSE, resp)

        # Change the baud rate if it is supported
        if baudrate:
            self.ser.baudrate = baudrate
        else:
            print("Warning: Changing the baud rate is not supported")


    def emulateRAMWrite(self, req):
        addr = struct.unpack("<I", req[0:4])
        data = req[4:]

        # TODO: store data in memory

        resp = struct.pack("<B", 0)
        self.sendResponse(RAM_WRITE_RESPONSE, resp)


    def emulateFlashWrite(self, req):
        addr = struct.unpack("<I", req[0:4])[0]
        data = req[4:]

        self.flash_data[addr : addr + len(data)] = data

        resp = struct.pack("<B", 0)
        self.sendResponse(FLASH_WRITE_RESPONSE, resp)


    def emulateFlashRead(self, req):
        addr, len = struct.unpack("<IH", req)
        data = bytes(self.flash_data[addr : addr + len])

        resp = struct.pack("<B", 0)
        resp += data
        self.sendResponse(FLASH_READ_RESPONSE, resp)


    def run(self):
        while True:
            # Wait for a message, read the message header
            data = self.ser.read(2)
            if not data:
                continue

            # Parse the message header, dump the message
            msglen, msgtype = struct.unpack('BB', data)
            data = self.ser.read(msglen - 1)
            dumpMessage("<", msglen, msgtype, data, self.verbose == "raw")

            # Process the message depending on the message type
            data = data[:-1]
            if msgtype == GET_CHIP_ID_REQUEST:
                self.emulateGetChipId(data)
            elif msgtype == RAM_READ_REQUEST:
                self.emulateRAMRead(data)
            elif msgtype == SELECT_FLASH_TYPE_REQUEST:
                self.emulateSelectFlashType(data)
            elif msgtype == CHANGE_BAUD_RATE_REQUEST:
                self.emulateChangeBaudRate(data)
            elif msgtype == FLASH_ERASE_REQUEST:
                self.emulateFlashErase(data)
            elif msgtype == RESET_REQUEST:
                self.emulateReset(data)
            elif msgtype == RAM_WRITE_REQUEST:
                self.emulateRAMWrite(data)
            elif msgtype == FLASH_WRITE_REQUEST:
                self.emulateFlashWrite(data)
            elif msgtype == FLASH_READ_REQUEST:
                self.emulateFlashRead(data)
            else:
                print(f"Unsupported message type: {msgtype:02x}")


def main():
    parser = argparse.ArgumentParser(description="Emulate NXP JN5169 device")
    parser.add_argument("port", help="Serial port")
    parser.add_argument("-v", "--verbose", nargs='?', choices=["none", "protocol", "raw"], help="Set verbosity level", default="none")
    args = parser.parse_args()
    
    print("Starting NXP JN5169 emulator on " + args.port)
    emulator = Emulator(args.port, args.verbose)
    emulator.run()


if __name__ == "__main__":
    main()