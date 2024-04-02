import serial
import struct
import argparse
import socket
import time
import sys
import os

from jn51xx_protocol import *

class Uart2SocketWrapper:
    def __init__(self, sock):
        self.sock = sock

    def write(self, data):
        self.sock.sendall(data)

    def read(self, len):
        return self.sock.recv(len)


def check(cond, errmsg):
    if not cond:
        raise RuntimeError(errmsg)


class Flasher:
    """ Class to handle communication with JN5169 device """

    def __init__(self, ser, verbose="none"):
        self.ser = ser
        self.verbose = verbose


    def sendRequest(self, msgtype, data):
        """ Send a request to the device and return the response"""

        # Prepare the message
        msglen = len(data) + 2
        msg = struct.pack("<BB", msglen, msgtype)
        msg += data
        msg += calcCRC(msg).to_bytes(1, 'big')
        
        # Dump the request to send
        if self.verbose != "none":
            dumpMessage(">", msglen, msgtype, msg[2:], self.verbose == "raw")

        # Send the request
        self.ser.write(msg)

        # Wait for response
        data = self.ser.read(2)
        check(data, "No response from device")

        # Parse the response header, and wait for the rest of data
        resplen, resptype = struct.unpack('BB', data)
        data = self.ser.read(resplen - 1)
        check(data, "Incorrect response from device")
        check(msgtype + 1 == resptype, f"Incorrect response type ({msgtype:02x} != {resptype:02x})")   # Looks like request and response type numbers are next to each other

        # Dump the response
        if self.verbose != "none":
            dumpMessage("<", resplen, resptype, data, self.verbose == "raw")
            
        # Return the response payload
        return data[:-1]


    def getChipId(self):
        """ Get the chip ID of the device, verify it is JN5169 """

        resp = self.sendRequest(GET_CHIP_ID_REQUEST, b'')

        # Parse response
        bootloaderVer = None
        if len(resp) == 5:
            status, chipId = struct.unpack('>BI', resp)
        else:
            status, chipId, bootloaderVer = struct.unpack('>BII', resp)

        print(f"Chip ID: {chipId:08x}, Bootloader={bootloaderVer:08x} (Status={status:02x})")

        # Chip ID structure
        #define CHIP_ID_MANUFACTURER_ID_MASK    0x00000fff
        #define CHIP_ID_PART_MASK               0x003ff000
        #define CHIP_ID_MASK_VERSION_MASK       0x0fc00000
        #define CHIP_ID_REV_MASK                0xf0000000

        check(status == 0, "Wrong status on get Chip ID request")
        check(chipId & 0x003fffff == 0x0000b686, "Unsupported chip ID")   # Support only JN5169 for now
        return chipId


    def selectFlashType(self, flashType = 8):
        """ Select the flash type to use. By default select internal flash (8) """

        print("Selecting internal flash")
        req = struct.pack("<BI", flashType, 0x00000000)

        resp = self.sendRequest(SELECT_FLASH_TYPE_REQUEST, req)
        status = struct.unpack("<B", resp)
        check(status[0] == 0, "Wrong status on select internal flash request")


    def readMemory(self, addr, len, requestType):
        """ Read memory data at the given address """

        # print(f"Reading Memory at addr {addr:08x}")
        req = struct.pack("<IH", addr, len)
        resp = self.sendRequest(requestType, req)
        check(resp[0] == 0, "Wrong status on read flash request")
        return resp[1:1+len]


    def writeMemory(self, addr, chunk, requestType):
        """ Write memory data at the given address """

        # print(f"Writing Memory at addr {addr:08x}")
        req = struct.pack("<I", addr)
        req += chunk
        resp = self.sendRequest(requestType, req)
        check(resp[0] == 0, "Wrong status on write memory command")


    def readFlash(self, addr, len):
        """ Read flash data at the given address """
        return self.readMemory(addr, len, FLASH_READ_REQUEST)


    def writeFlash(self, addr, chunk):
        """ Write flash data at the given address """
        return self.writeMemory(addr, chunk, FLASH_WRITE_REQUEST)


    def readRAM(self, addr, len):
        """ Read data from RAM at the given address """
        return self.readMemory(addr, len, RAM_READ_REQUEST)


    def writeRAM(self, addr, data):
        """ Write data to RAM at the given address """
        return self.writeMemory(addr, data, RAM_WRITE_REQUEST)


    def readEEPROM(self, addr, len):
        """ Read data from EEPROM at the given address """
        return self.readMemory(addr, len, EEPROM_READ_REQUEST)
    

    def writeEEPROM(self, addr, data):
        """ Write data to EEPROM at the given address """
        return self.writeMemory(addr, data, EEPROM_WRITE_REQUEST)
    

    def getChipSettings(self):
        """ Get the chip settings bytes """

        settings = self.readRAM(CHIP_SETTINGS_ADDRESS, 16)
        print("Device settings: " + ':'.join(f'{x:02x}' for x in settings))
        return settings


    def getUserMAC(self):
        """ Get the user MAC address of the device """

        mac = self.readRAM(OVERRIDEN_MAC_ADDRESS, 8)
        print("Device User MAC address: " + ':'.join(f'{x:02x}' for x in mac))
        return mac


    def getFactoryMAC(self):
        """ Get the factory MAC address of the device """
        
        mac = self.readRAM(FACTORY_MAC_ADDRESS, 8)
        print("Device Factory MAC address: " + ':'.join(f'{x:02x}' for x in mac))
        return mac


    def getMAC(self):
        mac = self.getUserMAC()
        if mac == [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]:
            mac = self.getFactoryMAC()
        return mac


    def eraseFlash(self):
        """ Erase the microcontroller flash memory """

        print("Erasing internal flash")
        resp = self.sendRequest(FLASH_ERASE_REQUEST, b'')
        status = struct.unpack("<B", resp)
        check(status[0] == 0, "Wrong status on erase internal flash")


    def reset(self):
        """ Reset the target microcontroller """

        print("Reset target device")
        resp = self.sendRequest(RESET_REQUEST, b'')
        status = struct.unpack("<B", resp)
        check(status[0] == 0, "Wrong status on reset device")


    def changeBaudRate(self, baudrate):
        """ Change the baud rate of the device """

        # Calculate the divisor number
        divisor = None
        match baudrate:
            case 1000000: divisor = 1
            case 500000: divisor = 2
            case 115200: divisor = 9
            case 38400: divisor = 26
        check(divisor, f"Unsupported baud rate {baudrate}")

        # Send the baud rate change request, verify the device supports the new baud rate
        print(f"Changing baud rate to {baudrate}")
        req = struct.pack("<I", divisor)
        resp = self.sendRequest(CHANGE_BAUD_RATE_REQUEST, req)
        status = struct.unpack("<B", resp)
        check(status[0] == 0, "Wrong status on change baud rate request")
              
        # Switch the baud rate
        self.ser.baudrate = baudrate

    
    def execute(self, addr):
        """ Execute the code at the given address """

        print(f"Executing code at address {addr:08x}")
        req = struct.pack("<I", addr)
        resp = self.sendRequest(RUN_REQUEST, req)
        status = struct.unpack("<B", resp)
        check(status[0] == 0, "Wrong status on execute code request")


    def loadFirmwareFile(self, filename):
        """ Load the firmware file """

        # Load the file data
        with open(filename, "rb") as f:
            firmware = f.read()
        
        # Strip the file type marker
        check(firmware[0:4] == b'\x0f\x03\x00\x0b', "Incorrect firmware format")
        firmware = firmware[4:]

        return firmware


    def saveFirmwareFile(self, filename, content):
        """ Save the data to the file """

        # Load a file to flash
        with open(filename, "w+b") as f:
            # f.write(b'\x0f\x03\x00\x0b')
            f.write(content)


    def writeFirmware(self, filename):
        """" Write the firmware to the device """

        firmware = self.loadFirmwareFile(filename)

        # Prepare flash
        self.selectFlashType()
        self.eraseFlash()

        # Try to change the baud rate to speed up the flashing process
        self.changeBaudRate(1000000)

        # Calculate the starting address of the last chunk
        firmware_size = len(firmware)
        start_addr = firmware_size - (firmware_size % 0x80 if firmware_size % 0x80 != 0 else 0x80)
        chunklen = firmware_size - start_addr

        # Flash data in reverse order
        for addr in range(start_addr, -1, -0x80):
            self.writeFlash(addr, firmware[addr : addr + chunklen])
            chunklen = 0x80


    def verifyFirmware(self, filename):
        """ Verify the firmware on the device against the given file """

        firmware = self.loadFirmwareFile(filename)

        # Prepare the flash
        self.selectFlashType()

        # Try to change the baud rate to speed up the flashing process
        self.changeBaudRate(1000000)

        # Verify flash data
        errors = False
        for addr in range(0, len(firmware), 0x80):
            chunklen = len(firmware) - addr
            if chunklen > 0x80:
                chunklen = 0x80

            chunk = self.readFlash(addr, chunklen)

            if chunk != firmware[addr:addr+chunklen]:
                print(f"Firmware verification failed: data different at addr {addr:08x}")
                errors = True

        print("Firmware verification " + ("failed" if errors else "successful"))


    def readFirmware(self, filename):
        """ Read the firmware from the device """

        self.getChipSettings()

        # Prepare flash
        self.selectFlashType()

        # Try to change the baud rate to speed up the flashing process
        self.changeBaudRate(1000000)

        # Flash data
        firmware = b''
        for addr in range(0, 512*1024, 0x80):
            firmware += self.readFlash(addr, 0x80)

        # Save downloaded firmware content
        self.saveFirmwareFile(filename, firmware)


    def writeRAMData(self, addr, data):
        """ Write a big piece of data to RAM at the given address """

        # Write data in 128-bytes chunks
        for offset in range(0, len(data), 128):
            self.writeRAM(addr + offset, data[offset : offset + 128])


    def loadExtension(self, filename):
        """ Load and execute the bootloader extension file """

        # Load the file data
        with open(filename, "rb") as f:
            ext = f.read()

        # Parse the extension firmware header
        check((ext[0:4] == b'\x0f\x03\x00\x0b') or (ext[0:4] == b'\x0f\x03\x00\x09'), "Incorrect extension firmware format")
        text_start = 0x04000000 + struct.unpack(">H", ext[0x2c : 0x2c + 2])[0] * 4
        text_len = struct.unpack(">H", ext[0x2e : 0x2e + 2])[0] * 4
        bss_start = 0x04000000 + struct.unpack(">H", ext[0x30 : 0x30 + 2])[0] * 4
        bss_len = struct.unpack(">H", ext[0x32 : 0x32 + 2])[0] * 4
        entry_point = struct.unpack(">I", ext[0x38 : 0x38 + 4])[0]

        # Upload the extension firmware
        self.writeRAMData(text_start, ext[0x3c : 0x3c + text_len])

        # Clean the BSS section
        self.writeRAMData(bss_start, b'\x00' * bss_len)

        # Execute the extension
        self.execute(entry_point)


    def readEEPROMMemory(self, filename):
        """ Read the EEPROM memory from the device """

        # Upload the extension firmware
        extension = os.path.join(os.path.dirname(__file__), "extension/FlashProgrammerExtension_JN5169.bin")
        self.loadExtension(extension)

        # Read EEPROM data
        eeprom = b''
        for addr in range(0, 16 * 1024 - 64, 0x40):
            eeprom += self.readEEPROM(addr, 0x40)

        # Save downloaded EEPROM content
        self.saveFirmwareFile(filename, eeprom)

        # Switch back to the bootloader
        self.execute(0x00000066)
        time.sleep(1)   # Let the bootloader to start


    def writeEEPROMMemory(self, filename):
        """ Write the EEPROM memory to the device """

        # Upload the extension firmware
        extension = os.path.join(os.path.dirname(__file__), "extension/FlashProgrammerExtension_JN5169.bin")
        self.loadExtension(extension)

        # Load the EEPROM data
        with open(filename, "rb") as f:
            eeprom = f.read()

        # Write EEPROM data
        for addr in range(0, 16 * 1024 - 64, 0x40):
            self.writeEEPROM(addr, eeprom[addr : addr + 0x40])

        # Switch back to the bootloader
        self.execute(0x00000066)
        time.sleep(1)   # Let the bootloader to start


    def run(self, action, filename):
        """ Perform the requested action on the device """

        # Prepare the target device
        self.getChipId()
        mac = self.getMAC()
        print("Effective device MAC address: " + ':'.join(f'{x:02x}' for x in mac))

        # Perform the requested action
        match action:
            case "write": self.writeFirmware(filename)
            case "read": self.readFirmware(filename)
            case "verify": self.verifyFirmware(filename)
            case "eeprom_read": self.readEEPROMMemory(filename)
            case "eeprom_write": self.writeEEPROMMemory(filename)

        # Finalize and reset the device into the firmware
        self.reset()


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Flash NXP JN5169 device")
    parser.add_argument("-p", "--port", help="Serial port")
    parser.add_argument("-s", "--server", help="Remote flashing server")
    parser.add_argument("-v", "--verbose", nargs='?', choices=["none", "protocol", "raw"], help="Set verbosity level", default="none")
    parser.add_argument("action", choices=["read", "write", "verify", "eeprom_read", "eeprom_write"], 
                        help="Action to perform: read, write, verify, eeprom_read, eeprom_write")
    parser.add_argument("file", help="Firmware file to flash")
    args = parser.parse_args()

    # Validate parameters
    if not args.port and not args.server:
        print("Please specify either serial port or remote flashing server")
        sys.exit(1)

    if args.port and args.server:
        print("You can use either serial port or remote flashing server")
        sys.exit(1)

    # Open connection
    if args.port:
        ser = serial.Serial(args.port, baudrate=38400, timeout=2)
        ser.flush()
        ser.flushInput()
        time.sleep(1)   # Let the device to boot
    if args.server:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((args.server, 5169))
        ser = Uart2SocketWrapper(sock)

    # Create the flasher object
    flasher = Flasher(ser, args.verbose)
    flasher.run(args.action, args.file)


if __name__ == "__main__":
    main()