import serial
import struct
import argparse
import socket

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
        check(msgtype + 1 == resptype, "Incorrect response type")   # Looks like request and response type numbers are next to each other

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


    def readRAM(self, addr, len):
        """ Read data from RAM at the given address """

        req = struct.pack("<IH", addr, len)
        resp = self.sendRequest(RAM_READ_REQUEST, req)
        check(resp[0] == 0, "Wrong status on read RAM request")
        return [x for x in resp[1:1+len]]


    def writeRAM(self, addr, data):
        """ Write data to RAM at the given address """

        req = struct.pack("<I", addr)
        req += data
        resp = self.sendRequest(RAM_WRITE_REQUEST, req)
        check(resp[0] == 0, "Wrong status on read RAM request")


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
        """ Reset the target micocontroller """

        print("Reset target device")
        resp = self.sendRequest(RESET_REQUEST, b'')
        status = struct.unpack("<B", resp)
        check(status[0] == 0, "Wrong status on reset device")


    def writeFlash(self, addr, chunk):
        """ Write flash data at the given address """

        print(f"Writing flash at addr {addr:08x}")
        req = struct.pack("<I", addr)
        req += chunk
        resp = self.sendRequest(FLASH_WRITE_REQUEST, req)
        check(resp[0] == 0, "Wrong status on write flash command")


    def readFlash(self, addr, len):
        """ Read flash data at the given address """

        print(f"Reading flash at addr {addr:08x}")
        req = struct.pack("<IH", addr, len)
        resp = self.sendRequest(FLASH_READ_REQUEST, req)
        check(resp[0] == 0, "Wrong status on read flash request")
        return resp[1:1+len]


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
            f.write(b'\x0f\x03\x00\x0b')
            f.write(content)


    def writeFirmware(self, filename):
        """" Write the firmware to the device """

        firmware = self.loadFirmwareFile(filename)

        # Prepare flash
        self.selectFlashType()
        self.eraseFlash()

        # Flash data
        for addr in range(0, len(firmware), 0x80):
            chunklen = len(firmware) - addr
            if chunklen > 0x80:
                chunklen = 0x80

            self.writeFlash(addr, firmware[addr:addr+chunklen])

        # Finalize and reset the device into the firmware
        self.reset()


    def verifyFirmware(self, filename):
        """ Verify the firmware on the device against the given file """

        firmware = self.loadFirmwareFile(filename)

        # Prepare the flash
        self.selectFlashType()

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

        # Finalize and reset the device into the firmware
        self.reset()


    def readFirmware(self, filename):
        """ Read the firmware from the device """

        self.getSettings()

        # Prepare flash
        self.setFlashType()

        # Flash data
        firmware = b''
        for addr in range(0, 512*1024, 0x80):
            firmware += self.readFlash(addr, 0x80)

        # Finalize and reset the device into the firmware
        self.reset()

        # Save downloaded firmware content
        self.saveFirmwareFile(filename, firmware)


    def run(self, action, filename):
        """ Perform the requested action on the device """

        # Prepare the target device
        self.getChipId()
        mac = self.getMAC()
        print("Effective device MAC address: " + ':'.join(f'{x:02x}' for x in mac))

        match action:
            case "write": self.writeFirmware(filename)
            case "read": self.readFirmware(filename)
            case "verify": self.verifyFirmware(filename)


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Flash NXP JN5169 device")
    parser.add_argument("-p", "--port", help="Serial port")
    parser.add_argument("-s", "--server", help="Remote flashing server")
    parser.add_argument("-v", "--verbose", nargs='?', choices=["none", "protocol", "raw"], help="Set verbosity level", default="none")
    parser.add_argument("action", choices=["read", "write", "verify"], help="Action to perform: read, write, verify")
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
        ser = serial.Serial(args.port, baudrate=38400, timeout=1)
    if args.server:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((args.server, 5169))
        ser = Uart2SocketWrapper(sock)

    # Create the flasher object
    flasher = Flasher(ser, args.verbose)
    flasher.run(args.action, args.file)


if __name__ == "__main__":
    main()