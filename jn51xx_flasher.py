import serial
import struct
import argparse
import socket


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


def trace(msg):
    enabled = False
    if enabled:
        print(msg)


def calcCRC(data):
    res = 0
    for b in data:
        res ^= b
    
    return res

def sendRequest(ser, msgtype, data):
    # Prepare the message
    msg = struct.pack("<BB", len(data) + 2, msgtype)
    msg += data
    msg += calcCRC(msg  ).to_bytes(1, 'big')
    
    # Send the message
    trace("Sending: " + ' '.join('{:02x}'.format(x) for x in msg))
    ser.write(msg)

    # Wait for response
    data = ser.read(2)
    check(data, "No response from device")

    resplen, resptype = struct.unpack('BB', data)
    trace("Response type={:02x} length={}".format(resptype, resplen))
    data = ser.read(resplen - 1)
    check(data, "Incorrect response from device")

    trace("Received: " + "{:02x} {:02x} ".format(resplen, resptype) + ' '.join('{:02x}'.format(x) for x in data))
    check(msgtype + 1 == resptype, "Incorrect response type")   # Looks like request and response type numbers are next to each other

    return data[:-1]


def getChipId(ser):
    print("Requesting Chip ID")
    resp = sendRequest(ser, 0x32, b'')

    bootloaderVer = None
    if len(resp) == 5:
        status, chipId = struct.unpack('>BI', resp)
    else:
        status, chipId, bootloaderVer = struct.unpack('>BII', resp)

    print("Received chip ID {:08x}, Bootloader={:08x} (Status={:02x})".format(chipId, bootloaderVer, status))

    # Chip ID structure
    #define CHIP_ID_MANUFACTURER_ID_MASK    0x00000fff
    #define CHIP_ID_PART_MASK               0x003ff000
    #define CHIP_ID_MASK_VERSION_MASK       0x0fc00000
    #define CHIP_ID_REV_MASK                0xf0000000

    check(status == 0, "Wrong status on get Chip ID request")
    check(chipId & 0x003fffff == 0x0000b686, "Unsupported chip ID")   # Support only JN5169 for now
    return chipId


def setFlashType(ser):
    print("Selecting internal flash")
    req = struct.pack("<BI", 8, 0x00000000) # Select internal flash (8) at addr 0x00000000
    resp = sendRequest(ser, 0x2c, req)
    status = struct.unpack("<B", resp)
    check(status[0] == 0, "Wrong status on select internal flash")


def readRAM(ser, addr, len):
    req = struct.pack("<IH", addr, len)
    resp = sendRequest(ser, 0x1f, req)
    check(resp[0] == 0, "Wrong status on read RAM request")
    return [x for x in resp[1:1+len]]


def writeRAM(ser, addr, data):
    req = struct.pack("<I", addr)
    req += data
    resp = sendRequest(ser, 0x1d, req)
    check(resp[0] == 0, "Wrong status on read RAM request")


def getSettings(ser):
    print("Requesting device customer settings")
    settings = readRAM(ser, 0x01001510, 16)
    print("Device settings: " + ':'.join('{:02x}'.format(x) for x in settings))
    return settings


def resetSettings(ser):
    print("Resetting device customer settings")
    writeRAM(ser, 0x01001510, b'\xff')


def getUserMAC(ser):
    print("Requesting device User MAC address")
    mac = readRAM(ser, 0x01001570, 8)
    print("Device User MAC address: " + ':'.join('{:02x}'.format(x) for x in mac))
    return mac


def getFactoryMAC(ser):
    print("Requesting device Factory MAC address")
    mac = readRAM(ser, 0x01001580, 8)
    print("Device Factory MAC address: " + ':'.join('{:02x}'.format(x) for x in mac))
    return mac


def getMAC(ser):
    mac = getUserMAC(ser)
    if mac == [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]:
        mac = getFactoryMAC(ser)
    return mac


def eraseFlash(ser):
    print("Erasing internal flash")
    resp = sendRequest(ser, 0x07, b'')
    status = struct.unpack("<B", resp)
    check(status[0] == 0, "Wrong status on erase internal flash")


def reset(ser):
    print("Reset target device")
    resp = sendRequest(ser, 0x14, b'')
    status = struct.unpack("<B", resp)
    check(status[0] == 0, "Wrong status on reset device")


def writeFlash(ser, addr, chunk):
    print("Writing flash at addr {:08x}".format(addr))
    req = struct.pack("<I", addr)
    req += chunk
    resp = sendRequest(ser, 0x09, req)

    check(resp[0] == 0, "Wrong status on write flash command")


def readFlash(ser, addr, len):
    print("Reading flash at addr {:08x}".format(addr))
    req = struct.pack("<IH", addr, len)
    resp = sendRequest(ser, 0x0b, req)
    check(resp[0] == 0, "Wrong status on read flash request")
    return resp[1:1+len]


def loadFirmwareFile(filename):
    # Load a file to flash
    with open(filename, "rb") as f:
        firmware = f.read()
    check(firmware[0:4] == b'\x0f\x03\x00\x0b', "Incorrect firmware format")
    firmware = firmware[4:]
    return firmware


def saveFirmwareFile(filename, content):
    # Load a file to flash
    with open(filename, "w+b") as f:
        #f.write(b'\x0f\x03\x00\x0b')
        f.write(content)


def writeFirmware(ser, filename):
    firmware = loadFirmwareFile(filename)

    # Prepare flash
    setFlashType(ser)
    eraseFlash(ser)
    #resetSettings(ser)

    # Flash data
    for addr in range(0, len(firmware), 0x80):
        chunklen = len(firmware) - addr
        if chunklen > 0x80:
            chunklen = 0x80

        writeFlash(ser, addr, firmware[addr:addr+chunklen])

    # Finalize and reset the device into the firmware
    reset(ser)


def verifyFirmware(ser, filename):
    firmware = loadFirmwareFile(filename)

    # Prepare the flash
    setFlashType(ser)

    # Verify flash data
    errors = False
    for addr in range(0, len(firmware), 0x80):
        chunklen = len(firmware) - addr
        if chunklen > 0x80:
            chunklen = 0x80

        chunk = readFlash(ser, addr, chunklen)

        if chunk != firmware[addr:addr+chunklen]:
            print("Firmware verification failed: data different at addr {:08x}".format(addr))
            errors = True

    print("Firmware verification " + ("failed" if errors else "successful"))

    # Finalize and reset the device into the firmware
    reset(ser)


def readFirmware(ser, filename):

    getSettings(ser)

    # Prepare flash
    setFlashType(ser)

    # Flash data
    firmware = b''
    for addr in range(0, 512*1024, 0x80):
        firmware += readFlash(ser, addr, 0x80)

    # Finalize and reset the device into the firmware
    reset(ser)

    # Save downloaded firmware content
    saveFirmwareFile(filename, firmware)


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Flash NXP JN5169 device")
    parser.add_argument("-p", "--port", help="Serial port")
    parser.add_argument("-s", "--server", help="Remote flashing server")
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

    # Prepare the target device
    getChipId(ser)
    mac = getMAC(ser)
    print("Effective device MAC address: " + ':'.join('{:02x}'.format(x) for x in mac))

    if args.action == "write":
        writeFirmware(ser, args.file)
    if args.action == "read":
        readFirmware(ser, args.file)
    if args.action == "verify":
        verifyFirmware(ser, args.file)


main()