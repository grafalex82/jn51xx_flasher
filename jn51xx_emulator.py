import serial
import struct
import argparse

verbose = False

def calcCRC(data):
    res = 0
    for b in data:
        res ^= b
    
    return res

def sendMessage(ser, msgtype, data):
    # Message header and data
    msg = struct.pack("<BB", len(data) + 2, msgtype)
    msg += data
    msg += calcCRC(msg).to_bytes(1, 'big')

    if verbose:    
        print("Sending: " + ' '.join('{:02x}'.format(x) for x in msg))

    ser.write(msg)


def getChipId(ser, req):
    print("MESSAGE: Get Chip ID")
    
    resp = struct.pack('>BI', 0, 0x0000b686)
    sendMessage(ser, 0x33, resp)


def emulateReadRAM(addr, len):
    if addr == 0x00000062:
        print("Reading bootloader version - emulating 42")
        return struct.pack("<I", 42)
    if addr == 0x01001570:
        print("Reading MAC address - returning 00:11:22:33:44:55:66:77:88")
        return struct.pack("<BBBBBBBB", 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88)
    if addr == 0x01001500:
        print("Reading Memory configuration")
        return struct.pack(">IIII", 0x3f, 0x3f, 0x3f, 0)
    
    print("Attempt to read {} bytes at unknown address {:08x}".format(len, addr))
    return bytes(len)


def readRAM(ser, req):
    addr, len = struct.unpack("<IH", req)
    print("MESSAGE: Read RAM addr={:08x} len={:04x}".format(addr, len))

    resp = struct.pack('>B', 0)
    resp += emulateReadRAM(addr, len)
    sendMessage(ser, 0x20, resp)


def selectFlashType(ser, req):
    flash, addr = struct.unpack("<BI", req)
 
    status = 0 if flash == 8 else 0xff  #Emulating only internal flash
    print("MESSAGE: Select flash type {:02x} addr={:08x}  - status={:02x}".format(flash, addr, status))

    resp = struct.pack("<B", status)
    sendMessage(ser, 0x2d, resp)


def flashErase(ser, req):
    print("MESSAGE: Flash Erase")

    resp = struct.pack("<B", 0)
    sendMessage(ser, 0x08, resp)


def setReset(ser, req):
    print("MESSAGE: Set reset")

    resp = struct.pack("<B", 0)
    sendMessage(ser, 0x15, resp)


def changeBaudRate(ser, req):
    br = struct.unpack("<B", req)
    print("MESSAGE: Change baud rate to " + str(br[0]))

    resp = struct.pack("<B", 0xff)
    sendMessage(ser, 0x28, resp)


def ramWrite(ser, req):
    addr = struct.unpack("<I", req[0:4])
    data = req[4:]

    print("MESSAGE: RAM write at addr={:08x}".format(addr[0]))
    if verbose:
        print(": " + ' '.join('{:02x}'.format(x) for x in data))

    resp = struct.pack("<B", 0)
    sendMessage(ser, 0x1e, resp)


def flashWrite(ser, req):
    addr = struct.unpack("<I", req[0:4])
    data = req[4:]

    print("MESSAGE: Flash write at addr={:08x}".format(addr[0]))
    if verbose:
        print(": " + ' '.join('{:02x}'.format(x) for x in data))

    resp = struct.pack("<B", 0)
    sendMessage(ser, 0x0a, resp)


def dumpMessage(msglen, msgtype, data):
    if not verbose:
        return

    print()
    print("Received: " + "{:02x} {:02x} ".format(msglen, msgtype) + ' '.join('{:02x}'.format(x) for x in data))
    

def main():
    parser = argparse.ArgumentParser(description="Flash NXP JN5169 device")
    parser.add_argument("port", help="Serial port")
    parser.add_argument("-v", "--verbose", action='store_true', help="Set verbose mode")
    args = parser.parse_args()
    
    global verbose
    verbose = args.verbose

    print("Starting NXP JN5169 emulator on " + args.port)
    ser = serial.Serial(args.port, baudrate=38400, timeout=1)

    while True:
        data = ser.read(2)
        if not data:
            continue

        msglen, msgtype = struct.unpack('BB', data)
        data = ser.read(msglen - 1)
        dumpMessage(msglen, msgtype, data)

        if msgtype == 0x32:
            getChipId(ser, data[:-1])
        elif msgtype == 0x1f:
            readRAM(ser, data[:-1])
        elif msgtype == 0x2c:
            selectFlashType(ser, data[:-1])
        elif msgtype == 0x27:
            changeBaudRate(ser, data[:-1])
        elif msgtype == 0x07:
            flashErase(ser, data[:-1])
        elif msgtype == 0x14:
            setReset(ser, data[:-1])
        elif msgtype == 0x1d:
            ramWrite(ser, data[:-1])
        elif msgtype == 0x09:
            flashWrite(ser, data[:-1])
        else:
            print("Unsupported message type: {:02x}".format(msgtype))


main()