import serial
import struct
import argparse

from jn51xx_protocol import *

verbose = "none"

def calcCRC(data):
    res = 0
    for b in data:
        res ^= b
    
    return res

def sendResponse(ser, msgtype, data):
    # Message header and data
    msglen = len(data) + 2
    msg = struct.pack("<BB", msglen, msgtype)
    msg += data
    msg += calcCRC(msg).to_bytes(1, 'big')

    if verbose != "none":
        dumpMessage(">", msglen, msgtype, msg[2:], verbose == "raw")

    ser.write(msg)


def emulateGetChipId(ser, data):
    chipID = CHIP_ID_JN5169
    bootloaderVer = 0x000b0002
    resp = struct.pack('>BII', 0, chipID, bootloaderVer)
    sendResponse(ser, GET_CHIP_ID_RESPONSE, resp)


def emulateRAMData(addr, len):
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


def emulateRAMRead(ser, req):
    addr, len = struct.unpack("<IH", req)
    resp = struct.pack('>B', 0)
    resp += emulateRAMData(addr, len)

    sendResponse(ser, RAM_READ_RESPONSE, resp)


def emulateSelectFlashType(ser, req):
    flash, addr = struct.unpack("<BI", req)
 
    status = 0 if flash == 8 else 0xff  #Emulating only internal flash
    resp = struct.pack("<B", status)
    sendResponse(ser, SELECT_FLASH_TYPE_RESPONSE, resp)


def emulateFlashErase(ser, req):
    resp = struct.pack("<B", 0)
    sendResponse(ser, FLASH_ERASE_RESPONSE, resp)


def emulateReset(ser, req):
    resp = struct.pack("<B", 0)
    sendResponse(ser, RESET_RESPONSE, resp)


def emulateChangeBaudRate(ser, req):
    print("Warning: Changing the baud rate is not supported")

    resp = struct.pack("<B", 0xff)
    sendResponse(ser, CHANGE_BAUD_RATE_RESPONSE, resp)


def emulateRAMWrite(ser, req):
    addr = struct.unpack("<I", req[0:4])
    data = req[4:]

    # TODO: store data in memory

    resp = struct.pack("<B", 0)
    sendResponse(ser, RAM_WRITE_RESPONSE, resp)


def emulateFlashWrite(ser, req):
    addr = struct.unpack("<I", req[0:4])
    data = req[4:]

    # TODO: store data in memory

    resp = struct.pack("<B", 0)
    sendResponse(ser, FLASH_WRITE_RESPONSE, resp)


def main():
    parser = argparse.ArgumentParser(description="Emulate NXP JN5169 device")
    parser.add_argument("port", help="Serial port")
    parser.add_argument("-v", "--verbose", nargs='?', choices=["none", "protocol", "raw"], help="Set verbosity level", default="none")
    args = parser.parse_args()
    
    global verbose
    verbose = args.verbose

    print("Starting NXP JN5169 emulator on " + args.port)
    ser = serial.Serial(args.port, baudrate=38400, timeout=1)

    while True:
        # Wait for a message, read the message header
        data = ser.read(2)
        if not data:
            continue

        # Parse the message header, dump the message
        msglen, msgtype = struct.unpack('BB', data)
        data = ser.read(msglen - 1)
        dumpMessage("<", msglen, msgtype, data, verbose == "raw")

        # Process the message depending on the message type
        if msgtype == GET_CHIP_ID_REQUEST:
            emulateGetChipId(ser, data[:-1])
        elif msgtype == RAM_READ_REQUEST:
            emulateRAMRead(ser, data[:-1])
        elif msgtype == SELECT_FLASH_TYPE_REQUEST:
            emulateSelectFlashType(ser, data[:-1])
        elif msgtype == CHANGE_BAUD_RATE_REQUEST:
            emulateChangeBaudRate(ser, data[:-1])
        elif msgtype == FLASH_ERASE_REQUEST:
            emulateFlashErase(ser, data[:-1])
        elif msgtype == RESET_REQUEST:
            emulateReset(ser, data[:-1])
        elif msgtype == RAM_WRITE_REQUEST:
            emulateRAMWrite(ser, data[:-1])
        elif msgtype == FLASH_WRITE_REQUEST:
            emulateFlashWrite(ser, data[:-1])
        else:
            print("Unsupported message type: {:02x}".format(msgtype))

if __name__ == "__main__":
    main()