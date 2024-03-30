import serial
import struct
import argparse

verbose = "none"

def dumpGetChipIDRequest(data):
    print(">>  Chip ID Request")


def dumpGetChipIDResponse(data):
    # As per documentation, the chip ID response has only status byte, and ChipID (4 bytes) 
    # However real device sends one more 4 byte value. As per JN51xxProgrammer.exe sources these 4 bytes might be bootloader version.
    bootloaderVer = None
    if len(data) == 5:
        status, chipId = struct.unpack('>BI', data)
    else:
        status, chipId, bootloaderVer = struct.unpack('>BII', data)

    print(f"<<  Chip ID Response: Status=0x{status:02x}, ChipID=0x{chipId:08x}, BootloaderVer=0x{bootloaderVer:08x}")


def dumpRAMWriteRequest(data):
    addr = struct.unpack("<I", data[0:4])
    data = data[4:]
    print(f">>  Write RAM Request: Address=0x{addr[0]:08x}, Len=0x{len(data):02x}, Data: {' '.join(f'{x:02x}' for x in data)}")


def dumpRAMWriteResponse(data):
    status = data[0]
    print(f"<<  Write RAM Response: Status=0x{status:02x}")


def dumpRAMReadRequest(data):
    addr, len = struct.unpack("<IH", data)
    print(f">>  Read RAM Request: Address=0x{addr:08x}, Length=0x{len:04x}")


def dumpRAMReadResponse(data):
    status = data[0]
    print(f"<<  Read RAM Response: Status=0x{status:02x}, Data: {' '.join(f'{x:02x}' for x in data[1:])}")


def dumpSelectFlashTypeRequest(data):
    flash, addr = struct.unpack("<BI", data)
    print(f">>  Select Flash Type: FlashType={flash}, Address=0x{addr:08x}")


def dumpSelectFlashTypeResponse(data):
    status = data[0]
    print(f"<<  Select Flash Type Response: Status=0x{status:02x}")


def dumpReadFlashIdRequest(data):
    print(">>  Read Flash ID Request")


def dumpReadFlashIdResponse(data):
    status, manufacturerId, flashId = struct.unpack('>BBB', data)
    print(f"<<  Read Flash ID Response: Status=0x{status:02x}, ManufacturerID=0x{manufacturerId:02x}, FlashID=0x{flashId:02x}")


def dumpFlashEraseRequest(data):
    print(">>  Flash Erase Request")


def dumpFlashEraseResponse(data):
    status = data[0]
    print(f"<<  Flash Erase Response: Status=0x{status:02x}")


def dumpFlashReadRequest(data):
    addr, len = struct.unpack("<IH", data)
    print(f">>  Read Flash Request: Address=0x{addr:08x}, Length=0x{len:04x}")


def dumpFlashReadResponse(data):
    status = data[0]
    print(f"<<  Read Flash Response: Status=0x{status:02x}, Data: {' '.join(f'{x:02x}' for x in data[1:])}")


def dumpFlashWriteRequest(data):
    addr = struct.unpack("<I", data[0:4])
    data = data[4:]
    print(f">>  Write Flash Request: Address=0x{addr[0]:08x}, Len=0x{len(data):02x}, Data: {' '.join(f'{x:02x}' for x in data)}")


def dumpFlashWriteResponse(data):
    status = data[0]
    print(f"<<  Write Flash Response: Status=0x{status:02x}")


def dumpResetRequest(data):
    print(">>  Reset Request")


def dumpResetResponse(data):
    status = data[0]
    print(f"<<  Reset Response: Status=0x{status:02x}")


def dumpRunRequest(data):
    addr = struct.unpack("<I", data)
    print(f">>  Run Request: Address=0x{addr[0]:08x}")


def dumpRunResponse(data):
    status = data[0]
    print(f"<<  Run Response: Status=0x{status:02x}")


def dumpEEPROMReadRequest(data):
    addr, len = struct.unpack("<IH", data)
    print(f">>  Read EEPROM Request: Address=0x{addr:08x}, Length=0x{len:04x}")


def dumpEEPROMReadResponse(data):
    status = data[0]
    print(f"<<  Read EEPROM Response: Status=0x{status:02x}, Data: {' '.join(f'{x:02x}' for x in data[1:])}")


def dumpEEPROMWriteRequest(data):
    addr = struct.unpack("<I", data[0:4])
    data = data[4:]
    print(f">>  Write EEPROM Request: Address=0x{addr[0]:08x}, Len=0x{len(data):02x}, Data: {' '.join(f'{x:02x}' for x in data)}")


def dumpEEPROMWriteResponse(data):
    status = data[0]
    print(f"<<  Write EEPROM Response: Status=0x{status:02x}")


def dumpChangeBaudRateRequest(data):
    divisor = data[0]
    baudrate = "Unknown"
    match divisor:
        case 1: baudrate = 1000000
        case 2: baudrate = 500000
        case 9: baudrate = 115200
        case 26: baudrate = 38400
        case _: baudrate = f"Unknown (divisor={divisor})"
    print(f">>  Change Baud Rate Request: Baudrate={baudrate}")


def dumpChangeBaudRateResponse(data):
    status = data[0]
    print(f"<<  Change Baud Rate Response: Status=0x{status:02x}")


dumpers = {
    0x07: dumpFlashEraseRequest,
    0x08: dumpFlashEraseResponse,
    0x09: dumpFlashWriteRequest,
    0x0a: dumpFlashWriteResponse,
    0x0b: dumpFlashReadRequest,
    0x0c: dumpFlashReadResponse,
    0x14: dumpResetRequest,
    0x15: dumpResetResponse,
    0x1d: dumpRAMWriteRequest,
    0x1e: dumpRAMWriteResponse,
    0x1f: dumpRAMReadRequest,   
    0x20: dumpRAMReadResponse,
    0x21: dumpRunRequest,
    0x22: dumpRunResponse,
    0x25: dumpReadFlashIdRequest,
    0x26: dumpReadFlashIdResponse,
    0x27: dumpChangeBaudRateRequest,
    0x28: dumpChangeBaudRateResponse,
    0x2c: dumpSelectFlashTypeRequest,
    0x2d: dumpSelectFlashTypeResponse,
    0x32: dumpGetChipIDRequest,
    0x33: dumpGetChipIDResponse,
    0x3a: dumpEEPROMReadRequest,
    0x3b: dumpEEPROMReadResponse,
    0x3c: dumpEEPROMWriteRequest,
    0x3d: dumpEEPROMWriteResponse,
}

def dumpMessage(direction, msglen, msgtype, data):
    if verbose == "none":
        return

    # Dump all the message including msg length, type, data, and CRC as is
    if (verbose == "raw") or (msgtype not in dumpers):
        print(f"{direction} {msglen:02x} {msgtype:02x} {' '.join(f'{x:02x}' for x in data)}")
    
    # If there is a dumper for this message type, call it (strip CRC byte from data)
    if msgtype in dumpers:
        dumpers[msgtype](data[:-1])
    

def transferMsg(direction, src, dst):
    header = src.read(2)
    msglen, msgtype = struct.unpack('BB', header)
    data = src.read(msglen - 1)

    dumpMessage(direction, msglen, msgtype, data)

    dst.write(header)
    dst.write(data)


def main():
    parser = argparse.ArgumentParser(description="Proxy and dump JN5169 flashing messages")
    parser.add_argument("srcport", help="Source serial port (flasher side)")
    parser.add_argument("dstport", help="Destination serial port (device side)")
    parser.add_argument("-v", "--verbose", nargs='?', choices=["none", "protocol", "raw"], help="Set verbosity level", default="none")
    args = parser.parse_args()
    
    global verbose
    verbose = args.verbose

    print(f"Starting proxy on {args.srcport} and {args.dstport} ports")
    src = serial.Serial(args.srcport, baudrate=38400)
    dst = serial.Serial(args.dstport, baudrate=38400)

    while True:
        transferMsg(">", src, dst)
        transferMsg("<", dst, src)

main()