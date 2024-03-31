import struct

# This file contains functions to dump the request and response packets of JN51xx bootloader protocol.
# Most of the messages are described in the JN-AN-1003 "JN51xx Boot Loader Operation" document. However,
# a few messages are not described in the document, were just reverse engineered from the sniffed data, 
# or their description is based on the JN51xxProgrammer.exe sources.

FLASH_ERASE_REQUEST         = 0x07
FLASH_ERASE_RESPONSE        = 0x08
FLASH_WRITE_REQUEST         = 0x09
FLASH_WRITE_RESPONSE        = 0x0a
FLASH_READ_REQUEST          = 0x0b
FLASH_READ_RESPONSE         = 0x0c
RESET_REQUEST               = 0x14
RESET_RESPONSE              = 0x15
RAM_WRITE_REQUEST           = 0x1d
RAM_WRITE_RESPONSE          = 0x1e
RAM_READ_REQUEST            = 0x1f
RAM_READ_RESPONSE           = 0x20
RUN_REQUEST                 = 0x21
RUN_RESPONSE                = 0x22
READ_FLASH_ID_REQUEST       = 0x25
READ_FLASH_ID_RESPONSE      = 0x26
CHANGE_BAUD_RATE_REQUEST    = 0x27
CHANGE_BAUD_RATE_RESPONSE   = 0x28
SELECT_FLASH_TYPE_REQUEST   = 0x2c
SELECT_FLASH_TYPE_RESPONSE  = 0x2d
GET_CHIP_ID_REQUEST         = 0x32
GET_CHIP_ID_RESPONSE        = 0x33
EEPROM_READ_REQUEST         = 0x3a
EEPROM_READ_RESPONSE        = 0x3b
EEPROM_WRITE_REQUEST        = 0x3c
EEPROM_WRITE_RESPONSE       = 0x3d

CHIP_ID_JN5169              = 0x0100b686

MEMORY_CONFIG_ADDRESS       = 0x01001500
CHIP_SETTINGS_ADDRESS       = 0x01001510
OVERRIDEN_MAC_ADDRESS       = 0x01001570
FACTORY_MAC_ADDRESS         = 0x01001580

def dumpGetChipIDRequest(data):
    print(">>  Chip ID Request")


def dumpGetChipIDResponse(data):
    # As per documentation, the chip ID response has only status byte, and ChipID (4 bytes) 
    # However the real device sends one more 4 byte value. As per JN51xxProgrammer.exe sources
    # these 4 bytes might be the bootloader version.
    bootloaderVer = None
    if len(data) == 5:
        status, chipId = struct.unpack('>BI', data)
    else:
        status, chipId, bootloaderVer = struct.unpack('>BII', data)

    print(f"<<  Chip ID Response: Status=0x{status:02x}, ChipID=0x{chipId:08x}, BootloaderVer=0x{bootloaderVer:08x}")


def getSpecialRAMAddrString(addr):
    addrstr = f"0x{addr:08x}"
    if addr == MEMORY_CONFIG_ADDRESS: 
        return addrstr + " (Memory Configuration)"
    if addr == CHIP_SETTINGS_ADDRESS:
        return addrstr + " (Chip Settings)"
    if addr == FACTORY_MAC_ADDRESS: 
        return addrstr + " (Factory MAC Address)"
    if addr == OVERRIDEN_MAC_ADDRESS: 
        return addrstr + " (Overriden MAC Address)"
    return addrstr


def dumpRAMWriteRequest(data):
    addr = struct.unpack("<I", data[0:4])[0]
    data = data[4:]
    print(f">>  Write RAM Request: Address={getSpecialRAMAddrString(addr)}, Len=0x{len(data):02x}, Data: {' '.join(f'{x:02x}' for x in data)}")


def dumpRAMWriteResponse(data):
    status = data[0]
    print(f"<<  Write RAM Response: Status=0x{status:02x}")


def dumpRAMReadRequest(data):
    addr, len = struct.unpack("<IH", data)
    print(f">>  Read RAM Request: Address={getSpecialRAMAddrString(addr)}, Length=0x{len:04x}")


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
    FLASH_ERASE_REQUEST: dumpFlashEraseRequest,
    FLASH_ERASE_RESPONSE: dumpFlashEraseResponse,
    FLASH_WRITE_REQUEST: dumpFlashWriteRequest,
    FLASH_WRITE_RESPONSE: dumpFlashWriteResponse,
    FLASH_READ_REQUEST: dumpFlashReadRequest,
    FLASH_READ_RESPONSE: dumpFlashReadResponse,
    RESET_REQUEST: dumpResetRequest,
    RESET_RESPONSE: dumpResetResponse,
    RAM_WRITE_REQUEST: dumpRAMWriteRequest,
    RAM_WRITE_RESPONSE: dumpRAMWriteResponse,
    RAM_READ_REQUEST: dumpRAMReadRequest,
    RAM_READ_RESPONSE: dumpRAMReadResponse,
    RUN_REQUEST: dumpRunRequest,
    RUN_RESPONSE: dumpRunResponse,
    READ_FLASH_ID_REQUEST: dumpReadFlashIdRequest,
    READ_FLASH_ID_RESPONSE: dumpReadFlashIdResponse,
    CHANGE_BAUD_RATE_REQUEST: dumpChangeBaudRateRequest,
    CHANGE_BAUD_RATE_RESPONSE: dumpChangeBaudRateResponse,
    SELECT_FLASH_TYPE_REQUEST: dumpSelectFlashTypeRequest,
    SELECT_FLASH_TYPE_RESPONSE: dumpSelectFlashTypeResponse,
    GET_CHIP_ID_REQUEST: dumpGetChipIDRequest,
    GET_CHIP_ID_RESPONSE: dumpGetChipIDResponse,
    EEPROM_READ_REQUEST: dumpEEPROMReadRequest,
    EEPROM_READ_RESPONSE: dumpEEPROMReadResponse,
    EEPROM_WRITE_REQUEST: dumpEEPROMWriteRequest,
    EEPROM_WRITE_RESPONSE: dumpEEPROMWriteResponse,
}

def dumpMessage(direction, msglen, msgtype, data, verbose=False):
    # Dump all the message including msg length, type, data, and CRC as is
    if verbose or (msgtype not in dumpers):
        print(f"{direction} {msglen:02x} {msgtype:02x} {' '.join(f'{x:02x}' for x in data)}")
    
    # If there is a dumper for this message type, call it (strip CRC byte from data)
    if msgtype in dumpers:
        dumpers[msgtype](data[:-1])


def calcCRC(data):
    res = 0
    for b in data:
        res ^= b
    
    return res
