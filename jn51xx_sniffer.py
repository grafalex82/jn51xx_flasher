import serial
import struct
import argparse

from jn51xx_dumper import dumpMessage

# This script proxies data from one serial port to another, and dumps all JN5169 flashing messages

def transferMsg(direction, src, dst, verbose):
    header = src.read(2)
    msglen, msgtype = struct.unpack('BB', header)
    data = src.read(msglen - 1)

    if verbose != "none":
        dumpMessage(direction, msglen, msgtype, data, verbose == "raw")

    dst.write(header)
    dst.write(data)


def main():
    parser = argparse.ArgumentParser(description="Proxy and dump JN5169 flashing messages")
    parser.add_argument("srcport", help="Source serial port (flasher side)")
    parser.add_argument("dstport", help="Destination serial port (device side)")
    parser.add_argument("-v", "--verbose", nargs='?', choices=["none", "protocol", "raw"], help="Set verbosity level", default="none")
    args = parser.parse_args()
    
    print(f"Starting proxy on {args.srcport} and {args.dstport} ports")
    src = serial.Serial(args.srcport, baudrate=38400)
    dst = serial.Serial(args.dstport, baudrate=38400)

    while True:
        transferMsg(">", src, dst, args.verbose)
        transferMsg("<", dst, src, args.verbose)


if __name__ == "__main__":
    main()
