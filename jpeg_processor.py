import struct
import argparse

parser = argparse.ArgumentParser()

parser.add_argument('-i', '--file', help='Path to the input file', required=True)

args = parser.parse_args()

file = open(args.file,"rb")
 
