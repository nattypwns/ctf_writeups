#!/usr/bin/env python

from z3 import *
import struct

# Define the 8 dwords in the input string
in1 = BitVec('in1', 32)
in2 = BitVec('in2', 32)
in3 = BitVec('in3', 32)
in4 = BitVec('in4', 32)
in5 = BitVec('in5', 32)
in6 = BitVec('in6', 32)
in7 = BitVec('in7', 32)
in8 = BitVec('in8', 32)

# Define the constraint solver and add the
# constraints determined through debugging bitpuzzle.
s = Solver()
#s.add(in1 + in2 == 0xc0dcdfce)
s.add(in1 + in2 != 0xc0dcdfce)
s.add(in1 + in2 == 0xd5d3dddc)
s.add((in1 + in1*2) + (in2 + in2*4) == 0x404a7666)
s.add(in4 ^ in1 == 0x18030607)
s.add(in1 & in4 == 0x666c6970)
s.add(in2 * in5 == 0xb180902b)
s.add(in5 * in3 == 0x3e436b5f)
s.add(in6*2 + in5 == 0x5c483831)
s.add(in6 & 0x70000000 == 0x70000000)
s.add(in6 / in7 == 1)
s.add(in6 % in7 == 0x0e000cec)
s.add((in5 + in5*2) + in8*2 == 0x3726eb17)
s.add((in8*8 - in8) + in3*4 == 0x8b0b922d)
s.add((in8 + in8*2) + in4 == 0xb9cf9c91)

# Verify that we can even get a satisfiable solution.
print(s.check())

# print out each value in the solution, unpacking
# strings from uint32_le's
def numToStr(z3var):
    return struct.pack("<I", mod[z3var].as_long())
mod = s.model()
print "%s"*8 % (
    numToStr(in1), 
    numToStr(in2), 
    numToStr(in3), 
    numToStr(in4), 
    numToStr(in5), 
    numToStr(in6), 
    numToStr(in7), 
    numToStr(in8))
