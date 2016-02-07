# Pico CTF 2014 : Bit Puzzle

**Category:** Reverse Engineering
**Points:** 130
**Description:**

>This program seems to be a puzzle! Can you reverse-engineer it and find the solution to the puzzle?

**Hint:**
>You will probably want to disassemble this program and find the constraints on the input. Then, you might want a constraint solver!

## Write-up

This challenge is a crackme-style Linux ELF. It was completed on a 64-bit
Ubuntu 14.04 VM.

Download the challenge binary `bitpuzzle` and determine what it is:

``` bash
file bitpuzzle
bitpuzzle: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=55b8b87d63cadf2cc36cf4b08587c8dac17a48c1, stripped
```

Running the binary gives the following output:

```
Bet you can't solve my puzzle!
Give me a string.
hello 
Sorry, hello is not the right string!
```

At this point, the normal next steps would be to analyze the binary in IDA Pro
or gdb. For this write-up, I opted to try out a new analysis tool called
**qira** (http://qira.me). qira is a very new tool by our friend geohot that
he calls "timeless debugger", that is, all of the state (registers and memory) are
tracked and saved while a program is debugged, such that you can go back and
forth within the execution to analyze behavior. 

I opted to download and install the master branch and installed using the
following:

```bash
git clone https://github.com/BinaryAnalysisPlatform/qira.git 
cd qira
./install.sh
```

The installation will take a while, as it fetches and compiles qemu among
other things. The `install.sh` script will also prompt you for your sudo
password in order to apt-get packages for you. Once that is complete, you can
run qira locally and see the usage to make sure it built properly:

```bash
./qira -h
```

When run, qira will start a webserver to host the debugging session and will
also allow you to provide stdin/stdout to the program using a socat-like port
forwarder  on port 4000 for the target program. Here is the command to run 
for `bitpuzzle`:

```bash
./qira -s -S ../bitpuzzle
```

Leave this running and browse to http://localhost:3002/ (use Chrome) 
to view the interface.

Also, open a new terminal and run `nc localhost 4000` and you will see that
qira starts running the binary. Supply "helloworld" to the prompt and press
Enter. In the Chrome window, you will see a new vertical bar on the left.
This is known as the "timeline" and shows every step executed by the program
invocation you just ran. Place your mouse cursor in the main panel and scroll
the mouse weel to move backwards and forwards in the program execution
history. Notice that you can observe the register state, instruction
execution, basic block diagram, and memory contents for every step of the
program. You should also bring up the keyboard shortcuts in a new tab and
familiarize yourself with with:

>https://github.com/BinaryAnalysisPlatform/qira#keyboard-shortcuts-in-webclientcontrolsjs

Even **more** useful is the `strace` output window below the register view.
This shows any system call (with arguments and return values) done during the
program run. If you scroll to the bottom of that window, you will see a call
to `write()`. Click on the blue step count next to it to snap to where that
happened in the instruction listing. If you click on the yellow instruction
given to the `write()` call, it will snap the memory dump to the location of
the static messages that were printed out at the start of the program. You can
do the same thing for the preceeding `read()` call to see where exactly your
input was read in. Doing that and exploring the code following reveals that a
`cmp ecx, 0xde` is checking to make sure the input is 32-bytes long. Ours
isn't so next conditional jump fails, the fail message is printed, and program
exits.

Run the `nc localhost 4000` again, and this time supply
`11112222333344445555666677778888` as the input string. This will pass the
length check and will also put easily-spotted values in input 
buffer so we can track the program testing our input.

After you do this, the browser will refresh to show a new, longer timeline on
the left, this means that the program had a higher step count due to the
proper length input being supplied. Click on the bar to update the other views
to use this new "fork". If you scoll through the same area, the jump now
passes and we get deeper into the program.  Your window should look something
like this:

![qira
bitpuzzle](https://raw.githubusercontent.com/nattypwns/ctf_writeups/master/pico-ctf-2014/bitpuzzle-130/qira-screen.png)

At this point the program starts doing checks on 4-byte pieces of the input.
As you scroll through them you can see what the register values are to
determine which of the 4-byte dwords are being checked. The first check
happens between ``0x8048596 - 0x804859c`` and can be reduced to the following
(``in1`` means bytes[0:4], ``in2`` is bytes[5:7], etc):

```
constraint1 (c1): in1 + in2 == 0xc0dcdfce
```

However, you can see that if this check *fails*, the program will actually do
another check instead and then continue. We actually want this instead (we'll
see why later), so the constraint it really:

```
constraint1 (c1): in1 + in2 != 0xc0dcdfce
```

Now the goal is to go through all of the instruction "sets" and record the
checks that it is enforcing on our input. While it is time-consuming and
tedious, having the qira-recorded state is helpful to see which input chunks
are being read from the stack and checked. Here are the constraints:

```
c1: in1 + in2 != 0xc0dcdfce
c1b:in1 + in2 == 0xd5d3dddc
c2:(in1 + in1*2) + (in2 + in2*4) == 0x404a7666
c3: in4 ^ in1 == 0x18030607
c4: in1 & in4 == 0x666c6970
c5: in2 * in5 == 0xb180902b

c6: in5 * in3 == 0x3e436b5f
c7: in6*2 + in5 == 0x5c483831
c8: in6 & 0x70000000 == 0x70000000
c9: in6 / in7 == 1
c10: in6 % in7 == 0x0e000cec
c11: (in5 + in5*2) + in8*2 == 0x3726eb17
c12: ((in8*8 - in8) + in3*4) == 0x8b0b922d
c13: (in8 + in8*2) + in4 == 0xb9cf9c91
```

After this is done, if they all pass, the win message is printed.

So now you must determine how to craft your input such that the laundry list
of constraints is satisfied from above. z3 (https://github.com/Z3Prover/z3) is
a well-known theorem prover that will do the job, plus it has a simple Python
Binding to make it easy to hack something together.

Download one of the binary releases and extract:

```bash
wget https://github.com/Z3Prover/bin/blob/master/releases/z3-4.4.1-x64-ubuntu-14.04.zip
unzip z3-4.4.1-x64-ubuntu-14.04.zip
cd z3-4.4.1-x64-ubuntu-14.04/bin
```

Copy and run the included ``bitpuzzle-solver.py`` into this directory and run
it, yielding the input that satisfies our program constraints (and is also the
flag): **solving_equations_is_lots_of_fun**.

Note, if you try to enforce that first constraint we found above, you'll find
out that the system is not satisfiable! Thus the need to negate the constraint
and add "c1b" instead. 

Copy bitpuzzle-solver.py into `z3-4.4.1-x64-ubuntu-14.04/bin`
