# Whiff
   Whiff is a program written to dump packets sent and received by
   the World of Warcraft client. Packets can be parsed using
   TrinityCore's WowPacketParser. Whiff supports 32-bit and 64-bit
   Windows clients, as well as Live and PTR (WoD only) builds.
   Whiff uses Injection, powered by the  MologieDetours library,
   with a few modifications.

### Useful Links
Source Code:
   https://github.com/Zedron/Whiff

MologieDetours:
   https://github.com/kimperator/MologieDetours
   
WowPacketParser
   https://github.com/TrinityCore/WowPacketParser

### Usage
 - If you wish to have named opcodes in the console, place your
    Opcodes.h(new opcode system) or Opcodes.cpp(old opcode system) or
    Opcodes.cs(WowPacketParser) in the same directory as your executable
 - Start Whiff (or Whiff-64) from the same directory as Whiff.dll
 - If you want to stop sniffing type 'quit' into the console or CTRL-C
 - .pkt file containing the dumped packets is located where the
       Whiff executable is

### Supported Client Builds
 - All common pre-WoD builds
 - All WoD builds (PTR and Live)

### WARNING
 Injection writes into WoW's memory at runtime. So Warden (Blizzard's anticheat)
 could detect it. However there have been no reported cases of someone
 getting banned for sniffing.

### Compilation  
 Project files must be generated with CMake.
 CMake (http://www.cmake.org/) is an extensible, open-source
 system that manages the build process in an operating system
 and in a compiler-independent manner. You can download a GUI
 for your Windows OS and generate project files for example
 your Visual Studio.
 
 Alternatively, compiled binaries can be download from https://github.com/Zedron/Whiff/wiki
    
### License
    GNU GPLv3
    COPYING file contains the license which should be distributed
    with the software or visit http://www.gnu.org/licenses/gpl-3.0.html

    Whiff is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Whiff is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Whiff.  If not, see <http://www.gnu.org/licenses/>.
