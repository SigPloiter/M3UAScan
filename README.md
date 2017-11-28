# M3UAScan

A Scanner for M3UA protocol to detect Sigtran supporting nodes

M3UA stands for MTP Level 3 (MTP3) User Adaptation Layer as defined by the IETF SIGTRAN working group in RFC 4666 .M3UA enables the SS7 protocol's User Parts (e.g. ISUP, SCCP and TUP) to run over IP instead of telephony equipment like ISDN and PSTN. It is recommended to use the services of SCTP to transmit M3UA.

M3UA uses a complex state machine to manage and indicate states it's running. Several M3UA messages are mandatory to make a M3UA association or peering fully functional (ASP UP, ASP UP Acknowledge, ASP Active, ASP Active Acknowledge).

# Why Use M3UAScan
M3UA scan is simple scanner that aims to help pentesters to identify nodes that has sctp ports opened with m3ua on top of it.

Detecting a node with m3ua is an indication that this is a node core. This scanner could be helpful to identify signaling nodes exposed on the internet

# Requirements

sudo apt-get install libsctp1 libsctp-dev lksctp-tools

# Usage

Usage: m3uascan.py -l [sctp listening IP] -p [sctp listening port]-r [Remote subnet/mask] -P [Remote sctp port]-o [Output filename] 


Example: ./m3uascan.py -l 192.168.1.1 -p 2905 -r 179.0.0.0/16 -P 2906 -o output.txt

Or you can opt-out "-P" and use the built-in sctp ports in the script

Disclaimair: sctp ports were taken from the SCTPscanner provided by P1Security. Along with pysctp.py. Credit goes to P1Security on both 

