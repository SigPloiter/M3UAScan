#!/usr/bin/env python
#       Copyright 2017 Loay Abdelrazek (@sigploiter)
#

#       Redistribution and use in source and binary forms, with or without
#       modification, are permitted provided that the following conditions are
#       met:
#
#       * Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the following disclaimer
#         in the documentation and/or other materials provided with the
#         distribution.
#       * Neither the name of the  nor the names of its
#         contributors may be used to endorse or promote products derived from
#         this software without specific prior written permission.
#
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#       "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#       LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#       A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#       OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#       SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#       LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#       DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#       THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import socket
import sys
import time
import threading
import optparse
import signal
import select
import os
from sctp import *
from netaddr import *
from colorama import init
from termcolor import cprint
from pyfiglet import figlet_format
from struct import *
from binascii import * 





def initSCTP(local_ip, local_port, peer_ip, peer_port):
	#Initializing SCTP
    global sk
    global sctp_count
    global m3ua_count
  
    
    try:
        sk=sctpsocket_tcp(socket.AF_INET)
        sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sk.events.clear()
        sk.bind((local_ip,local_port))
        sk.settimeout(1.5)
    except Exception, err:
        print '\033[31m[-]\033[0m Error: %s' %err
        sys.exit(1)

        
       
    print "\033[34m[*]\033[0m Scanning %s on port %s" %(peer_ip, peer_port)
    try:
               
        sk.connect(("%s" %peer_ip ,peer_port))
        print '\033[32m[+]\033[0m Scanning %s on port %s for M3UA' %(peer_ip,peer_port)
        fname.write('SCTP Detected- '+str(peer_ip)+ ':'  +str(peer_port)+'\n')
        sctp_count +=1

        #M3UA Header 
        m3ua_version = 1    #1Byte
        m3ua_reserved = 0   #1Byte

        #M3UA Message Classes, 1Byte
        m3ua_msg_class = {'ASPStateMaint':3,'ASPTrafficMaint':4,'TransferMessages':1} 
            
        #M3UA Message Types
        m3ua_msg_type = {'ASPUP':1, 'ASPC':1, 'ASPUP_Ack':4, 'ASPAC_ACK':3, 'Payload': 1} 
        m3ua_param_tags = {'TrafficMode':11, 'RoutingContext': 6, 'ASPIdentifier':17, 'ProtocolData':528}   #2Bytes

        msg_length = 0  #4Bytes, total length of message to be the sum of all messages lenghts of the high layers (sccp,tcap,map) and be replaced with calcsize()
            
        ##M3UA ASP Identifier Parameter
        m3ua_asp_identifier = 3 #4Bytes
        aspid_param_len = 8 #2Bytes

        ##M3UA Traffic Mode type Parameters
        m3ua_traffic_mode = {'Loadshare':2,'Broadcast': 3 ,'Override': 1 } #4Bytes
        traffic_mode_param_len = 8 #2Bytes

        ##M3UA Routing Context Parameters
        m3ua_rc = 100   #4Bytes
        rc_param_len = 8

        m3ua_header_aspup = pack('!BBBBiHHi',m3ua_version,m3ua_reserved,m3ua_msg_class['ASPStateMaint'],m3ua_msg_type['ASPUP'],calcsize('BBBBiHHi'),m3ua_param_tags['ASPIdentifier'], aspid_param_len, m3ua_asp_identifier)


        try:
            sk.sendall(m3ua_header_aspup)
                
        except Exception, msg:
            print '\033[31m[-]\033[0m Error: %s' %msg
                
           

        reply_1=sk.recv(4096)
        
        m3ua_recv = unpack('!BBBBiHHi',reply_1)
        
        if m3ua_recv[3] == 4:
            print '\033[32m[+]\033[0m '+ str(peer_ip) +':'+'\033[32m'+str(ports)+'\033[0m' ' - \033[32mM3UA Detected ASP Up\033[0m'
            print 
            fname.write('M3UA Detected- '+str(peer_ip) +':'+str(peer_port)+'\n')
            fname.write('####################################\n')
            m3ua_count += 1
            

               
        else:
            print '\033[31m[-]\033[0m ' + str(peer_ip)+ ':ASP is Down'

            
           
        fname.close() 

    except Exception, msg:
        print '\033[31m[-]\033[0m Port %s closed on %s: %s' %(peer_port,peer_ip,msg)
        screenLock.acquire()
    finally:
        screenLock.release()

           



def main():

     global sctp_ports
     global local_ip
     global local_port
     global peer_ip
     global peer_port
     global fname
     

     #List of ports provided by P1sec sctp scanner
     sctp_ports = [
             2097,
             2000,    # Huawei UMG8900 MGW H248 port
             2001,    # Huawei UMG8900 MGW H248 port
             2010,    # Huawei UMG8900 MGW H248 port
             2011,    # Huawei UMG8900 MGW H248 port
             2020,    # Huawei UMG8900 MGW H248 port
             2021,    # Huawei UMG8900 MGW H248 port
             2100,    # Huawei UMG8900 MGW H248 port
             2110,    # Huawei UMG8900 MGW H248 port
             2120,    # Huawei UMG8900 MGW H248 port
             2225,    # rcip-itu -- Resource Connection Initiation Protocol
             2427,    # mgcp-gateway - MGCP and SGCP -- http:#en.wikipedia.org/wiki/Media_Gateway_Control_Protocol
             2477,
             2577,    # Test configuration for Cisco AS5400 products (SCTP/IUQ/Q931)
             2904,    # m2ua -- http:#www.pt.com/tutorials/iptelephony/tutorial_voip_mtp.html , then mtp2, mtp3, sccp  (default for Huawei UMG8900 MGW)
             2905,    # m3ua -- http:#www.ietf.org/rfc/rfc3332.txt - http:#www.hssworld.com/voip/stacks/sigtran/Sigtran_M3UA/overview.htm
             2906,    # m3ua common config port
             2907,    # m3ua -- py sms m3ua default ports
             2908,    # m3ua -- py sms m3ua default ports
             2909,    # m3ua common config port
             2944,    # megaco-h248 - Megaco-H.248 text
             2945,    # h248-binary - Megaco/H.248 binary (default for Huawei UMG8900 MGW)
             3000,    # m3ua common port
             3097,    # ITU-T Q.1902.1/Q.2150.3
             3565,    # m2pa -- http:#rfc.archivesat.com/rfc4166.htm
             3740,    # ayiya -- http:#unfix.org/~jeroen/archive/drafts/draft-massar-v6ops-ayiya-01.txt
             3863,    # RSerPool's ASAP protocol -- http:#tdrwww.iem.uni-due.de/dreibholz/rserpool/
             3864,    # RSerPool's ENRP protocol (asap-sctp/tls) -- http:#tdrwww.iem.uni-due.de/dreibholz/rserpool/
             3868,    # Diameter
             4000,    # m3ua common port
             5000,
             5001,
             5060,    # SIP - Session Initiation Protocol
             5061,    # sip-tls
             5672,    # AMQP
             5675,    # v5ua,  V5UA (V5.2-User Adaptation) Layer -- http:#rfc.archivesat.com/rfc4166.htm
             6000,
             6100,    # Huawei UMG8900 MGW config
             6110,    # Huawei UMG8900 MGW config
             6120,    # Huawei UMG8900 MGW config
             6130,    # Huawei UMG8900 MGW config
             6140,    # Huawei UMG8900 MGW config
             6150,    # Huawei UMG8900 MGW config
             6160,    # Huawei UMG8900 MGW config
             6170,    # Huawei UMG8900 MGW config
             6180,    # Huawei UMG8900 MGW config
             6190,    # Huawei UMG8900 MGW config
             6529,    # Non standard V5 & IUA port -- from port 6005
             6700,    # SCTP based TML (Transport Mapping Layer) for ForCES protocol -- http:#www.ietf.org/id/draft-ietf-forces-sctptml-05.txt
             6701,    # SCTP based TML (Transport Mapping Layer) for ForCES protocol -- http:#www.ietf.org/id/draft-ietf-forces-sctptml-05.txt
             6702,    # SCTP based TML (Transport Mapping Layer) for ForCES protocol -- http:#www.ietf.org/id/draft-ietf-forces-sctptml-05.txt
             6789,    # iua test port for some CISCO default configurations
             6790,    # iua test port for some CISCO default configurations
             7000,    # MTP3 / BICC
             7001,    # Common M3UA port
             7102,    # found in the wild
             7103,    # found in the wild
             7105,    # found in the wild
             7551,    # found in the wild
             7626,    # simco - SImple Middlebox COnfiguration (SIMCO)
             7701,    # found in the wild
             7800,    # found in the wild
             8000,    # found in the wild, MTP3 / BICC
             8001,    # found in the wild
             8471,    # pim-port PIM over Reliable Transport
             8787,    # iua test port for some CISCO default configurations
             9899,    # sctp-tunneling, actually is usually tcp/udp based but could come from human error
             9911,    # iua test port for some CISCO default configurations
             9900,    # sua (SCCP User Adaptation layer) or iua (ISDN Q.921 User Adaptation -- http:#rfc.archivesat.com/rfc4166.htm)  (default for Huawei UMG8900 MGW)
             9901,    # enrp-sctp - enrp server channel
             9902,     # enrp-sctp-tls - enrp/tls server channel 
             10000,
             10001,
             11146,    # Local port for M3UA, Cisco BTS 10200 Softswitch
             11997,    # wmereceiving - WorldMailExpress 
             11998,    # wmedistribution - WorldMailExpress 
             11999,    # wmereporting - WorldMailExpress 
             12205,    # Local port for SUA, Cisco BTS uses for FSAIN communication is usually 12205,
             12235,    # Local port for SUA, Cisco BTS usage for FSPTC
             13000,    # m3ua -- py sms m3ua default ports
             13001,    # m3ua -- py sms m3ua default ports
             14000,    # m3ua common port, m2pa sometimes too
             14001,    # sua, SUA (SS7 SCCP User Adaptation) Layer -- http:#rfc.archivesat.com/rfc4166.htm , m3ua sometimes too
             29118,    # SGsAP in 3GPP
             29168,    # SBcAP in 3GPP, [TS 29.168][Kymalainen]           2009-08-20
             30000,
             32905,    # m3ua common port
             32931,
             32768,
             36412,    # S1AP
             36422,    # X2AP
             ]     
     
     init(strip=not sys.stdout.isatty())
     banner = "M3UAScan"
     cprint(figlet_format(banner, font="standard"),"blue")
     print "\033[33m[+]\033[0m	\tM3UA Scanner			\033[33m[+]\033[0m"
     print "\033[33m[+]\033[0m	\tBeta Version 1			\033[33m[+]\033[0m"
     print "\033[33m[+]\033[0m\t  CodedBy: LoayAbdelrazek		\033[33m[+]\033[0m"
     print "\033[33m[+]\033[0m	\t(@SigPloiter)			\033[33m[+]\033[0m"
     print 
     
    

     parser = optparse.OptionParser(usage="usage: %prog -l [sctp listening IP] -p [sctp listening port]"
                                                        "-r [Remote subnet/mask] -P [Remote sctp port]"
                                                        "-o [Output filename] ",
                               version="%prog BETA Version 1")
     parser.add_option("-l", "--localIP", dest="local_ip",
                  default=False,type="string",
                  help="\tSpecify local IP listening for sctp")
     parser.add_option("-p","--localPort", dest="local_port",
                  default=2905,type="int", 
                  help="\tSpecify local sctp port,default 2905")
     parser.add_option("-r","--peerIP",dest="peer_ip",
                  default=False,type='string', 
                  help="\tSpecify subnet/IP to scan")
     parser.add_option("-P", "--remotePort",dest="peer_port",
                 default=False, type="int",
                 help="\tSpecify Remote SCTP port to scan" )
                 
     parser.add_option("-o", "--output",dest="output_file",
                 default=False, type="string",
                 help="\tSpecify Filename to output the results" )

     (options, args) = parser.parse_args()

     

     if (options.local_ip is False) or (options.peer_ip is False):
         parser.error("not enought number of arguments\n\nExample: ./m3uascan.py -l 192.168.1.1 -p 2905 -r 179.0.0.0/16 -P 2906 -o output.txt\n")
        
     else:
     
         local_ip = options.local_ip
         local_port = options.local_port
         peer_ip = IPNetwork(options.peer_ip)
         
         peer_port = []
         peer_port.append(options.peer_port)
         peer_port = peer_port
        
         output_file = options.output_file
         if options.output_file:
            fname = open(output_file, 'a')
         elif options.output_file is False:
            fname = open('dummy.txt', 'a')
            os.system('rm -f dummy.txt')
            fname.close()
         if options.peer_port is False:
            peer_port = sctp_ports
           

         
         for ip in peer_ip.iter_hosts():
            for port in peer_port:
                s = threading.Thread(target=initSCTP, args=(local_ip, local_port, ip, port))
                s.daemon = True
                s.start()
                time.sleep(0.1)
     
     

         
def sigint_handler(signal, frame):
    print '\nM3UA Scanner:Interrupted'
    sys.exit(1)


     
      
         
if __name__ == '__main__':
    
    m3ua_count = 0
    sctp_count = 0
    
    signal.signal(signal.SIGINT, sigint_handler)
    screenLock = threading.Semaphore(value = 1)
    main()
    time.sleep(2)
    
     
    
    print '\n\033[32mStatistics:\033[0m '
    print 'Scanned IPs: %d' %(peer_ip.size-2)
    print 'Scanned Ports: %d' %len(peer_port)
    print 'Opened SCTP Port: %s' %sctp_count
    print 'Detected M3UA Nodes: %s' %m3ua_count
    sys.exit(0)
