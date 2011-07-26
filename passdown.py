#!/usr/bin/env python
#encoding: utf-8

# License: any version of the currently available GNU General Public License,
#          choose which fits best. non commercial use only
########



# Imports
###############################################################################
from sys import argv, exit, path
path.append("modules/") #XXX could we do this in a cooler way to import modules? :)

try:
    from scapy.all import sniff, Packet, Ether, IP, IPv6, TCP, Raw, hexdump, bind_layers, rdpcap, wrpcap
except ImportError:
    print "[E] Could not import scapy, please install scapy first. See README for instructions on how to do so."
    exit(1)


import socket # for root-error bla
from re import match, IGNORECASE # module-finder

from os import mkdir
from os.path import isdir, exists


from time import strftime # for filenames

import logging

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from http import Http #  das hier dynamisch wär cooler
PROTOCOLS = [Http]


# Main stuff
############################################################################

"""
TCP Flags:
 (000. .... .... = Reserved)
  ...0 .... .... = Nonce
  .... 0... .... = Congestion Window Reduced (CWR)
  .... .0.. .... = ECN-Echo
  .... ..0. .... = Urgent
  .... ...0 .... = Acknowledgement (ACK)
  .... .... 0... = Push
  .... .... .0.. = Reset (RST)
  .... .... ..0. = Syn (SYN)
  .... .... ...0 = Fin (FIN)
"""

FIN=0x1
SYN=0x2
RST=0x4
PSH=0x8
ACK=0x10

def hasflag(inp, flag):
    """ check if given input (bitmask as int, tcp packet) has specific flag set
        e.g. hasflag(SYN|ACK,ACK) -> True.
    """
    if isinstance(inp, int):
        return inp & flag == flag
    elif isinstance(inp, Packet):
        if inp.haslayer(TCP):
            return inp[TCP].flags & flag == flag
        else:
            raise ValueError("Cannot get flags for" + inp.summary())
            # should we just return False here? dunno :<

class Stream:
    """ Stream object combines TCP packets to a single stream(!) of data sent
        by client and server
    """
    def __init__(self, synpacket):
        if not hasflag(synpacket, SYN):
            # first packet has to have syn-flag only
            # we only check if synflag is generally set.
            # instead we should check if flags == SYN
            raise ValueError("First packet does not contain SYN")
        self._synpacket = synpacket
        self.clientdata = StringIO()
        self.serverdata = StringIO()

    def synack(self, packet):
        if not hasflag(packet, (SYN|ACK)):
            raise ValueError("SYNACK packet does not have SYN and ACK set")
        if hasattr(self, '_ack'):
            raise ValueError("We already have an established Handshake. No SYN-ACK accepted")
        self._synack = packet

    def ack(self, packet):
        if not hasflag(packet, ACK):
            raise ValueError("Ack Packet does not say 'ACK'")
        if not hasattr(self, '_synack'):
            raise ValueError("We dont have SYNACK yet. Why ACKing?")
        self._ack = packet
        self.established = True

    def fitsinto(self, packet):
        """ check if specified packet fits into this stream """
        if (packet.dst == self._synpacket.dst) and \
            (packet.src == self._synpacket.src) and \
            (packet.dport == self._synpacket.dport) and \
            (packet.sport == self._synpacket.sport):
                return 1 # Same direction (Client->Server)
        if (packet.dst == self._synpacket.src) and \
            (packet.src == self._synpacket.dst) and \
            (packet.dport == self._synpacket.sport) and \
            (packet.sport == self._synpacket.dport):
                return 2 # Opposite Direction (Server->Client)
        return False

    def add_data(self, packet):
        if self.fitsinto(packet) == 1:
            self.clientdata.write(packet.load)
        elif self.fitsinto(packet) == 2:
            self.serverdata.write(packet.load)

    def push(self, packet):
        pass

    def finack(self, packet):
        """ We expect a FIN-Packet from *both* parties.
            fitsinto for client->server is 1 and server->client is 2
            ORing the both values to the current status means that we need each
            direction has to be present for it to be 3. Pretty cool, huh?
        """
        if not hasattr(self, '_finstatus'):
            self._finstatus = self.fitsinto(packet)
        elif self._finstatus == 1 or self._finstatus == 2:
            self._finstatus |= self.fitsinto(packet)
        if self._finstatus == 3:
            self.end()

    def end(self):
        if not isdir('output'):
            mkdir('output')
        #XXX use tempfile.mkstemp
        #fname_c = 'output/client_%s-%s_port%s.dat' % (self._synpacket.src, self._synpacket.dst, self._synpacket.dport)
        #while exists(fname_c):
        #    fname_c += '1'
        #with open(fname_c, 'wb') as f:
        #    f.write(self.clientdata.getvalue())

        #fname_s = 'output/server_%s-%s_port%s.dat' % (self._synpacket.dst, self._synpacket.src, self._synpacket.dport)
        #while exists(fname_s):
        #    fname_s += '1'
        #with open(fname_s, 'wb') as f:
        #    f.write(self.serverdata.getvalue())

        for protocol in PROTOCOLS:
            if match(protocol.regex, self.serverdata.getvalue()):
                logging.debug("Known protocol detected: "+ protocol.name)
                protocol(self.serverdata.getvalue(), self.clientdata.getvalue())
        self.clientdata.close()
        self.serverdata.close()
        #print "Wrote to %s and %s" % (fname_c, fname_s)



class StreamSorting:
    def __init__(self):
        self.num = 0
        self.streams = []
        self.packets = []
    def addpacket(self, p):
        """ called for each packet """
        self.packets.append(p)
        self.num += 1
        if p.haslayer(Ether):
            if p.haslayer(IP):
                p = p[IP] # Inception! :)
            elif p.haslayer(IPv6):
                p = p[IPv6] # ..
        if not p.haslayer(TCP):
            return
        logging.debug("[%s] %s" % (self.num, p.summary()))  #"|| Flags:", p[TCP].flags
        if hasflag(p, SYN) and not hasflag(p, ACK): #SYN gesetzt, aber ACK nicht.
            # falsch. sollten prüfen ob NUR syn gesetzt ist.
            self.streams.append( Stream(p) )
            logging.debug("<<NewStream>>")
        elif hasflag(p, (SYN|ACK)): # SYN und ACK gesetzt
            for stream in self.streams:
                if stream.fitsinto(p) and not hasattr(stream, '_synack'):
                    stream.synack(p)
                    logging.debug("<<StreamUpdate>>")
        elif hasflag(p, ACK) and not hasflag(p, SYN): # ACK gesetzt. SYN nicht.
            for stream in self.streams:
                if stream.fitsinto(p) and not hasattr(stream, '_ack'):
                    stream.ack(p)
                    logging.debug("<<StreamUpdated: Handshake Complete>>")
        #elif p[TCP].flags == S2F['PSHACK']:
        #    for stream in self.streams:
        #        if stream.fitsinto(p) and stream.established:
        #            stream.push(p)
        #            print "<<PUSHING>>",
        if p[TCP].haslayer(Raw):
            for stream in self.streams:
                if stream.fitsinto(p) and stream.established:
                    stream.add_data(p)
        if hasflag(p, (FIN|ACK)): #FIN und ACK gesetzt
            for stream in self.streams:
                if stream.fitsinto(p) and stream.established:
                    stream.finack(p)




def usage():
    print "usage: %s [file]\nSniff for tcp-packets on port 80 (requires root)\n\nfile\tRead packets from file instead of sniffing.\n" % argv[0]


if __name__ == '__main__':
    s = StreamSorting()
    if '-d' in argv:
        # lame option handling
        del(argv[argv.index('-d') ])
        logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)

    if len(argv) == 2:
        logging.info("Reading packets from "+ argv[1])
        try:
            packets = rdpcap(argv[1])
            logging.info("%s Packets" % len(packets))
            for packet in packets:
                s.addpacket(packet)
        except Exception, err:
            logging.error(err)
            exit(1)
    elif len(argv) == 1:
        try:
            logging.info("Sniffing on port 80")
            sniff(filter="tcp and port 80", prn=s.addpacket)
            # capture infinitely, handle each packet in StreamSorting class
        except socket.error, err:
            logging.error("Sniffing requires root privileges, try ``sudo %s''" % argv[0])
            logging.error("Exit.")
        except KeyboardInterrupt:
            logging.error("Had %s packets sniffed when called for exit" % len(s.packets))
            fname = strftime('%Y%m%d_%H-%M') + '.cap'
            logging.error("Writing to %s" % fname)
            wrpcap(fname, s.packets)
            exit(1)
    else:
        usage()



