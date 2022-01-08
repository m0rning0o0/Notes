# -*- coding: utf-8 -*-
#!/usr/bin/env python3

"""
File Name: GetNTLMv2.py
Author: M0rning0o0
Original Author: 3gStudent
Description:
  Get NTLMv2 Hash from .pcap file with python3. Tested in window 10 with python 3.8.1.
"""

try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    # This import works from the project directory
    import scapy_http.http
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers import http

packets = scapy.rdpcap('test.pcap')
Num = 1
for p in range(len(packets)):
    try:
        if packets[p]['TCP'].dport == 445:
            packet = packets[p]
            # print(packet.show())
            TCPPayload = packets[p]['Raw'].load

            if TCPPayload.find(b'NTLMSSP') != -1:
                if len(packets[p]["TCP"].payload) > 500:
                    print("----------------------------------Hashcat NTLMv2 No.%s----------------------------------" % (
                        Num))
                    Num = Num + 1
                    print("PacketNum: %d" % (p + 1))
                    print("src: %s" % (packets[p]['IP'].src))
                    print("dst: %s" % (packets[p]['IP'].dst))
                    Flag = TCPPayload.find(b'NTLMSSP')

                    ServerTCPPayload = packets[p - 1]['Raw'].load

                    ServerFlag = ServerTCPPayload.find(b'NTLMSSP')
                    try:
                        ServerChallenge = ServerTCPPayload[ServerFlag + 24:ServerFlag + 24 + 8].hex()
                    except:
                        raise
                    print("ServerChallenge: %s" % (ServerChallenge))

                    DomainLength1 = int(TCPPayload[Flag + 28:Flag + 28 + 1].hex(), 16)
                    DomainLength2 = int(TCPPayload[Flag + 28 + 1:Flag + 28 + 1 + 1].hex(), 16) * 256
                    DomainLength = DomainLength1 + DomainLength2
                    DomainOffset = int(TCPPayload[Flag + 31 + 4:Flag + 31:-1].hex(), 16)
                    # print DomainLength
                    DomainNameUnicode = TCPPayload[Flag + DomainOffset:Flag + DomainOffset + DomainLength]
                    DomainName = [chr(DomainNameUnicode[i]) for i in range(len(DomainNameUnicode)) if i % 2 == 0]
                    DomainName = ''.join(DomainName)
                    print("DomainName: %s" % (DomainName))

                    UserNameLength1 = int(TCPPayload[Flag + 36:Flag + 36 + 1].hex(), 16)
                    UserNameLength2 = int(TCPPayload[Flag + 36 + 1:Flag + 36 + 1 + 1].hex(), 16) * 256
                    UserNameLength = UserNameLength1 + UserNameLength2
                    UserNameOffset = int(TCPPayload[Flag + 39 + 4:Flag + 39:-1].hex(), 16)
                    # print UserNameLength
                    UserNameUnicode = TCPPayload[Flag + UserNameOffset:Flag + UserNameOffset + UserNameLength]
                    UserName = [chr(UserNameUnicode[i]) for i in range(len(UserNameUnicode)) if i % 2 == 0]
                    UserName = ''.join(UserName)
                    print("UserName: %s" % (UserName))

                    NTLMResPonseLength1 = int(TCPPayload[Flag + 20:Flag + 20 + 1].hex(), 16)
                    NTLMResPonseLength2 = int(TCPPayload[Flag + 20 + 1:Flag + 20 + 1 + 1].hex(), 16) * 256
                    NTLMResPonseLength = NTLMResPonseLength1 + NTLMResPonseLength2
                    NTLMResponseOffset = int(TCPPayload[Flag + 23 + 4:Flag + 23:-1].hex(), 16)
                    # print NTLMResPonseLength
                    NTLMResPonse = TCPPayload[
                                   Flag + NTLMResponseOffset:Flag + NTLMResponseOffset + NTLMResPonseLength].hex()
                    # print NTLMResPonse
                    print("%s::%s:%s:%s:%s" % (
                        UserName, DomainName, ServerChallenge, NTLMResPonse[:32], NTLMResPonse[32:]))

    except:
        pass
