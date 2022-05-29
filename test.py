#!/usr/bin/env python3

from scapy.all import *
from threading import Thread
import sys
import time

conf.layers.filter([IPv6, UDP, DNS])

program_port = 53

class Resolver(Thread):
    def __init__(self, verbose, condition):
        Thread.__init__(self)
        self.verbose = verbose
        self.condition = condition
    def sniffCallback(self, reason):
        if self.verbose:
            print(f'Started to sniff for {reason}')
        with self.condition:
            self.condition.notifyAll()

class DnsResolverA(Resolver):
    def __init__(self, verbose, wait_condition, start_condition, packet):
        Resolver.__init__(self, verbose, start_condition)
        self.packet = packet
        self.wait_condition = wait_condition
        self.start_condition = start_condition
    
    def run(self):
        with self.wait_condition:
            self.wait_condition.wait()
        request = sniff(filter="udp dst port 53000", iface="lo", count=1, started_callback=lambda: self.sniffCallback('A'))[0]
        self.packet[UDP].dport = request.sport
        send(self.packet, verbose=0)
        if self.verbose:
            print('Sent A packet')

class DnsResolverAAAA(Resolver):
    def __init__(self, verbose, client_condition, a_wait_condition, a_start_condition, packet, willSynthetize):
        Resolver.__init__(self, verbose, client_condition)
        self.packet = packet
        self.client_condition = client_condition
        self.a_wait_condition = a_wait_condition
        self.a_start_condition = a_start_condition
        self.willSynthetize = willSynthetize
    
    def run(self):
        request = sniff(filter="udp dst port 53000", iface="lo", count=1, started_callback=lambda: self.sniffCallback('AAAA'))[0]
        self.packet[UDP].dport = request.sport

        if self.willSynthetize:
            with self.a_wait_condition:
                self.a_wait_condition.notifyAll()
            
            with self.a_start_condition:
                self.a_start_condition.wait()

        send(self.packet, verbose=0)
        if self.verbose:
            print('Sent AAAA packet')

class DnsClient(Thread):
    def __init__(self, verbose, condition, packet, willNeedResolver):
        Thread.__init__(self)
        self.verbose = verbose
        self.packet = packet
        self.condition = condition
        self.willNeedResolver = willNeedResolver
        self.result = None
    
    def run(self):
        if self.willNeedResolver:
            with self.condition:
                self.condition.wait()
        sourcePort = RandShort()._fix()
        self.packet[UDP].sport = sourcePort
        self.packet[UDP].dport = program_port
        print(f'Sending client packet on port {sourcePort}')
        if self.willNeedResolver:
            self.result = sr1(self.packet, verbose=0)
            if self.verbose:
                print('Received answer packet')
        else:
            send(self.packet, verbose=0)

class DnsTest:
    destination_ip = '::1'
    verbose = False
    def __init__(self, name):
        self.name = name
    
    def requestHeader(self):
        return IPv6(dst=self.destination_ip) / UDP(sport=RandShort(), dport=program_port)

    def responseHeader(self):
        return IPv6(dst=self.destination_ip) / UDP(sport=53000, dport=program_port)
    
    def stubARequest(self):
        return self.requestHeader() / DNS(rd=1, qd=DNSQR(qname='dns64sec.test.', qtype='A'))

    def stubAAAARequest(self):
        return self.requestHeader() / DNS(rd=1, qd=DNSQR(qname='dns64sec.test.', qtype='AAAA'))
    
    def stubAFound(self):
        return self.responseHeader() / DNS(rd=1, qr=1, qd=DNSQR(qname='dns64sec.test.', qtype='AAAA'), ancount=1, an=DNSRR(rrname="dns64sec.test.", rdata='10.0.0.1'))
    
    def stubAAAAFound(self):
        return self.responseHeader() / DNS(rd=1, qr=1, qd=DNSQR(qname='dns64sec.test.', qtype='AAAA'), ancount=1, an=DNSRR(rrname='dns64sec.test.', type='AAAA', rdlen=16, rdata='::1'))
    
    def stubANotFound(self):
        return self.responseHeader() / DNS(rd=1, qr=1, qd=DNSQR(qname='dns64sec.test.', qtype='A'))
    
    def stubAAAANotFound(self):
        return self.responseHeader() / DNS(rd=1, qr=1, qd=DNSQR(qname='dns64sec.test.', qtype='AAAA'))
    
    def request(self):
        return None
    
    def firstResponse(self):
        return None
    
    def secondResponse(self):
        return None
    
    def result(self):
        return None

    def performPacketExchange(self):
        self.printTestHeader()

        client_condition = threading.Condition()
        a_wait_condition = threading.Condition()
        a_start_condition = threading.Condition()

        if self.firstResponse() is not None:
            aaaa_resolver = DnsResolverAAAA(self.verbose, client_condition, a_wait_condition, a_start_condition, self.firstResponse(), self.secondResponse() is not None)

        if self.secondResponse() is not None:
            a_resolver = DnsResolverA(self.verbose, a_wait_condition, a_start_condition, self.secondResponse())

        client = DnsClient(self.verbose, client_condition, self.request(), self.firstResponse() is not None)

        if self.secondResponse() is not None:
            a_resolver.start()
        
        start_time = time.time()

        client.start()

        if self.firstResponse() is not None:
            aaaa_resolver.start()

        if self.secondResponse() is not None:
            a_resolver.join()

        client.join()

        if self.firstResponse() is not None:
            aaaa_resolver.join()
        
        if client.result is not None and self.result() is not None:
            if bytes(client.result[DNS]) == bytes(self.result()[DNS]):
                print(f"Result is as expected, took {time.time() - start_time:.2f} s")
            else:
                print("Response packet does not match the expected")
                DNS(bytes(client.result[DNS])).show()
                DNS(bytes(self.result()[DNS])).show()
                sys.exit()
    
    def printTestHeader(self):
        print()
        print("#" * len(self.name))
        print(self.name)
        print("#" * len(self.name))

class DnsTest1(DnsTest):
    def __init__(self):
        super().__init__("AAAA request, AAAA not found, A found")

    def request(self):
        return self.stubAAAARequest()
    
    def firstResponse(self):
        return self.stubAAAANotFound()
    
    def secondResponse(self):
        return self.stubAFound()
    
    def result(self):
        base = self.stubAFound().copy()

        base[DNSRR].type = 'AAAA'
        base[DNSRR].rdata = '64:face::a00:1'

        return base

class DnsTest2(DnsTest):
    def __init__(self):
        super().__init__('AAAA request, AAAA not found, A not found')
    
    def request(self):
        return self.stubAAAARequest()
    
    def firstResponse(self):
        return self.stubAAAANotFound()
    
    def secondResponse(self):
        return self.stubANotFound()
    
    def result(self):
        return self.stubANotFound()

class DnsTest3(DnsTest):
    def __init__(self):
        super().__init__('AAAA request, AAAA found')
    
    def request(self):
        return self.stubAAAARequest()
    
    def firstResponse(self):
        return self.stubAAAAFound()
    
    def result(self):
        return self.stubAAAAFound()

class DnsTest4(DnsTest):
    def __init__(self):
        super().__init__('AAAA response')
    
    def request(self):
        return self.stubAAAANotFound()

class DnsTest5(DnsTest):
    def __init__(self):
        super().__init__('A request, A found')

    def request(self):
        return self.stubARequest()
    
    def firstResponse(self):
        return self.stubAFound()
    
    def result(self):
        return self.stubAFound()

class DnsTest6(DnsTest):
    def __init__(self):
        super().__init__('A request, A not found')
    
    def request(self):
        return self.stubARequest()
    
    def firstResponse(self):
        return self.stubANotFound()
    
    def result(self):
        return self.stubANotFound()

class HiradoTest(DnsTest):
    def __init__(self):
        super().__init__('hirado.hu')
    
    def request(self):
        return self.requestHeader() / DNS(rd=1, qd=DNSQR(qname="hirado.hu", qtype="AAAA"))
    
    def firstResponse(self):
        return dns_compress(self.responseHeader() / DNS(rd=1, qr=1, ancount=4, qd=DNSQR(qname="hirado.hu", qtype="AAAA"), an=DNSRR(rrname="hirado.hu", rdata="185.161.204.65")/DNSRR(rrname="hirado.hu", rdata="185.161.204.60")/DNSRR(rrname="hirado.hu", rdata="185.161.204.64")/DNSRR(rrname="hirado.hu", rdata="185.161.204.63")))
    
    def secondResponse(self):
        return self.firstResponse()
    
    def result(self):
        base = self.firstResponse().copy()

        newIps = ['64:face::b9a1:cc41', '64:face::b9a1:cc3c', '64:face::b9a1:cc40', '64:face::b9a1:cc3f']

        for i in range(base[DNS].ancount):
            dnsrr = base[DNS].an[i]

            dnsrr.type = 'AAAA'
            dnsrr.rdata = newIps[i]
        
        return base

def main():
    # TODO: Starting up the DNS daemon as part of the test
    for cls in DnsTest.__subclasses__():
        cls().performPacketExchange()

if __name__ == '__main__':
    main()