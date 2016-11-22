onesixtyone
===========

[![Build Status](https://travis-ci.org/trailofbits/onesixtyone.svg)](https://travis-ci.org/trailofbits/onesixtyone)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/10906/badge.svg)](https://scan.coverity.com/projects/onesixtyone)

The SNMP protocol is a stateless, datagram oriented protocol. An SNMP scanner is a program that sends SNMP requests to multiple IP addresses, trying different community strings and waiting for a reply. Unfortunately SNMP servers don't respond to requests with invalid community strings and the underlying UDP protocol does not reliably report closed UDP ports. This means that 'no response' from the probed IP address can mean either of the following:

* machine unreachable
* SNMP server not running
* invalid community string
* the response datagram has not yet arrived

The approach taken by most SNMP scanners is to send the request, wait for n seconds and assume that the community string is invalid. If only 1 of every hundred scanned IP addresses responds to the SNMP request, the scanner will spend 99\*n seconds waiting for replies that will never come. This makes traditional SNMP scanners very inefficient.

onesixtyone takes a different approach to SNMP scanning. It takes advantage of the fact that SNMP is a connectionless protocol and sends all SNMP requests as fast as it can. Then the scanner waits for responses to come back and logs them, in a fashion similar to Nmap ping sweeps. By default onesixtyone waits for 10 milliseconds between sending packets, which is adequate for 100MBs switched networks. The user can adjust this value via the -w command line option. If set to 0, the scanner will send packets as fast as the kernel would accept them, which may lead to packet drop.

Running onesixtyone on a class B network (switched 100MBs with 1Gbs backbone) with -w 10 gives us a performance of 3 seconds per class C, with no dropped packets. All 65536 IP addresses were scanned in less than 13 minutes. onesixtyone sends a request for the system.sysDescr.0 value, which is present on almost all SNMP enabled devices. This returned value gives us a description of the system software running on the device. Here is an excerpt of a log file:

```
192.168.120.92 [1234] HP ETHERNET MULTI-ENVIRONMENT,ROM A.05.03,JETDIRECT,
JD24,EEPROM A.05.05
130.160.108.146 [public] Hardware: x86 Family 15 Model 0 Stepping 10 AT/AT
COMPATIBLE - Software: Windows 2000 Version 5.0 (Build 2195 Uniprocessor Free)
192.168.112.64 [public] Power Macintosh, hardware type 406; MacOS 9.0;
OpenTransport 2.5.2
192.168.104.254 [public] Novell NetWare 4.11  August 22, 1996
192.168.112.83 [public] Macintosh Quadra 650, System Software 7.1 
192.168.244.210 [public] RICOH Aficio 850 / RICOH Network Printer D model
192.168.240.39 [public] Cisco Systems WS-C5000
192.168.244.103 [public] HPJ3210A AdvanceStack 10BT Switching Hub Management
Module, ROM A.01.02, EEPROM A.01.01, HW A.01.00
```

### Authors

onesixtyone was designed and implemented by Alex Sotirov (alex@trailofbits.com).
