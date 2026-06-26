# Network Security Toolkit (Java)

A **Java-based cybersecurity and computer networks toolkit** that provides multiple utilities for analyzing and monitoring network activity.
The project demonstrates concepts such as **port scanning, packet sniffing, network discovery, and service detection** using Java socket programming and the **Pcap4J packet capture library**.

---

## Features

### 1. Port Scanner

Scans a target host to identify open ports.

* Multithreaded port scanning
* Detects common services (HTTP, SSH, FTP, etc.)
* Fast scanning using Java sockets

Example output:

Port 22 → OPEN (SSH)
Port 80 → OPEN (HTTP)
Port 443 → OPEN (HTTPS)

---

### 2. Banner Grabber

Attempts to retrieve service banners from open ports to identify running server software.

Example:

Port 80 → Apache Server
Port 21 → vsFTPd

---

### 3. Network Scanner

Scans the local network to detect active devices.

Example:

192.168.0.1 → ACTIVE
192.168.0.5 → ACTIVE
192.168.0.12 → ACTIVE

---

### 4. Packet Sniffer

Captures live network packets and extracts useful information.

Information captured:

* Source IP address
* Destination IP address
* Protocol type (TCP / UDP / ICMP)
* Packet length

Example:

192.168.0.2 → 142.250.183.14 → TCP → 74 bytes

---

## Technologies Used

* Java
* Socket Programming
* Multithreading
* Pcap4J
* Npcap
* Swing (GUI)

---

## Project Structure

network-port-scanner
│
├── lib (external libraries)
│   ├── pcap4j-core.jar
│   ├── pcap4j-packetfactory-static.jar
│   ├── jna.jar
│   ├── slf4j-api.jar
│   └── slf4j-simple.jar
│
├── src
│   ├── BannerGrabber.java
│   ├── NetworkScanner.java
│   ├── PacketSniffer.java
│   ├── PortScannerUtil.java
│   ├── ScannerGUI.java
│   └── ServiceMapper.java
│
└── screenshots

---

## Installation

### 1. Install Npcap (Required for packet capture)

Download from:
https://npcap.com/

During installation enable:

Install Npcap in WinPcap API-compatible mode

---

### 2. Compile the Project

Open terminal in the project folder:

javac -cp "lib/*" src/*.java

---

### 3. Run the Packet Sniffer

java -cp "lib/*;src" PacketSniffer

---

### 4. Run the GUI Port Scanner

java -cp "lib/*;src" ScannerGUI

---

## Learning Outcomes

This project demonstrates:

* TCP/IP networking concepts
* Network reconnaissance techniques
* Packet capture and analysis
* Java socket programming
* Multithreaded network scanning
* Cybersecurity fundamentals

---

## Use Cases

* Educational network security demonstrations
* Understanding packet-level communication
* Learning penetration testing basics
* Studying TCP/IP protocols

---

## Disclaimer

This tool is intended **for educational purposes only**.
Do not use it to scan or monitor networks without permission.

---

## Author

Anisha Paturi
Computer Science Engineering Student
