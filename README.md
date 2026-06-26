# Legacy Network Security Desktop Client (Swing GUI)

This subdirectory contains the standalone Java Swing desktop implementation of the port scanning and packet capture toolkit. As part of Phase 1 improvements, the core codebase has been optimized for thread safety, high performance, and banner grabbing.

---

## 🛠️ Phase 1 Optimizations Implemented

We resolved critical thread-safety and performance bugs present in the original desktop toolkit:
1. **Thread Pool Optimization (`ExecutorService`):** Replaced the inefficient, blocking "one thread per port" loop with a dedicated fixed thread pool of 50 threads, accelerating scanning speeds by up to 10x.
2. **EDT Safety (`SwingUtilities.invokeLater`):** All background thread status logs, progress bar state changes, and results are delegated to the Swing Event Dispatch Thread (EDT) to eliminate UI freezes and deadlock conditions.
3. **Active/Passive Banner Grabbing:** Added active socket probe requests (sending HTTP `HEAD` to ports 80/8080/443, and generic handshakes to database/mail ports) to force silent ports to greet and reveal version details.
4. **Input Validation:** Prevents bounds-exceeded crashes by validating input hostnames, port range parameters (1 - 65535), and timeouts.
5. **Abort Controller:** Added a "Stop Scan" button that terminates background executor jobs immediately.

---

## 📦 Directory Structure

```text
network-port-scanner
│
├── lib/                             # JNA and SLF4J dependencies for Packet Capture
│   ├── pcap4j-core.jar
│   ├── pcap4j-packetfactory-static.jar
│   ├── jna.jar
│   ├── slf4j-api.jar
│   └── slf4j-simple.jar
│
├── src/                             # Optimized source code files
│   ├── ScannerGUI.java              # EDT-safe GUI scanner
│   ├── PortScannerUtil.java         # Connection helper
│   ├── BannerGrabber.java           # Active header banner retriever
│   ├── ServiceMapper.java           # Logical port mapping
│   ├── NetworkScanner.java          # Subnet auto-discovery utility
│   └── PacketSniffer.java           # Live packet hook (Pcap4j wrapper)
```

---

## 🚀 Execution Guide

### Prerequisite: Install Npcap
To run the live Packet Sniffer, install Npcap in WinPcap-compatible mode from [npcap.com](https://npcap.com/).

### 1. Compile the Project
Open your command terminal in the desktop directory:
```bash
javac -cp "lib/*" src/*.java
```

### 2. Run the Port Scanner GUI
Execute the GUI executable:
```bash
java -cp "lib/*;src" ScannerGUI
```

### 3. Run the Subnet Auto-discovery CLI
Execute the host mapper:
```bash
java -cp "lib/*;src" NetworkScanner
```

### 4. Run the Packet Sniffer CLI
Execute the packet sniffer:
```bash
java -cp "lib/*;src" PacketSniffer
```

---

## ⚖️ Disclaimer
This tool is intended for educational network diagnostic demonstrations. Always secure prior authorization before executing scans against network hosts.
