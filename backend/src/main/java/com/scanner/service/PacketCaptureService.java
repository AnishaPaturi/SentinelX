package com.scanner.service;

import com.scanner.model.PacketLog;
import com.scanner.model.IdsAlert;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
public class PacketCaptureService {

    private final List<PacketLog> packetLogs = Collections.synchronizedList(new ArrayList<>());
    private final List<IdsAlert> alerts = Collections.synchronizedList(new ArrayList<>());
    private boolean active = true;

    private ExecutorService snifferExecutor;
    private PcapHandle pcapHandle;
    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");

    @PostConstruct
    public void startCapture() {
        snifferExecutor = Executors.newSingleThreadExecutor();
        snifferExecutor.submit(() -> {
            try {
                // Try initializing Pcap4J capture
                List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
                if (interfaces == null || interfaces.isEmpty()) {
                    throw new Exception("No network interfaces found. Launching simulation.");
                }

                // Use the first active interface
                PcapNetworkInterface nif = interfaces.get(0);
                int snapLen = 65536;
                int timeout = 10;

                pcapHandle = nif.openLive(
                        snapLen,
                        PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                        timeout
                );

                pcapHandle.loop(-1, (PacketListener) packet -> {
                    if (!active) return;

                    IpV4Packet ipv4 = packet.get(IpV4Packet.class);
                    if (ipv4 != null) {
                        String srcIP = ipv4.getHeader().getSrcAddr().getHostAddress();
                        String dstIP = ipv4.getHeader().getDstAddr().getHostAddress();
                        String protocol = ipv4.getHeader().getProtocol().name();
                        int length = packet.length();
                        String info = "TCP flag sequence transaction";

                        if ("TCP".equalsIgnoreCase(protocol)) {
                            info = "TCP handshake packet seq=" + (int)(Math.random()*1000);
                        } else if ("UDP".equalsIgnoreCase(protocol)) {
                            info = "UDP Datagram payload transaction";
                        }

                        addPacket(protocol, srcIP, dstIP, length, info);

                        // Basic IDS Heuristics on real packets
                        checkIdsHeuristics(srcIP, protocol, length);
                    }
                });

            } catch (Throwable t) {
                System.err.println("Pcap4J initialization failed (" + t.getMessage() + "). Falling back to dynamic simulated sniffer.");
                runSimulationLoop();
            }
        });
    }

    private void runSimulationLoop() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                Thread.sleep(1000); // 1 packet per second
                if (!active) continue;

                // Dynamic packet simulation
                String[] protocols = {"TCP", "UDP", "HTTP", "DNS", "ARP", "ICMP", "SSH", "HTTPS"};
                String protocol = protocols[(int)(Math.random() * protocols.length)];
                
                String[] localIPs = {"192.168.1.1", "192.168.1.12", "192.168.1.45", "192.168.1.100", "192.168.1.15"};
                String[] externalIPs = {"8.8.8.8", "142.250.190.46", "185.190.140.23", "23.45.67.89"};
                
                String src = localIPs[(int)(Math.random() * localIPs.length)];
                String dst = Math.random() > 0.4 
                        ? externalIPs[(int)(Math.random() * externalIPs.length)]
                        : localIPs[(int)(Math.random() * localIPs.length)];
                
                int len = (int)(Math.random() * 1200) + 40;
                
                String info = "Generic communication";
                if ("HTTP".equals(protocol)) info = "GET /index.html HTTP/1.1";
                else if ("HTTPS".equals(protocol)) info = "Client Hello TLSv1.3";
                else if ("DNS".equals(protocol)) info = "Standard query A google.com";
                else if ("ARP".equals(protocol)) info = "Who has " + dst + "? Tell " + src;
                else if ("ICMP".equals(protocol)) info = "Echo (ping) request";
                else if ("SSH".equals(protocol)) info = "SSH-2.0-OpenSSH_8.2p1";

                addPacket(protocol, src, dst, len, info);

                // Dynamic IDS Alarm generator (5% probability per second)
                if (Math.random() > 0.95) {
                    triggerSimulatedAlert(externalIPs[(int)(Math.random() * externalIPs.length)]);
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void addPacket(String protocol, String src, String dst, int len, String info) {
        String time = LocalTime.now().format(timeFormatter);
        PacketLog log = new PacketLog(time, protocol, src, dst, len, info);
        
        synchronized (packetLogs) {
            packetLogs.add(0, log);
            if (packetLogs.size() > 50) {
                packetLogs.remove(packetLogs.size() - 1);
            }
        }
    }

    private void triggerSimulatedAlert(String sourceIp) {
        String time = LocalTime.now().format(timeFormatter);
        String[] attacks = {"Port Scan", "SYN Flood", "ARP Spoofing", "Brute Force Attempt"};
        String attack = attacks[(int)(Math.random() * attacks.length)];
        
        String severity = "high";
        String desc = "Abnormal traffic flags detected.";
        String rec = "Monitor network socket interfaces.";

        if ("Port Scan".equals(attack)) {
            severity = "medium";
            desc = "Rapid sequential port connection requests detected.";
            rec = "Configure local firewall to rate-limit connections.";
        } else if ("SYN Flood".equals(attack)) {
            severity = "high";
            desc = "High rate of TCP SYN packets without finishing handshake.";
            rec = "Enable SYN Cookies on the host operating system.";
        } else if ("ARP Spoofing".equals(attack)) {
            severity = "critical";
            desc = "Duplicate IP associations detected for Gateway (192.168.1.1).";
            rec = "Configure Static ARP tables and implement dynamic ARP inspection.";
        } else if ("Brute Force Attempt".equals(attack)) {
            severity = "high";
            desc = "Repeated failed SSH logins detected from external IP.";
            rec = "Install Fail2ban and temporarily block offender IP.";
        }

        IdsAlert alert = new IdsAlert(System.currentTimeMillis(), time, sourceIp, attack, severity, desc, rec);
        synchronized (alerts) {
            alerts.add(0, alert);
            if (alerts.size() > 50) {
                alerts.remove(alerts.size() - 1);
            }
        }
    }

    private void checkIdsHeuristics(String sourceIp, String protocol, int length) {
        // High length packet alert (Threshold = 1500 bytes)
        if (length > 1500 && Math.random() > 0.8) {
            String time = LocalTime.now().format(timeFormatter);
            IdsAlert alert = new IdsAlert(
                    System.currentTimeMillis(),
                    time,
                    sourceIp,
                    "Oversized Packet",
                    "medium",
                    "Packet size exceeds standard MTU limits (length: " + length + " bytes).",
                    "Inspect packet payloads for fragmentation attacks."
            );
            synchronized (alerts) {
                alerts.add(0, alert);
                if (alerts.size() > 50) {
                    alerts.remove(alerts.size() - 1);
                }
            }
        }
    }

    public List<PacketLog> getPacketLogs() {
        return new ArrayList<>(packetLogs);
    }

    public List<IdsAlert> getAlerts() {
        return new ArrayList<>(alerts);
    }

    public boolean isActive() {
        return active;
    }

    public void toggleActive() {
        this.active = !this.active;
    }

    @PreDestroy
    public void stopSniffer() {
        if (pcapHandle != null) {
            try {
                pcapHandle.breakLoop();
            } catch (Exception ignored) {}
            pcapHandle.close();
        }
        if (snifferExecutor != null) {
            snifferExecutor.shutdownNow();
        }
    }
}
