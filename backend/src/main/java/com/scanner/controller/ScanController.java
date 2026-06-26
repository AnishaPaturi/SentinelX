package com.scanner.controller;

import com.scanner.model.ScanResult;
import com.scanner.model.NetworkNode;
import com.scanner.model.PacketLog;
import com.scanner.model.IdsAlert;
import com.scanner.service.PortScannerService;
import com.scanner.service.NetworkDiscoveryService;
import com.scanner.service.PacketCaptureService;
import com.scanner.service.AiAssistantService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.HashMap;

@RestController
@RequestMapping("/api")
public class ScanController {

    @Autowired
    private PortScannerService portScannerService;

    @Autowired
    private NetworkDiscoveryService networkDiscoveryService;

    @Autowired
    private PacketCaptureService packetCaptureService;

    @Autowired
    private AiAssistantService aiAssistantService;

    @Autowired
    private com.scanner.service.ReportService reportService;

    @PostMapping("/ai/chat")
    public Map<String, String> chatWithAi(@RequestBody Map<String, String> request) {
        String userMsg = request.get("message");
        String reply = aiAssistantService.generateSecurityAdvice(userMsg);
        Map<String, String> response = new HashMap<>();
        response.put("response", reply);
        return response;
    }

    @GetMapping("/sniffer/packets")
    public List<PacketLog> getPackets() {
        return packetCaptureService.getPacketLogs();
    }

    @GetMapping("/sniffer/alerts")
    public List<IdsAlert> getAlerts() {
        return packetCaptureService.getAlerts();
    }

    @PostMapping("/sniffer/toggle")
    public boolean toggleSniffer() {
        packetCaptureService.toggleActive();
        return packetCaptureService.isActive();
    }

    @GetMapping("/sniffer/status")
    public boolean getSnifferStatus() {
        return packetCaptureService.isActive();
    }

    @GetMapping("/devices")
    public List<NetworkNode> getDiscoveredDevices() {
        return networkDiscoveryService.discoverDevices();
    }

    @PostMapping("/scan")
    public List<ScanResult> triggerScan(
            @RequestParam String host,
            @RequestParam(defaultValue = "1") int startPort,
            @RequestParam(defaultValue = "1024") int endPort,
            @RequestParam(defaultValue = "200") int timeout) {
        
        // Simple input validation to prevent out of bounds crashes
        if (startPort < 1 || startPort > 65535 || endPort < 1 || endPort > 65535 || startPort > endPort) {
            throw new IllegalArgumentException("Invalid port configuration.");
        }
        
        return portScannerService.scanHost(host, startPort, endPort, timeout);
    }

    @GetMapping("/history")
    public List<ScanResult> getHistory() {
        return portScannerService.getHistory();
    }

    @GetMapping(value = "/report/pdf", produces = org.springframework.http.MediaType.APPLICATION_PDF_VALUE)
    public org.springframework.http.ResponseEntity<org.springframework.core.io.InputStreamResource> downloadReport(@RequestParam String host) {
        java.io.ByteArrayInputStream bis = reportService.generatePdfReport(host);
        
        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.add("Content-Disposition", "attachment; filename=scan-report-" + host + ".pdf");
        
        return org.springframework.http.ResponseEntity
                .ok()
                .headers(headers)
                .contentType(org.springframework.http.MediaType.APPLICATION_PDF)
                .body(new org.springframework.core.io.InputStreamResource(bis));
    }
}
