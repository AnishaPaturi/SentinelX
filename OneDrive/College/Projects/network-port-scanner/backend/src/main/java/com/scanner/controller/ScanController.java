package com.scanner.controller;

import com.scanner.model.ScanResult;
import com.scanner.service.PortScannerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class ScanController {

    @Autowired
    private PortScannerService portScannerService;

    @Autowired
    private com.scanner.service.ReportService reportService;

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
