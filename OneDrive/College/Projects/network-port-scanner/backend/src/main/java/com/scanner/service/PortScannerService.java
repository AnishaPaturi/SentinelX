package com.scanner.service;

import com.scanner.model.ScanResult;
import com.scanner.repository.ScanResultRepository;
import com.scanner.util.BannerGrabber;
import com.scanner.util.PortScannerUtil;
import com.scanner.util.ServiceMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@Service
public class PortScannerService {

    @Autowired
    private ScanResultRepository scanResultRepository;

    public List<ScanResult> scanHost(String host, int startPort, int endPort, int timeoutMs) {
        List<ScanResult> results = Collections.synchronizedList(new ArrayList<>());
        ExecutorService executor = Executors.newFixedThreadPool(50);

        for (int port = startPort; port <= endPort; port++) {
            final int currentPort = port;
            executor.submit(() -> {
                boolean isOpen = PortScannerUtil.scanPort(host, currentPort, timeoutMs);
                if (isOpen) {
                    ScanResult result = new ScanResult();
                    result.setHost(host);
                    result.setPort(currentPort);
                    result.setState("OPEN");
                    
                    String serviceName = ServiceMapper.getService(currentPort);
                    result.setService(serviceName);
                    
                    String banner = BannerGrabber.grabBanner(host, currentPort, timeoutMs);
                    result.setBanner(banner);
                    
                    // Basic risk rating for modules 4 & 10
                    result.setRiskLevel(calculateRisk(currentPort, serviceName, banner));
                    result.setScanTime(LocalDateTime.now());
                    
                    scanResultRepository.save(result);
                    results.add(result);
                }
            });
        }

        executor.shutdown();
        try {
            executor.awaitTermination(1, TimeUnit.HOURS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return results;
    }

    public List<ScanResult> getHistory() {
        return scanResultRepository.findAll();
    }

    private String calculateRisk(int port, String service, String banner) {
        String serviceLower = service.toLowerCase();
        String bannerLower = banner != null ? banner.toLowerCase() : "";

        if (serviceLower.equals("telnet") || serviceLower.equals("ftp") || bannerLower.contains("smbv1")) {
            return "HIGH";
        }
        if (bannerLower.contains("apache/2.2") || bannerLower.contains("openssh/7.2")) {
            return "CRITICAL";
        }
        if (port == 3306 || port == 3389 || port == 1433 || port == 1521) {
            return "MEDIUM";
        }
        return "LOW";
    }
}
