package com.scanner.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.*;

import java.util.HashMap;
import java.util.Map;

@Service
public class ThreatIntelService {

    @Value("${api.abuseipdb.key:}")
    private String abuseIpDbKey;

    private final RestTemplate restTemplate = new RestTemplate();

    public Map<String, Object> getIpDetails(String ip) {
        // Fallback or local IPs mock handler
        if (ip.startsWith("127.") || ip.startsWith("192.168.") || ip.startsWith("10.") || abuseIpDbKey.isEmpty()) {
            return getSimulatedDetails(ip);
        }

        // Real API Call to AbuseIPDB
        try {
            String url = "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip + "&maxAgeInDays=90";
            HttpHeaders headers = new HttpHeaders();
            headers.set("Key", abuseIpDbKey);
            headers.set("Accept", "application/json");
            HttpEntity<String> entity = new HttpEntity<>(headers);

            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, entity, Map.class);
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> data = (Map<String, Object>) response.getBody().get("data");
                Map<String, Object> result = new HashMap<>();
                result.put("ip", data.get("ipAddress"));
                result.put("isPublic", data.get("isPublic"));
                result.put("ipVersion", data.get("ipVersion"));
                result.put("abuseConfidenceScore", data.get("abuseConfidenceScore"));
                result.put("countryCode", data.get("countryCode"));
                result.put("usageType", data.get("usageType"));
                result.put("isp", data.get("isp"));
                result.put("domain", data.get("domain"));
                result.put("totalReports", data.get("totalReports"));
                result.put("lastReportedAt", data.get("lastReportedAt"));
                result.put("isMocked", false);
                return result;
            }
        } catch (Exception e) {
            // Log warning and fallback
            System.err.println("API Query failed: " + e.getMessage() + ". Falling back to simulation.");
        }

        return getSimulatedDetails(ip);
    }

    private Map<String, Object> getSimulatedDetails(String ip) {
        Map<String, Object> mock = new HashMap<>();
        mock.put("ip", ip);
        mock.put("isPublic", !ip.startsWith("127.") && !ip.startsWith("192.168."));
        mock.put("ipVersion", 4);
        mock.put("isMocked", true);

        // Preconfigured popular lookup simulations
        if ("8.8.8.8".equals(ip)) {
            mock.put("abuseConfidenceScore", 0);
            mock.put("countryCode", "US");
            mock.put("usageType", "DNS Server");
            mock.put("isp", "Google LLC");
            mock.put("domain", "google.com");
            mock.put("totalReports", 0);
            mock.put("lastReportedAt", "N/A");
        } else if ("185.190.140.23".equals(ip)) {
            mock.put("abuseConfidenceScore", 95);
            mock.put("countryCode", "NL");
            mock.put("usageType", "Data Center");
            mock.put("isp", "Creanova Hosting Solutions Ltd");
            mock.put("domain", "creanovahost.net");
            mock.put("totalReports", 142);
            mock.put("lastReportedAt", "2026-06-26T14:22:10Z");
        } else {
            // Randomly generate details for unknown external IPs
            boolean isPrivate = ip.startsWith("127.") || ip.startsWith("192.168.") || ip.startsWith("10.");
            mock.put("abuseConfidenceScore", isPrivate ? 0 : Math.floor(Math.random() * 85));
            mock.put("countryCode", isPrivate ? "Local" : "US");
            mock.put("usageType", isPrivate ? "Intranet" : "Commercial");
            mock.put("isp", isPrivate ? "LAN Connection" : "Amazon Technologies");
            mock.put("domain", isPrivate ? "local.network" : "amazon.aws");
            mock.put("totalReports", isPrivate ? 0 : (int)(Math.random() * 50));
            mock.put("lastReportedAt", isPrivate ? "N/A" : "2026-06-26T12:00:00Z");
        }
        return mock;
    }
}
