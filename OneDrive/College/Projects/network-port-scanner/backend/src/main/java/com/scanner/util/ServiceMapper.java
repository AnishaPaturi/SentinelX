package com.scanner.util;

import java.util.HashMap;
import java.util.Map;

public class ServiceMapper {
    private static final Map<Integer, String> services = new HashMap<>();

    static {
        services.put(21, "FTP");
        services.put(22, "SSH");
        services.put(23, "Telnet");
        services.put(25, "SMTP");
        services.put(53, "DNS");
        services.put(80, "HTTP");
        services.put(110, "POP3");
        services.put(143, "IMAP");
        services.put(443, "HTTPS");
        services.put(1433, "MSSQL");
        services.put(1521, "Oracle");
        services.put(3306, "MySQL");
        services.put(3389, "RDP");
        services.put(5432, "PostgreSQL");
        services.put(8080, "HTTP-Alt");
    }

    public static String getService(int port) {
        return services.getOrDefault(port, "Unknown");
    }
}
