package com.scanner.util;

import java.net.InetSocketAddress;
import java.net.Socket;

public class PortScannerUtil {
    public static boolean scanPort(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
