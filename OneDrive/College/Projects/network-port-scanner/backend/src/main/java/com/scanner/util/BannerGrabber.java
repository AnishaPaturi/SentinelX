package com.scanner.util;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

public class BannerGrabber {

    public static String grabBanner(String host, int port, int timeoutMs) {
        // Passive read
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            
            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[1024];
            
            int bytesRead = in.read(buffer);
            if (bytesRead > 0) {
                return new String(buffer, 0, bytesRead).trim();
            }
        } catch (Exception ignored) {}

        // Active probing for HTTP
        if (port == 80 || port == 8080 || port == 443) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), timeoutMs);
                socket.setSoTimeout(timeoutMs);
                
                OutputStream out = socket.getOutputStream();
                out.write("HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n".getBytes());
                out.flush();
                
                InputStream in = socket.getInputStream();
                byte[] buffer = new byte[1024];
                int bytesRead = in.read(buffer);
                if (bytesRead > 0) {
                    String res = new String(buffer, 0, bytesRead).trim();
                    for (String line : res.split("\r\n")) {
                        if (line.toLowerCase().startsWith("server:")) {
                            return line.substring(7).trim();
                        }
                    }
                    return res.split("\r\n")[0];
                }
            } catch (Exception ignored) {}
        }

        // Active generic carriage return probe
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            
            OutputStream out = socket.getOutputStream();
            out.write("\r\n".getBytes());
            out.flush();
            
            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[1024];
            int bytesRead = in.read(buffer);
            if (bytesRead > 0) {
                return new String(buffer, 0, bytesRead).trim();
            }
        } catch (Exception ignored) {}

        return "No banner";
    }
}
