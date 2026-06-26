import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class NetworkScanner {

    public static String getLocalSubnet() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface nif = interfaces.nextElement();
                if (nif.isLoopback() || !nif.isUp()) continue;
                for (InetAddress addr : Collections.list(nif.getInetAddresses())) {
                    if (addr instanceof java.net.Inet4Address) {
                        String ip = addr.getHostAddress();
                        if (!ip.startsWith("127.")) {
                            int lastDot = ip.lastIndexOf('.');
                            if (lastDot > 0) {
                                return ip.substring(0, lastDot + 1);
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return "192.168.1."; // fallback
    }

    public static void main(String[] args) {
        String subnet = getLocalSubnet();
        System.out.println("Auto-detected local subnet prefix: " + subnet);
        System.out.println("Scanning network concurrently...\n");

        ExecutorService executor = Executors.newFixedThreadPool(50);
        List<String> activeHosts = Collections.synchronizedList(new ArrayList<>());

        for (int i = 1; i < 255; i++) {
            final int hostNum = i;
            executor.submit(() -> {
                String host = subnet + hostNum;
                try {
                    InetAddress address = InetAddress.getByName(host);
                    if (address.isReachable(500)) {
                        System.out.println(host + " is ACTIVE");
                        activeHosts.add(host);
                    }
                } catch (Exception ignored) {}
            });
        }

        executor.shutdown();
        try {
            if (!executor.awaitTermination(30, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }

        System.out.println("\nScan complete. Discovered " + activeHosts.size() + " active host(s).");
    }
}