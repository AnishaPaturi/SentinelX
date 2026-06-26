import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;

import java.util.List;

public class PacketSniffer {

    public static void main(String[] args) throws Exception {

        System.out.println("Listing network interfaces...\n");

        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();

        if (interfaces == null || interfaces.isEmpty()) {
            System.out.println("No network interfaces found.");
            return;
        }

        int i = 0;
        for (PcapNetworkInterface nif : interfaces) {
            System.out.println(i + ": " + nif.getName() + " - " + nif.getDescription());
            i++;
        }

        System.out.print("\nEnter the network interface index to capture packets (0 to " + (interfaces.size() - 1) + "): ");
        int selectedIndex = 0;
        try (java.util.Scanner scanner = new java.util.Scanner(System.in)) {
            if (scanner.hasNextInt()) {
                selectedIndex = scanner.nextInt();
            } else {
                System.out.println("Invalid index. Defaulting to index 0.");
            }
        } catch (Exception e) {
            System.out.println("Error reading index. Defaulting to index 0.");
        }

        if (selectedIndex < 0 || selectedIndex >= interfaces.size()) {
            System.out.println("Selected index out of range. Defaulting to index 0.");
            selectedIndex = 0;
        }

        PcapNetworkInterface nif = interfaces.get(selectedIndex);
        System.out.println("Selected network interface: " + nif.getName());

        int snapLen = 65536;
        int timeout = 10;

        PcapHandle handle =
                nif.openLive(
                        snapLen,
                        PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                        timeout
                );

        System.out.println("\nStarting packet capture...\n");

        PacketListener listener = packet -> {

            IpV4Packet ipv4 = packet.get(IpV4Packet.class);

            if (ipv4 != null) {

                String srcIP = ipv4.getHeader().getSrcAddr().getHostAddress();
                String dstIP = ipv4.getHeader().getDstAddr().getHostAddress();

                String protocol = ipv4.getHeader().getProtocol().name();

                int length = packet.length();

                System.out.println(
                        srcIP + "  →  " + dstIP + "  →  " + protocol + "  →  " + length + " bytes"
                );
            }

        };

        handle.loop(-1, listener);

        handle.close();
    }
}