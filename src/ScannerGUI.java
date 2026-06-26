import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.InetAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class ScannerGUI {

    private JFrame frame;
    private JTextField ipField;
    private JTextField startPortField;
    private JTextField endPortField;
    private JTextField timeoutField;
    private JButton scanButton;
    private JButton stopButton;
    private JProgressBar progressBar;
    private JTextArea resultArea;
    
    private ExecutorService executor;
    private final AtomicBoolean isScanning = new AtomicBoolean(false);

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignored) {}
            new ScannerGUI().createAndShowGUI();
        });
    }

    public void createAndShowGUI() {
        frame = new JFrame("Network Security Port Scanner");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(550, 500);
        frame.setMinimumSize(new Dimension(500, 400));
        frame.setLocationRelativeTo(null);

        // Main Panel
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(15, 15, 15, 15));

        // Form Panel
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // IP Label and Field
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.2;
        formPanel.add(new JLabel("Target IP/Host:"), gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 0.8;
        gbc.gridwidth = 3;
        ipField = new JTextField("127.0.0.1");
        formPanel.add(ipField, gbc);

        // Reset gridwidth for next rows
        gbc.gridwidth = 1;

        // Start Port
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.2;
        formPanel.add(new JLabel("Start Port:"), gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 0.3;
        startPortField = new JTextField("1");
        formPanel.add(startPortField, gbc);

        // End Port
        gbc.gridx = 2; gbc.gridy = 1; gbc.weightx = 0.2;
        formPanel.add(new JLabel("End Port:"), gbc);
        gbc.gridx = 3; gbc.gridy = 1; gbc.weightx = 0.3;
        endPortField = new JTextField("1024");
        formPanel.add(endPortField, gbc);

        // Timeout and Threads
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0.2;
        formPanel.add(new JLabel("Timeout (ms):"), gbc);
        gbc.gridx = 1; gbc.gridy = 2; gbc.weightx = 0.3;
        timeoutField = new JTextField("200");
        formPanel.add(timeoutField, gbc);

        // Controls Panel
        JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        scanButton = new JButton("Start Scan");
        stopButton = new JButton("Stop Scan");
        stopButton.setEnabled(false);
        controlsPanel.add(scanButton);
        controlsPanel.add(stopButton);

        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 4;
        gbc.insets = new Insets(10, 5, 5, 5);
        formPanel.add(controlsPanel, gbc);

        mainPanel.add(formPanel, BorderLayout.NORTH);

        // Results and Progress Panel
        JPanel resultsPanel = new JPanel(new BorderLayout(5, 5));
        
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        
        resultArea = new JTextArea();
        resultArea.setEditable(false);
        resultArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(resultArea);

        resultsPanel.add(progressBar, BorderLayout.NORTH);
        resultsPanel.add(scrollPane, BorderLayout.CENTER);

        mainPanel.add(resultsPanel, BorderLayout.CENTER);

        frame.add(mainPanel);

        // Action Listeners
        scanButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                startScanning();
            }
        });

        stopButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                stopScanning();
            }
        });

        frame.setVisible(true);
    }

    private void startScanning() {
        String host = ipField.getText().trim();
        if (host.isEmpty()) {
            JOptionPane.showMessageDialog(frame, "Please enter a target IP or hostname.", "Input Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Validate IP/Host reachable
        try {
            InetAddress.getByName(host);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(frame, "Invalid hostname or IP address.", "Input Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        int startPort, endPort, timeout;
        try {
            startPort = Integer.parseInt(startPortField.getText().trim());
            endPort = Integer.parseInt(endPortField.getText().trim());
            timeout = Integer.parseInt(timeoutField.getText().trim());
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(frame, "Ports and timeout must be valid integers.", "Input Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (startPort < 1 || startPort > 65535 || endPort < 1 || endPort > 65535) {
            JOptionPane.showMessageDialog(frame, "Ports must be between 1 and 65535.", "Input Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (startPort > endPort) {
            JOptionPane.showMessageDialog(frame, "Start port cannot be greater than End port.", "Input Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (timeout <= 0) {
            JOptionPane.showMessageDialog(frame, "Timeout must be a positive integer.", "Input Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Reset UI
        resultArea.setText("Starting scan on " + host + "...\n");
        scanButton.setEnabled(false);
        stopButton.setEnabled(true);
        isScanning.set(true);
        
        int totalPorts = endPort - startPort + 1;
        progressBar.setMinimum(0);
        progressBar.setMaximum(totalPorts);
        progressBar.setValue(0);
        progressBar.setVisible(true);

        // Setup Thread Pool
        executor = Executors.newFixedThreadPool(50);

        new Thread(() -> {
            java.util.concurrent.atomic.AtomicInteger completedCount = new java.util.concurrent.atomic.AtomicInteger(0);

            for (int port = startPort; port <= endPort; port++) {
                if (!isScanning.get()) {
                    break;
                }

                final int finalPort = port;
                executor.submit(() -> {
                    if (!isScanning.get()) {
                        return;
                    }

                    boolean open = PortScannerUtil.scanPort(host, finalPort, timeout);

                    if (open) {
                        String service = ServiceMapper.getService(finalPort);
                        String banner = BannerGrabber.grabBanner(host, finalPort, timeout);
                        
                        SwingUtilities.invokeLater(() -> {
                            resultArea.append(String.format("Port %d OPEN (%s)\n", finalPort, service));
                            if (banner != null && !banner.equals("No banner")) {
                                resultArea.append(String.format("  -> Banner: %s\n", banner));
                            }
                        });
                    }

                    int current = completedCount.incrementAndGet();
                    SwingUtilities.invokeLater(() -> progressBar.setValue(current));
                });
            }

            // Shutdown executor and wait for tasks to finish
            executor.shutdown();
            try {
                executor.awaitTermination(1, TimeUnit.HOURS);
            } catch (InterruptedException ignored) {}

            SwingUtilities.invokeLater(() -> {
                if (isScanning.get()) {
                    resultArea.append("\nScan completed successfully.\n");
                } else {
                    resultArea.append("\nScan stopped by user.\n");
                }
                scanButton.setEnabled(true);
                stopButton.setEnabled(false);
                progressBar.setVisible(false);
                isScanning.set(false);
            });
        }).start();
    }

    private void stopScanning() {
        if (isScanning.get()) {
            isScanning.set(false);
            if (executor != null) {
                executor.shutdownNow();
            }
        }
    }
}