package de.leycm.dnsniper;

import de.leycm.dnsniper.dns.DnsRecord;
import de.leycm.dnsniper.dns.DnsScanResult;
import de.leycm.dnsniper.dns.NameServerCheckResult;
import de.leycm.dnsniper.port.PortResult;
import de.leycm.dnsniper.port.PortScanResult;
import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.List;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * GUI Client for DNSniper with multi-tab interface for displaying
 * subdomain scan, DNS entries, and port scan results.
 */
@SuppressWarnings("FieldCanBeLocal")
public class DNSniperGuiClient extends JFrame {

    private final DNSniperApi api;
    private final ExecutorService executor;

    private JTextField domainField;
    private JButton scanButton;
    private JButton saveButton;
    private JProgressBar progressBar;
    private JLabel statusLabel;
    private JTabbedPane tabbedPane;

    private final Map<String, ScanData> scanResults;

    private JPanel subdomainPanel;
    private JPanel dnsPanel;
    private JPanel portPanel;

    private JTable subdomainTable;
    private JTable dnsTable;
    private JTable portTable;

    private DefaultTableModel subdomainModel;
    private DefaultTableModel dnsModel;
    private DefaultTableModel portModel;

    public DNSniperGuiClient() throws IOException {
        new DNSniperBootstrap();
        this.api = DNSniperApiProvider.get();
        this.executor = Executors.newSingleThreadExecutor();
        this.scanResults = new HashMap<>();

        initializeUI();
    }

    private void initializeUI() {
        setTitle("DNSniper - Network Scanner");
        setSize(1000, 700);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout(10, 10));

        add(createInputPanel(), BorderLayout.NORTH);

        tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Subdomains", createSubdomainPanel());
        tabbedPane.addTab("DNS Records", createDnsPanel());
        tabbedPane.addTab("Port Scans", createPortPanel());
        add(tabbedPane, BorderLayout.CENTER);

        add(createStatusPanel(), BorderLayout.SOUTH);

        setLocationRelativeTo(null);
    }

    private @NotNull JPanel createInputPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 10));
        panel.setBorder(BorderFactory.createTitledBorder("Target Domain"));

        JLabel label = new JLabel("Domain:");
        domainField = new JTextField(30);
        scanButton = new JButton("Start Scan");
        saveButton = new JButton("Save Results to JSON");
        saveButton.setEnabled(false);

        scanButton.addActionListener(e -> startScan());
        saveButton.addActionListener(e -> saveResultsToJson());

        panel.add(label);
        panel.add(domainField);
        panel.add(scanButton);
        panel.add(saveButton);

        return panel;
    }

    private JPanel createSubdomainPanel() {
        subdomainPanel = new JPanel(new BorderLayout());
        String[] columns = {"Subdomain", "Status", "Scan Time"};
        subdomainModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        subdomainTable = new JTable(subdomainModel);
        JScrollPane scrollPane = new JScrollPane(subdomainTable);
        subdomainPanel.add(scrollPane, BorderLayout.CENTER);
        return subdomainPanel;
    }

    private JPanel createDnsPanel() {
        dnsPanel = new JPanel(new BorderLayout());
        String[] columns = {"Domain", "Record Type", "TTL", "Data", "Name Server", "NS Responsive"};
        dnsModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        dnsTable = new JTable(dnsModel);
        JScrollPane scrollPane = new JScrollPane(dnsTable);
        dnsPanel.add(scrollPane, BorderLayout.CENTER);
        return dnsPanel;
    }

    private JPanel createPortPanel() {
        portPanel = new JPanel(new BorderLayout());
        String[] columns = {"IP Address", "Port", "Status", "Response Time (ms)"};
        portModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        portTable = new JTable(portModel);
        JScrollPane scrollPane = new JScrollPane(portTable);
        portPanel.add(scrollPane, BorderLayout.CENTER);
        return portPanel;
    }

    private @NotNull JPanel createStatusPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        statusLabel = new JLabel("Ready");
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);

        panel.add(statusLabel, BorderLayout.WEST);
        panel.add(progressBar, BorderLayout.CENTER);

        return panel;
    }

    private void startScan() {
        String domain = domainField.getText().trim();
        if (domain.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a domain", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        subdomainModel.setRowCount(0);
        dnsModel.setRowCount(0);
        portModel.setRowCount(0);
        scanResults.clear();

        scanButton.setEnabled(false);
        saveButton.setEnabled(false);
        domainField.setEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);

        executor.submit(() -> performScan(domain));
    }

    private void performScan(String domain) {
        updateStatus("Scanning subdomains for " + domain + "...");

        List<String> subdomains = api.scanSubDomain(domain);
        updateStatus("Found " + subdomains.size() + " subdomains");

        for (String subdomain : subdomains) {
            ScanData data = new ScanData(subdomain);
            scanResults.put(subdomain, data);

            SwingUtilities.invokeLater(() -> {
                subdomainModel.addRow(new Object[]{
                        subdomain,
                        "Discovered",
                        Instant.now().toString()
                });
            });
        }

        updateStatus("Scanning DNS entries...");
        int processed = 0;
        for (String subdomain : subdomains) {
            try {
                DnsScanResult dnsResult = api.scanDnsEntry(subdomain);
                scanResults.get(subdomain).setDnsScanResult(dnsResult);

                for (DnsRecord record : dnsResult.records()) {
                    String nsInfo = formatNameServerInfo(dnsResult.nameServerChecks());
                    SwingUtilities.invokeLater(() -> {
                        dnsModel.addRow(new Object[]{
                                subdomain,
                                record.type(),
                                record.ttl(),
                                record.data(),
                                nsInfo,
                                countResponsiveNS(dnsResult.nameServerChecks())
                        });
                    });
                }

                processed++;
                int finalProcessed = processed;
                updateStatus("DNS scan progress: " + finalProcessed + "/" + subdomains.size());

            } catch (Exception e) {
                System.err.println("Error scanning DNS for " + subdomain + ": " + e.getMessage());
            }
        }

        // Step 3: Scan ports for all discovered IPs
        updateStatus("Scanning ports...");
        Set<InetAddress> uniqueIPs = extractUniqueIPs();

        int portProcessed = 0;
        for (InetAddress ip : uniqueIPs) {
            try {
                PortScanResult portResult = api.scanAllPorts(ip);

                for (PortResult port : portResult.ports()) {
                    SwingUtilities.invokeLater(() -> {
                        portModel.addRow(new Object[]{
                                ip.getHostAddress(),
                                port.port(),
                                port.status(),
                                port.pingMs()
                        });
                    });
                }

                // Store port results
                for (Map.Entry<String, ScanData> entry : scanResults.entrySet()) {
                    if (entry.getValue().containsIP(ip)) {
                        entry.getValue().addPortScanResult(portResult);
                    }
                }

                portProcessed++;
                int finalPortProcessed = portProcessed;
                updateStatus("Port scan progress: " + finalPortProcessed + "/" + uniqueIPs.size());

            } catch (Exception e) {
                System.err.println("Error scanning ports for " + ip.getHostAddress() + ": " + e.getMessage());
            }
        }

        SwingUtilities.invokeLater(() -> {
            updateStatus("Scan completed successfully!");
            progressBar.setVisible(false);
            scanButton.setEnabled(true);
            saveButton.setEnabled(true);
            domainField.setEnabled(true);
        });
    }

    private @NotNull Set<InetAddress> extractUniqueIPs() {
        Set<InetAddress> ips = new HashSet<>();
        for (ScanData data : scanResults.values()) {
            if (data.getDnsScanResult() != null) {
                for (DnsRecord record : data.getDnsScanResult().records()) {
                    if (record.type().equals("A") || record.type().equals("AAAA")) {
                        try {
                            InetAddress address = InetAddress.getByName(record.data());
                            ips.add(address);
                            data.addIP(address);
                        } catch (UnknownHostException ignored) { }
                    }
                }
            }
        }
        return ips;
    }

    private String formatNameServerInfo(@NotNull List<NameServerCheckResult> nsResults) {
        if (nsResults.isEmpty()) return "N/A";
        return nsResults.getFirst().nsName();
    }

    private @NotNull String countResponsiveNS(@NotNull List<NameServerCheckResult> nsResults) {
        long responsive = nsResults.stream().filter(NameServerCheckResult::responsive).count();
        return responsive + "/" + nsResults.size();
    }

    private void updateStatus(String message) {
        SwingUtilities.invokeLater(() -> statusLabel.setText(message));
    }

    private void saveResultsToJson() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Save Scan Results");
        fileChooser.setSelectedFile(new java.io.File("dnsniper_results.json"));

        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (FileWriter writer = new FileWriter(fileChooser.getSelectedFile())) {
                writer.write(generateJson());
                JOptionPane.showMessageDialog(this, "Results saved successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Failed to save results: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private @NotNull String generateJson() {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"scan_timestamp\": \"").append(Instant.now()).append("\",\n");
        json.append("  \"subdomains\": [\n");

        int i = 0;
        for (Map.Entry<String, ScanData> entry : scanResults.entrySet()) {
            if (i++ > 0) json.append(",\n");
            json.append("    {\n");
            json.append("      \"domain\": \"").append(entry.getKey()).append("\",\n");

            ScanData data = entry.getValue();

            if (data.getDnsScanResult() != null) {
                json.append("      \"dns_records\": [\n");
                List<DnsRecord> records = data.getDnsScanResult().records();
                for (int j = 0; j < records.size(); j++) {
                    DnsRecord rec = records.get(j);
                    json.append("        {\n");
                    json.append("          \"type\": \"").append(rec.type()).append("\",\n");
                    json.append("          \"ttl\": ").append(rec.ttl()).append(",\n");
                    json.append("          \"data\": \"").append(rec.data()).append("\"\n");
                    json.append("        }");
                    if (j < records.size() - 1) json.append(",");
                    json.append("\n");
                }
                json.append("      ],\n");

                json.append("      \"name_servers\": [\n");
                List<NameServerCheckResult> nsChecks = data.getDnsScanResult().nameServerChecks();
                for (int j = 0; j < nsChecks.size(); j++) {
                    NameServerCheckResult ns = nsChecks.get(j);
                    json.append("        {\n");
                    json.append("          \"name\": \"").append(ns.nsName()).append("\",\n");
                    json.append("          \"responsive\": ").append(ns.responsive()).append("\n");
                    json.append("        }");
                    if (j < nsChecks.size() - 1) json.append(",");
                    json.append("\n");
                }
                json.append("      ],\n");
            }

            json.append("      \"port_scans\": [\n");
            List<PortScanResult> portResults = data.getPortScanResults();
            for (int j = 0; j < portResults.size(); j++) {
                PortScanResult psr = portResults.get(j);
                json.append("        {\n");
                json.append("          \"ip\": \"").append(psr.target().getHostAddress()).append("\",\n");
                json.append("          \"open_ports\": [");

                List<PortResult> openPorts = psr.getOpenPorts();
                for (int k = 0; k < openPorts.size(); k++) {
                    json.append(openPorts.get(k).port());
                    if (k < openPorts.size() - 1) json.append(", ");
                }
                json.append("]\n");
                json.append("        }");
                if (j < portResults.size() - 1) json.append(",");
                json.append("\n");
            }
            json.append("      ]\n");
            json.append("    }");
        }

        json.append("\n  ]\n");
        json.append("}\n");
        return json.toString();
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            DNSniperGuiClient client = null;
            try {
                client = new DNSniperGuiClient();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            client.setVisible(true);
        });
    }

    /**
     * Data class to store all scan results for a subdomain
     */
    private static class ScanData {
        @Getter
        @Setter
        private DnsScanResult dnsScanResult;
        @Getter
        private final List<PortScanResult> portScanResults;
        private final Set<InetAddress> ips;

        public ScanData(String subdomain) {
            this.portScanResults = new ArrayList<>();
            this.ips = new HashSet<>();
        }

        public void addPortScanResult(PortScanResult result) {
            portScanResults.add(result);
        }

        public void addIP(InetAddress ip) {
            ips.add(ip);
        }

        public boolean containsIP(InetAddress ip) {
            return ips.contains(ip);
        }
    }
}
