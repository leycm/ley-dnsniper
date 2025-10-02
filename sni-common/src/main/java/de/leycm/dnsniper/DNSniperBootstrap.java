/**
 * LECP-LICENSE NOTICE
 * <br><br>
 * This Sourcecode is under the LECP-LICENSE. <br>
 * License at: <a href="https://github.com/leycm/leycm/blob/main/LICENSE">GITHUB</a>
 * <br><br>
 * Copyright (c) LeyCM <leycm@proton.me> <br>
 * Copyright (c) maintainers <br>
 * Copyright (c) contributors
 */
package de.leycm.dnsniper;

import de.leycm.dnsniper.dns.DnsScanResult;
import de.leycm.dnsniper.scanner.DnsScannerImpl;
import de.leycm.dnsniper.scanner.PortScannerImpl;
import de.leycm.dnsniper.port.PortScanResult;
import de.leycm.dnsniper.scanner.SubdomainScannerImpl;

import java.io.IOException;
import java.net.InetAddress;
import java.util.List;
import java.util.function.Predicate;

/**
 * Core implementation of the {@link DNSniperApi}.
 * <p>
 * This class serves as the main entry point for DNSniper functionality.
 * It provides methods to perform port scanning operations and manages
 * the lifecycle of the API implementation.
 * </p>
 */
public class DNSniperBootstrap implements DNSniperApi {
    // Instance of PortScannerImpl used for performing port scans
    PortScannerImpl portScanner = new PortScannerImpl();
    // Instance of DnsScannerImpl used for performing dns lookups
    DnsScannerImpl dnsScanner = new DnsScannerImpl();
    // Instance of SubdomainScannerImpl used for performing subdomain scans
    SubdomainScannerImpl subdomainScanner = new SubdomainScannerImpl();

    /**
     * Constructs a new DNSniperBootstrap and registers this instance with the {@link DNSniperApiProvider}.
     * <p>
     * This ensures that the API implementation is available for use throughout the application.
     * </p>
     */
    public DNSniperBootstrap() throws IOException {
        DNSniperApiProvider.register(this);
    }

    /**
     * Scans all TCP ports on the specified host.
     *
     * @param host the target {@link InetAddress} to scan
     * @return a {@link PortScanResult} containing the results of the scan
     */
    @Override
    public PortScanResult scanAllPorts(InetAddress host) {
        return portScanner.scanAllPorts(host);
    }

    /**
     * Scans TCP ports on the specified address, filtered by a predicate.
     * <p>
     * Only ports that pass the provided filter will be scanned.
     * </p>
     *
     * @param address    the target {@link InetAddress} to scan
     * @param portFilter a {@link Predicate} to filter the ports to be scanned
     * @return a {@link PortScanResult} containing the results of the filtered scan
     */
    @Override
    public PortScanResult scanAllPorts(InetAddress address, Predicate<Integer> portFilter) {
        return portScanner.scanAllPorts(address, portFilter);
    }

    @Override
    public DnsScanResult scanDnsEntry(String domain) {
        return dnsScanner.scan(domain);
    }

    @Override
    public List<String> scanSubDomain(String domain) {
        return subdomainScanner.scanDomain(domain);
    }

    /**
     * Shuts down this instance, unregistering the API implementation and releasing resources.
     * <p>
     * This method ensures that the API is properly unregistered and the associated
     * {@link PortScannerImpl} is shut down to release any allocated resources.
     * </p>
     */
    public void shutdown() {
        DNSniperApiProvider.unregister();
        portScanner.shutdown();
    }
}
