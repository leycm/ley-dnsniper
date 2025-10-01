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
package de.leycm.dnsniper.port;

     import de.leycm.dnsniper.DNSniperApiProvider;

     import java.net.InetAddress;
     import java.util.function.Predicate;

     /**
      * API for the DNSniper Port Scanner.
      * <p>
      * This interface defines the contract for scanning ports on a given IP address.
      * It provides methods to scan all ports or a filtered subset of ports based on a predicate.
      * </p>
      */
     public interface PortScannerApi {

         /**
          * Scans all ports on the given IP address.
          * <p>
          * This method performs a comprehensive scan of all ports (1-65535) on the specified
          * IPv4 or IPv6 address and returns the results.
          * </p>
          *
          * @param address the target {@link InetAddress} (IPv4 or IPv6) to scan
          * @return a {@link PortScanResult} containing the results of the scan
          */
         default PortScanResult scanAllPorts(InetAddress address) {
             return DNSniperApiProvider.get().scanAllPorts(address);
         }

         /**
          * Scans ports on the given IP address, filtered by a predicate.
          * <p>
          * This method scans only the ports that satisfy the provided {@link Predicate}.
          * </p>
          *
          * @param address    the target {@link InetAddress} (IPv4 or IPv6) to scan
          * @param portFilter a {@link Predicate} to filter the ports to be scanned
          * @return a {@link PortScanResult} containing the results of the filtered scan
          */
         default PortScanResult scanAllPorts(InetAddress address, Predicate<Integer> portFilter) {
             return DNSniperApiProvider.get().scanAllPorts(address, portFilter);
         }

         /**
          * Enumeration of possible port states.
          * <p>
          * Represents the status of a port after a scan.
          * </p>
          */
         enum PortStatus {
             OPEN,    // The port is open and accepting connections
             CLOSED,  // The port is closed and not accepting connections
             TIMEOUT  // The port scan timed out
         }
     }
