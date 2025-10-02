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
 import de.leycm.dnsniper.port.PortScanResult;

 import java.io.IOException;
 import java.net.InetAddress;
 import java.util.List;
 import java.util.function.Predicate;

 /**
  * <p>
  * Main API interface exposed to users.
  * This interface defines the contract for performing port scans on a given host.
  * Implementations of this interface should be registered via {@link DNSniperApiProvider}.
  * </p>
  */
 public interface DNSniperApi {

     /**
      * Scans all TCP ports (1-65535) on the specified address.
      * <p>
      * This method performs a comprehensive scan of all ports on the given host
      * and returns the results in a {@link PortScanResult}.
      * </p>
      *
      * @param address the target {@link InetAddress} to scan
      * @return a {@link PortScanResult} containing the results of the scan
      */
     PortScanResult scanAllPorts(InetAddress address);

     /**
      * Scans TCP ports on the specified address, filtered by a predicate.
      * <p>
      * Only ports that satisfy the provided {@link Predicate} will be scanned.
      * This allows for selective scanning of specific ports based on custom criteria.
      * </p>
      *
      * @param address    the target {@link InetAddress} to scan
      * @param portFilter a {@link Predicate} to filter the ports to be scanned
      * @return a {@link PortScanResult} containing the results of the filtered scan
      */
     PortScanResult scanAllPorts(InetAddress address, Predicate<Integer> portFilter);

     DnsScanResult scanDnsEntry(String domain);

     List<String> scanSubDomain(String domain);

 }
