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
package de.leycm.dnsniper.dns;

import de.leycm.dnsniper.DNSniperApi;
import de.leycm.dnsniper.DNSniperApiProvider;

/**
 * Defines the API for a DNS scanner, providing methods to perform DNS scans
 * and check the availability of the scanner.
 */
public interface DnsScannerApi {

    /**
     * Performs a DNS scan for the given domain name.
     *
     * @param domain The domain name to scan.
     * @return The result of the DNS scan, including records and other details.
     */
    default DnsScanResult scan(String domain) {
        return DNSniperApiProvider.get().scanDnsEntry(domain);
    }

}
