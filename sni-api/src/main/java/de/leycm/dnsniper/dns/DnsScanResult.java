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

    import org.jetbrains.annotations.NotNull;

    import java.time.Instant;
    import java.util.List;

    /**
     * Represents the result of a DNS scan, including the target, timestamp,
     * DNS records, and name server check results.
     *
     * @param target          The target domain or IP address of the DNS scan.
     * @param timestamp       The timestamp when the scan was performed.
     * @param records         A list of DNS records retrieved during the scan.
     * @param nameServerChecks A list of results from checking the responsiveness of name servers.
     */
    public record DnsScanResult(
            String target,
            Instant timestamp,
            List<DnsRecord> records,
            List<NameServerCheckResult> nameServerChecks
    ) {
        /**
         * Provides a short summary of the DNS scan result.
         *
         * @return A string summarizing the scan, including the target,
         *         the number of DNS records, the count of responsive name servers,
         *         and the timestamp of the scan.
         */
        public @NotNull String shortSummary() {
            long recs = records.size();
            long nsUp = nameServerChecks.stream().filter(NameServerCheckResult::responsive).count();
            return "DNS Scan for " + target + " | records=" + recs + " | nameservers_up=" + nsUp + " | @ " + timestamp;
        }
    }
