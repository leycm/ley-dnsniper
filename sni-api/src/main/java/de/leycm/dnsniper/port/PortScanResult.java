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

import org.jetbrains.annotations.NotNull;

import java.net.InetAddress;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Represents the full result of a port scan, including metadata such as the target address,
 * the timestamp of the scan, and the list of scanned ports with their results.
 */
public record PortScanResult(
        InetAddress target, // The target address of the scan
        Instant timestamp, // The timestamp when the scan was performed
        List<PortResult> ports // The list of results for all scanned ports
) {

    /**
     * Retrieves all ports that are open.
     *
     * @return a list of {@link PortResult} objects representing open ports
     */
    public List<PortResult> getOpenPorts() {
        return ports.stream()
                .filter(p -> p.status() == PortScannerApi.PortStatus.OPEN)
                .collect(Collectors.toList());
    }

    /**
     * Retrieves all ports that timed out during the scan.
     *
     * @return a list of {@link PortResult} objects representing ports that timed out
     */
    public List<PortResult> getTimedOutPorts() {
        return ports.stream()
                .filter(p -> p.status() == PortScannerApi.PortStatus.TIMEOUT)
                .collect(Collectors.toList());
    }

    /**
     * Retrieves all ports that are closed.
     *
     * @return a list of {@link PortResult} objects representing closed ports
     */
    public List<PortResult> getClosedPorts() {
        return ports.stream()
                .filter(p -> p.status() == PortScannerApi.PortStatus.CLOSED)
                .collect(Collectors.toList());
    }

    /**
     * Generates a short formatted summary of the scan result.
     * The summary includes the target address, the count of open, closed, and timed-out ports,
     * and the timestamp of the scan.
     *
     * @return a formatted string summarizing the scan result
     */
    public @NotNull String summary() {
        long open = getOpenPorts().size();
        long closed = getClosedPorts().size();
        long timeout = getTimedOutPorts().size();
        return "[ScanResult] " + target.getHostAddress() +
                " | Open=" + open +
                " Closed=" + closed +
                " Timeout=" + timeout +
                " | @ " + timestamp;
    }
}

