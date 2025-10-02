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
package de.leycm.dnsniper.scanner;

import de.leycm.dnsniper.port.PortResult;
import de.leycm.dnsniper.port.PortScanResult;
import de.leycm.dnsniper.port.PortScannerApi;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.Predicate;

/**
 * Common implementation of {@link PortScannerApi}.
 * <p>
 * This class provides functionality to scan TCP ports on a given host using multithreading.
 * It supports scanning all ports or filtering specific ports based on a predicate.
 * </p>
 */
public class PortScannerImpl implements PortScannerApi {

    private final int timeoutMs;
    private final ExecutorService executor;

    /**
     * Constructs a PortScannerImpl with a default timeout of 500ms per port.
     */
    public PortScannerImpl() {
        this(500);
    }

    /**
     * Constructs a PortScannerImpl with a custom timeout.
     *
     * @param timeoutMs the timeout in milliseconds for each port scan
     */
    public PortScannerImpl(int timeoutMs) {
        this.timeoutMs = timeoutMs;
        this.executor = Executors.newFixedThreadPool(200);
    }

    /**
     * Scans all TCP ports (1-65535) on the specified address.
     * Each port is scanned in parallel using a thread pool.
     *
     * @param address the target {@link InetAddress}
     * @return a {@link PortScanResult} containing the results for all ports
     */
    @Override
    public PortScanResult scanAllPorts(InetAddress address) {
        Instant start = Instant.now();
        List<Future<PortResult>> futures = new ArrayList<>();

        for (int port = 1; port <= 65535; port++) {
            final int p = port;
            futures.add(executor.submit(() -> scanPort(address, p)));
        }

        List<PortResult> results = new ArrayList<>(65535);
        for (Future<PortResult> f : futures) {
            try {
                results.add(f.get());
            } catch (Exception ignored) {}
        }

        PortScanResult result = new PortScanResult(address, start, results);
        System.out.println(result.summary());
        return result;
    }

    /**
     * Scans TCP ports on the specified address, filtered by a predicate.
     * Only ports that pass the filter are scanned.
     *
     * @param address    the target {@link InetAddress}
     * @param portFilter a {@link Predicate} to filter ports to be scanned
     * @return a {@link PortScanResult} containing the results for the filtered ports
     */
    @Override
    public PortScanResult scanAllPorts(InetAddress address, Predicate<Integer> portFilter) {
        Instant start = Instant.now();
        List<Future<PortResult>> futures = new ArrayList<>();

        for (int port = 1; port <= 65535; port++) {
            final int p = port;
            if (portFilter.test(port))
                futures.add(executor.submit(() -> scanPort(address, p)));
        }

        List<PortResult> results = new ArrayList<>(65535);
        for (Future<PortResult> f : futures) {
            try {
                results.add(f.get());
            } catch (Exception ignored) {}
        }

        PortScanResult result = new PortScanResult(address, start, results);
        System.out.println(result.summary());
        return result;
    }

    /**
     * Scans a single TCP port on the given address.
     *
     * @param address the target {@link InetAddress}
     * @param port    the port number to scan
     * @return a new {@link PortResult} with the scan outcome
     */
    @Contract("_, _ -> new")
    private @NotNull PortResult scanPort(InetAddress address, int port) {
        long startTime = System.nanoTime();
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(address, port), timeoutMs);
            long ping = (System.nanoTime() - startTime) / 1_000_000;
            log(address, port, PortStatus.OPEN, ping);
            return new PortResult(port, PortStatus.OPEN, ping);
        } catch (IOException e) {
            long ping = (System.nanoTime() - startTime) / 1_000_000;
            PortStatus status = e.getMessage() != null && e.getMessage().contains("timed out")
                    ? PortStatus.TIMEOUT : PortStatus.CLOSED;
            log(address, port, status, ping);
            return new PortResult(port, status, ping);
        }
    }

    /**
     * Logs the result of a port scan to the console.
     *
     * @param address   the target address
     * @param port   the port number
     * @param status the scan result status
     * @param ping   the time taken in milliseconds
     */
    private void log(@NotNull InetAddress address, int port, PortStatus status, long ping) {
        System.out.printf("[%s] %s:%d -> %s (%dms)%n",
                Thread.currentThread().getName(),
                address.getHostAddress(), port, status, ping);
    }

    /**
     * Shuts down the thread pool and cancels all running tasks.
     */
    public void shutdown() {
        executor.shutdownNow();
    }
}