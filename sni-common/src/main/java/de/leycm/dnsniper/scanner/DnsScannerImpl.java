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

import de.leycm.dnsniper.dns.DnsRecord;
import de.leycm.dnsniper.dns.DnsScanResult;
import de.leycm.dnsniper.dns.DnsScannerApi;
import de.leycm.dnsniper.dns.NameServerCheckResult;
import de.leycm.dnsniper.util.SimpleDnsClient;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.net.InetAddress;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Implementation of DnsScannerApi without external libraries.
 * Uses:
 * - InetAddress.getAllByName for A/AAAA resolution
 * - a small internal UDP DNS client (SimpleDnsClient) for other record types
 */
public class DnsScannerImpl implements DnsScannerApi {

    private final SimpleDnsClient dnsClient;
    private final ExecutorService executor;

    public DnsScannerImpl() {
        this.dnsClient = new SimpleDnsClient();
        this.executor = Executors.newFixedThreadPool(6);
    }

    @Override
    public DnsScanResult scan(String name) {
        Instant now = Instant.now();
        String normalized = normalizeName(name);

        List<DnsRecord> records = Collections.synchronizedList(new ArrayList<>());

        try {
            InetAddress[] addrs = InetAddress.getAllByName(normalized);
            for (InetAddress a : addrs) {
                String type = a.getAddress().length == 4 ? "A" : "AAAA";
                records.add(new DnsRecord(normalized, type, -1, a.getHostAddress()));
            }
        } catch (Exception ignored) {
        }

        List<Integer> types = Arrays.asList(
                SimpleDnsClient.TYPE_A,
                SimpleDnsClient.TYPE_AAAA,
                SimpleDnsClient.TYPE_CNAME,
                SimpleDnsClient.TYPE_MX,
                SimpleDnsClient.TYPE_NS,
                SimpleDnsClient.TYPE_TXT,
                SimpleDnsClient.TYPE_SOA
        );

        List<Future<List<DnsRecord>>> futures = new ArrayList<>();
        for (Integer t : types) {
            futures.add(executor.submit(() -> dnsClient.lookup(normalized, t)));
        }

        for (Future<List<DnsRecord>> f : futures) {
            try {
                List<DnsRecord> part = f.get(5, TimeUnit.SECONDS);
                if (part != null) records.addAll(part);
            } catch (Exception ignored) {
            }
        }

        List<DnsRecord> deduped = records.stream()
                .collect(Collectors.collectingAndThen(
                        Collectors.toMap(r -> r.type() + "@" + r.data(), r -> r, (a,b)->a),
                        m -> new ArrayList<>(m.values())
                ));

        List<String> nsNames = deduped.stream()
                .filter(r -> "NS".equalsIgnoreCase(r.type()))
                .map(DnsRecord::data)
                .map(this::stripDot)
                .distinct()
                .collect(Collectors.toList());

        if (nsNames.isEmpty()) {
            List<DnsRecord> nsOnly = dnsClient.lookup(normalized, SimpleDnsClient.TYPE_NS);
            nsNames = nsOnly.stream().map(DnsRecord::data).map(this::stripDot).distinct().toList();
        }

        List<NameServerCheckResult> nsChecks = new ArrayList<>();
        for (String ns : nsNames) {
            NameServerCheckResult check = checkNameServer(ns, normalized);
            nsChecks.add(check);
        }

        DnsScanResult result = new DnsScanResult(normalized, now, deduped, nsChecks);
        System.out.println(result.shortSummary());
        return result;
    }

    @Contract("_, _ -> new")
    private @NotNull NameServerCheckResult checkNameServer(String nsName, String targetToQuery) {
        String normalized = stripDot(nsName);
        List<InetAddress> resolved = new ArrayList<>();
        boolean responsive = false;
        Optional<String> error = Optional.empty();

        try {
            InetAddress[] ips = InetAddress.getAllByName(normalized);
            resolved.addAll(Arrays.asList(ips));
        } catch (Exception e) {
        }

        for (InetAddress ip : resolved) {
            try {
                boolean ok = dnsClient.testResolver(ip.getHostAddress(), targetToQuery, 2000);
                if (ok) {
                    responsive = true;
                    break;
                }
            } catch (Exception ex) {
            }
        }

        if (resolved.isEmpty()) {
            try {
                InetAddress[] sys = InetAddress.getAllByName(normalized);
                resolved.addAll(Arrays.asList(sys));
                for (InetAddress ip : sys) {
                    if (dnsClient.testResolver(ip.getHostAddress(), targetToQuery, 2000)) {
                        responsive = true;
                        break;
                    }
                }
            } catch (Exception ignored) {}
        }

        return new NameServerCheckResult(normalized, resolved, responsive, error);
    }

    private @NotNull String normalizeName(@NotNull String n) {
        if (n.endsWith(".")) return n.substring(0, n.length()-1);
        return n;
    }

    private String stripDot(String s) {
        if (s == null) return null;
        return s.endsWith(".") ? s.substring(0, s.length()-1) : s;
    }

    public void shutdown() {
        executor.shutdownNow();
        dnsClient.close();
    }
}