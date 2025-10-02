package de.leycm.dnsniper.scanner;

import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPInputStream;

public class SubdomainScannerImpl {

    public static final String DEFAULT_WORDLIST_URL =
            "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/refs/heads/main/n0kovo_subdomains_tiny.txt";

    private final int maxConcurrentLookups;
    private final Duration lookupTimeout;
    private final int httpConnectTimeoutMs;
    private final int httpReadTimeoutMs;

    private final ExecutorService lookupExecutor;

    private final List<String> cachedWordlist;
    private final String cachedSourceUrl;
    private final String cachedLocalFilePath;

    public SubdomainScannerImpl() throws IOException {
        this(DEFAULT_WORDLIST_URL, null, Math.max(50, Runtime.getRuntime().availableProcessors() * 4), Duration.ofSeconds(3));
    }

    public SubdomainScannerImpl(String wordlistUrl, String localFilePath) throws IOException {
        this(wordlistUrl, localFilePath, Math.max(50, Runtime.getRuntime().availableProcessors() * 4), Duration.ofSeconds(3));
    }

    public SubdomainScannerImpl(String wordlistUrl, String localFilePath, int maxConcurrentLookups, Duration lookupTimeout) throws IOException {
        if (maxConcurrentLookups <= 0) throw new IllegalArgumentException("maxConcurrentLookups > 0 required");
        this.maxConcurrentLookups = maxConcurrentLookups;
        this.lookupTimeout = Objects.requireNonNull(lookupTimeout);
        this.httpConnectTimeoutMs = 10_000;
        this.httpReadTimeoutMs = 120_000;
        this.lookupExecutor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });

        this.cachedSourceUrl = (wordlistUrl != null && !wordlistUrl.isBlank()) ? wordlistUrl : null;
        this.cachedLocalFilePath = (localFilePath != null && !localFilePath.isBlank()) ? localFilePath : null;
        this.cachedWordlist = Collections.unmodifiableList(loadWordlist(this.cachedSourceUrl, this.cachedLocalFilePath));
    }

    public List<String> scanDomain(String rootDomain) {
        if (rootDomain == null || rootDomain.isBlank()) throw new IllegalArgumentException("rootDomain required");

        return scanWithIterator(rootDomain, cachedWordlist.iterator());
    }

    public List<String> scanDomain(String rootDomain, String wordlistUrl, String localFilePath) throws IOException {
        if (rootDomain == null || rootDomain.isBlank()) throw new IllegalArgumentException("rootDomain required");

        boolean useCache;
        if (wordlistUrl != null && !wordlistUrl.isBlank()) {
            useCache = wordlistUrl.equalsIgnoreCase(cachedSourceUrl);
        } else if (localFilePath != null && !localFilePath.isBlank()) {
            useCache = localFilePath.equals(cachedLocalFilePath);
        } else {
            useCache = true;
        }

        if (useCache) return scanWithIterator(rootDomain, cachedWordlist.iterator());

        try (BufferedReader reader = openReader(wordlistUrl, localFilePath)) {
            List<String> singleUse = new ArrayList<>();
            String line;
            while ((line = reader.readLine()) != null) {
                String candidate = sanitizeLine(line);
                if (candidate != null) singleUse.add(candidate);
            }
            return scanWithIterator(rootDomain, singleUse.iterator());
        }
    }

    private @NotNull List<String> scanWithIterator(String rootDomain, @NotNull Iterator<String> candidates) {
        Semaphore inFlight = new Semaphore(maxConcurrentLookups);
        CompletionService<Optional<String>> completion = new ExecutorCompletionService<>(lookupExecutor);
        List<String> found = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger submitted = new AtomicInteger(0);

        int c = 0;

        while (candidates.hasNext()) {
            String candidate = candidates.next();
            c++;
            if (candidate == null || candidate.isBlank()) continue;

            final String fqdn = candidate + "." + rootDomain;

            System.out.println("Scanning " + fqdn + "[" + c + "]");

            try {
                inFlight.acquire();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }

            submitted.incrementAndGet();
            completion.submit(() -> {
                try {
                    boolean ok = resolves(fqdn, lookupTimeout);
                    return ok ? Optional.of(fqdn) : Optional.empty();
                } finally {
                    inFlight.release();
                }
            });
        }

        int toCollect = submitted.get();
        for (int i = 0; i < toCollect; i++) {
            try {
                Future<Optional<String>> f = completion.take();
                Optional<String> res = f.get();
                res.ifPresent(found::add);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (ExecutionException ignored) {
            }
        }

        List<String> dedup = new ArrayList<>(new LinkedHashSet<>(found));
        Collections.sort(dedup);
        return dedup;
    }

    private boolean resolves(String fqdn, @NotNull Duration timeout) {
        Callable<Boolean> call = () -> {
            try {
                InetAddress addr = InetAddress.getByName(fqdn);
                return addr != null;
            } catch (Throwable t) {
                return false;
            }
        };
        Future<Boolean> f = lookupExecutor.submit(call);
        try {
            return Boolean.TRUE.equals(f.get(timeout.toMillis(), TimeUnit.MILLISECONDS));
        } catch (TimeoutException te) {
            f.cancel(true);
            return false;
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            return false;
        } catch (ExecutionException ee) {
            return false;
        }
    }

    private @NotNull BufferedReader openReader(String wordlistUrl, String localFilePath) throws IOException {
        if (localFilePath != null && !localFilePath.isBlank()) {
            return java.nio.file.Files.newBufferedReader(java.nio.file.Path.of(localFilePath), StandardCharsets.UTF_8);
        }

        URL u = new URL(wordlistUrl);
        InputStream is = getInputStream(wordlistUrl, u);
        return new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
    }

    private InputStream getInputStream(String wordlistUrl, @NotNull URL u) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setConnectTimeout(httpConnectTimeoutMs);
        conn.setReadTimeout(httpReadTimeoutMs);
        conn.setRequestProperty("User-Agent", "HugeSubdomainScanner/1.0");
        conn.connect();
        InputStream is = conn.getInputStream();
        String encoding = Optional.ofNullable(conn.getContentEncoding()).orElse("");
        if ("gzip".equalsIgnoreCase(encoding) || (wordlistUrl != null && wordlistUrl.toLowerCase().endsWith(".gz"))) {
            is = new GZIPInputStream(is);
        }
        return is;
    }

    private @NotNull List<String> loadWordlist(String wordlistUrl, String localFilePath) throws IOException {
        List<String> out = new ArrayList<>(100_000);
        try (BufferedReader reader = openReader(
                (wordlistUrl != null && !wordlistUrl.isBlank()) ? wordlistUrl : DEFAULT_WORDLIST_URL,
                localFilePath)) {
            String line;
            while ((line = reader.readLine()) != null) {
                String candidate = sanitizeLine(line);
                if (candidate != null) out.add(candidate);
            }
        }
        return out;
    }

    private String sanitizeLine(String raw) {
        if (raw == null) return null;
        String s = raw.trim();
        if (s.isEmpty()) return null;
        if (s.startsWith("#")) return null;
        s = s.replaceAll("^\\.+|\\.+$", "");
        if (s.isEmpty()) return null;
        if (!s.matches("[A-Za-z0-9\\-.]+")) return null;
        return s;
    }

    public void shutdown() {
        lookupExecutor.shutdownNow();
    }

    public String cacheInfo() {
        return "cachedSourceUrl=" + cachedSourceUrl + ", cachedLocalFilePath=" + cachedLocalFilePath
                + ", entries=" + cachedWordlist.size();
    }
}
