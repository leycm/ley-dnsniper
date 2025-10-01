package de.leycm.dnsniper.util;


import de.leycm.dnsniper.dns.DnsRecord;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Minimal DNS client implemented with UDP sockets (no external libs).
 * Supports basic lookup for several types and a direct-resolver test.
 * NOTE: Not a full DNS implementation. Handles most typical answers and common RDATA types.
 */
@SuppressWarnings("SpellCheckingInspection")
public final class SimpleDnsClient {

    public static final int TYPE_A = 1;
    public static final int TYPE_NS = 2;
    public static final int TYPE_CNAME = 5;
    public static final int TYPE_SOA = 6;
    public static final int TYPE_MX = 15;
    public static final int TYPE_TXT = 16;
    public static final int TYPE_AAAA = 28;

    private final List<InetSocketAddress> resolvers;
    private final DatagramSocket socket;

    public SimpleDnsClient() {
        this.resolvers = detectSystemResolvers();
        try {
            this.socket = new DatagramSocket();
            this.socket.setSoTimeout(3000);
        } catch (SocketException e) {
            throw new RuntimeException(e);
        }
    }

    public void close() {
        if (socket != null && !socket.isClosed()) socket.close();
    }

    /**
     * High-level lookup: tries resolvers in order, returns list of DnsRecord.
     */
    public List<DnsRecord> lookup(@NotNull String name, int type) {
        String qname = name.endsWith(".") ? name : name + ".";
        for (InetSocketAddress resolver : resolvers) {
            try {
                byte[] query = buildQuery(qname, type);
                byte[] resp = sendUdp(query, resolver, 3000);
                return parseResponse(qname, resp, type);
            } catch (Exception ignored) {
            }
        }
        return Collections.emptyList();
    }

    /**
     * Test if a resolver at ip:53 is responsive for this target name by asking for SOA.
     */
    public boolean testResolver(String resolverIp, String targetName, int timeoutMs) {
        try (DatagramSocket s = new DatagramSocket()) {
            s.setSoTimeout(timeoutMs);
            InetSocketAddress resolver = new InetSocketAddress(resolverIp, 53);
            byte[] q = buildQuery(targetName.endsWith(".") ? targetName : targetName + ".", TYPE_SOA);
            DatagramPacket p = new DatagramPacket(q, q.length, resolver);
            s.send(p);
            byte[] buf = new byte[4096];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            s.receive(resp);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private byte @NotNull [] buildQuery(@NotNull String qname, int type) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Random rnd = new Random();
        int id = rnd.nextInt(0xFFFF);

        out.write((id >> 8) & 0xFF);
        out.write(id & 0xFF);
        out.write(0x01);
        out.write(0x00);
        out.write(0x00); out.write(0x01);
        out.write(new byte[]{0,0,0,0,0,0,0,0}, 0, 8);
        String[] labels = qname.split("\\.");
        for (String lab : labels) {
            if (lab.isEmpty()) continue;
            byte[] bs = lab.getBytes(StandardCharsets.UTF_8);
            out.write(bs.length);
            out.write(bs);
        }
        out.write(0x00);

        out.write((type >> 8) & 0xFF);
        out.write(type & 0xFF);
        out.write(0x00); out.write(0x01);

        return out.toByteArray();
    }

    private byte @NotNull [] sendUdp(byte[] query, InetSocketAddress resolver, @SuppressWarnings("SameParameterValue") int timeoutMs) throws IOException {
        DatagramSocket s = socket;
        boolean reusedSocket = (s != null && !s.isClosed());
        DatagramSocket localSocket = s;
        if (!reusedSocket) {
            localSocket = new DatagramSocket();
        }
        localSocket.setSoTimeout(timeoutMs);
        DatagramPacket p = new DatagramPacket(query, query.length, resolver);
        localSocket.send(p);
        byte[] buf = new byte[4096];
        DatagramPacket resp = new DatagramPacket(buf, buf.length);
        localSocket.receive(resp);
        if (!reusedSocket) localSocket.close();
        return Arrays.copyOf(resp.getData(), resp.getLength());
    }

    private @NotNull List<DnsRecord> parseResponse(String qname, byte[] resp, int wantType) {
        try {
            ByteBuffer bb = ByteBuffer.wrap(resp);
                        bb.getShort(); // skip transaction ID
            int flags = Short.toUnsignedInt(bb.getShort());
            int qdcount = Short.toUnsignedInt(bb.getShort());
            int ancount = Short.toUnsignedInt(bb.getShort());
            int nscount = Short.toUnsignedInt(bb.getShort());
            int arcount = Short.toUnsignedInt(bb.getShort());

            for (int i = 0; i < qdcount; i++) {
                skipName(bb);
                bb.getShort();
                bb.getShort();
            }

            List<DnsRecord> out = new ArrayList<>();
            int totalRR = ancount + nscount + arcount;
            for (int i = 0; i < totalRR; i++) {
                String name = readName(bb, resp);
                int type = Short.toUnsignedInt(bb.getShort());
                                bb.getShort(); // skip class field
                long ttl = Integer.toUnsignedLong(bb.getInt());
                int rdlength = Short.toUnsignedInt(bb.getShort());
                int rdataPos = bb.position();
                if (type == wantType || isInterestType(type)) {
                    String data = parseRdata(type, resp, rdataPos, rdlength);
                    if (data != null) {
                        out.add(new DnsRecord(name, TypeString(type), ttl, data));
                    }
                }
                bb.position(rdataPos + rdlength);
            }
            return out;
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    @Contract(pure = true)
    private @NotNull String TypeString(int t) {
        return switch (t) {
            case TYPE_A -> "A";
            case TYPE_AAAA -> "AAAA";
            case TYPE_CNAME -> "CNAME";
            case TYPE_MX -> "MX";
            case TYPE_NS -> "NS";
            case TYPE_TXT -> "TXT";
            case TYPE_SOA -> "SOA";
            default -> "TYPE" + t;
        };
    }

    private boolean isInterestType(int t) {
        return t == TYPE_A || t == TYPE_AAAA || t == TYPE_CNAME || t == TYPE_MX ||
                t == TYPE_NS || t == TYPE_TXT || t == TYPE_SOA;
    }

    private @Nullable String parseRdata(int type, byte[] resp, int pos, int len) {
        try {
            if (type == TYPE_A && len == 4) {
                return (resp[pos] & 0xFF) + "." + (resp[pos+1] & 0xFF) + "." + (resp[pos+2] & 0xFF) + "." + (resp[pos+3] & 0xFF);
            }
            if (type == TYPE_AAAA && len == 16) {
                ByteBuffer bb = ByteBuffer.wrap(resp, pos, len);
                StringBuilder sb = new StringBuilder();
                for (int i=0;i<8;i++){
                    sb.append(Integer.toHexString(Short.toUnsignedInt(bb.getShort())));
                    if (i<7) sb.append(':');
                }
                return sb.toString();
            }
            if (type == TYPE_NS || type == TYPE_CNAME) {
                return readNameAt(resp, pos);
            }
            if (type == TYPE_MX) {
                int pref = ((resp[pos] & 0xFF) << 8) | (resp[pos+1] & 0xFF);
                String exch = readNameAt(resp, pos + 2);
                return exch + " preference=" + pref;
            }
            if (type == TYPE_TXT) {
                int off = pos;
                StringBuilder sb = new StringBuilder();
                while (off < pos + len) {
                    int l = resp[off] & 0xFF;
                    off++;
                    if (l == 0) continue;
                    if (off + l <= resp.length) {
                        sb.append(new String(resp, off, l, StandardCharsets.UTF_8));
                    }
                    off += l;
                    if (off < pos + len) sb.append(" ");
                }
                return sb.toString();
            }
            if (type == TYPE_SOA) {
                int off = pos;
                String mname = readNameAt(resp, off);
                off += nameLenAt(resp, off);
                String rname = readNameAt(resp, off);
                off += nameLenAt(resp, off);
                long serial = readUInt32(resp, off); off += 4;
                long refresh = readUInt32(resp, off); off +=4;
                long retry = readUInt32(resp, off); off +=4;
                long expire = readUInt32(resp, off); off +=4;
                long minimum = readUInt32(resp, off); off +=4;
                return String.format("mname=%s rname=%s serial=%d refresh=%d retry=%d expire=%d minimum=%d",
                        mname, rname, serial, refresh, retry, expire, minimum);
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    private @NotNull String readName(@NotNull ByteBuffer bb, byte[] msg) {
        int pos = bb.position();
        String s = readNameAt(msg, pos);
        bb.position(pos + nameLenAt(msg, pos));
        return s;
    }

    private @NotNull String readNameAt(byte @NotNull [] msg, int pos) {
        StringBuilder sb = new StringBuilder();
        int p = pos;
        //noinspection MismatchedQueryAndUpdateOfCollection
        Set<Integer> seen = new HashSet<>();
        while (p < msg.length) {
            int len = msg[p] & 0xFF;
            if (len == 0) {
                if (sb.isEmpty()) sb.append(".");
                else {
                    if (sb.charAt(sb.length()-1) == '.') sb.setLength(sb.length()-1);
                }
                break;
            }
            if ((len & 0xC0) == 0xC0) {
                if (p + 1 >= msg.length) break;
                int ptr = ((len & 0x3F) << 8) | (msg[p+1] & 0xFF);
                seen.add(ptr);
                String rest = readNameAt(msg, ptr);
                if (rest.endsWith(".")) rest = rest.substring(0, rest.length()-1);
                if (!sb.isEmpty() && sb.charAt(sb.length()-1) != '.') sb.append('.');
                sb.append(rest);
                break;
            } else {
                p++;
                if (p + len > msg.length) break;
                String part = new String(msg, p, len);
                sb.append(part).append('.');
                p += len;
            }
        }
        if (sb.isEmpty()) return ".";
        if (sb.charAt(sb.length()-1) == '.') sb.setLength(sb.length()-1);
        return sb.toString();
    }

    @Contract(pure = true)
    private int nameLenAt(byte @NotNull [] msg, int pos) {
        int p = pos;
        int lenTotal = 0;
        while (p < msg.length) {
            int len = msg[p] & 0xFF;
            lenTotal++;
            if (len == 0) break;
            if ((len & 0xC0) == 0xC0) {
                lenTotal++; break;
            } else {
                p += 1 + len;
                lenTotal += len;
            }
        }
        return lenTotal;
    }

    private void skipName(@NotNull ByteBuffer bb) {
        while (true) {
            int b = bb.get() & 0xFF;
            if (b == 0) break;
            if ((b & 0xC0) == 0xC0) {
                bb.get();
                break;
            } else {
                bb.position(bb.position() + b);
            }
        }
    }

    @Contract(pure = true)
    private long readUInt32(byte @NotNull [] msg, int off) {
        return ((long)(msg[off] & 0xFF) << 24) | ((long)(msg[off+1] & 0xFF) << 16)
                | ((long)(msg[off+2] & 0xFF) << 8) | (long)(msg[off+3] & 0xFF);
    }

    private @NotNull List<InetSocketAddress> detectSystemResolvers() {
        List<InetSocketAddress> out = new ArrayList<>();
        try {
            Class<?> rc = Class.forName("sun.net.dns.ResolverConfiguration");
            Object conf = rc.getMethod("open").invoke(null);
            @SuppressWarnings("unchecked")
            List<String> names = (List<String>) rc.getMethod("nameservers").invoke(conf);
            for (String n : names) {
                try {
                    out.add(new InetSocketAddress(n, 53));
                } catch (Exception ignored) {}
            }
        } catch (Throwable ignored) {}

        if (out.isEmpty()) {
            out.add(new InetSocketAddress("8.8.8.8", 53));
            out.add(new InetSocketAddress("1.1.1.1", 53));
        }
        return out;
    }
}

