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

/**
 * Represents a DNS record with its associated properties.
 *
 * @param name The name of the DNS record (e.g., domain name).
 * @param type The type of the DNS record (e.g., A, AAAA, CNAME, etc.).
 * @param ttl  The time-to-live (TTL) value of the DNS record, in seconds.
 * @param data The data associated with the DNS record (e.g., IP address or other record-specific data).
 */
public record DnsRecord(String name, String type, long ttl, String data) { }
