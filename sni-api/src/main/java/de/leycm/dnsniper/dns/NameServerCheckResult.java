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

import java.net.InetAddress;
import java.util.List;
import java.util.Optional;

/**
 * Represents the result of a name server check, including the name server's
 * name, resolved addresses, responsiveness, and any error encountered.
 *
 * @param nsName            The name of the name server being checked.
 * @param resolvedAddresses A list of IP addresses resolved for the name server.
 * @param responsive        Indicates whether the name server responded successfully.
 * @param error             An optional error message if the name server check failed.
 */
public record NameServerCheckResult(
        String nsName,
        List<InetAddress> resolvedAddresses,
        boolean responsive,
        Optional<String> error
) {}
