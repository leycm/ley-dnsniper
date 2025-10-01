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

/**
 * Represents the result of a single port scan.
 *
 * @param port   the port number
 * @param status the {@link PortScannerApi.PortStatus} result
 * @param pingMs response time in milliseconds
 */
public record PortResult(int port, PortScannerApi.PortStatus status, long pingMs) {}
