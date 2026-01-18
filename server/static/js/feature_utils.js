/**
 * NetGuardian Pro - Feature Calculation Utilities
 * 
 * These functions derive aggregated features from raw packet data
 * to populate the dashboard components.
 */

// ==================== TCP FLAG COUNTS ====================
function calculateTCPFlagCounts(packets) {
    return {
        tcp_syn_count: packets.filter(p => p.tcp_syn === true).length,
        tcp_ack_count: packets.filter(p => p.tcp_ack === true).length,
        tcp_fin_count: packets.filter(p => p.tcp_fin === true).length,
        tcp_rst_count: packets.filter(p => p.tcp_rst === true).length,
        tcp_psh_count: packets.filter(p => p.tcp_psh === true).length
    };
}

// ==================== PACKET SIZE STATS ====================
function calculatePacketSizeStats(packets) {
    const lengths = packets.map(p => p.length).filter(l => l > 0);
    if (lengths.length === 0) return { min_packet_size: 0, max_packet_size: 0, avg_packet_size: 0 };

    return {
        min_packet_size: Math.min(...lengths),
        max_packet_size: Math.max(...lengths),
        avg_packet_size: lengths.reduce((a, b) => a + b, 0) / lengths.length
    };
}

// ==================== CONNECTION FAILURE RATE ====================
function calculateConnectionFailureRate(packets) {
    const tcpPackets = packets.filter(p => p.protocol === 'TCP');
    if (tcpPackets.length === 0) return 0;

    // Count SYN packets (connection attempts)
    const synCount = tcpPackets.filter(p => p.tcp_syn && !p.tcp_ack).length;

    // Count SYN-ACK packets (successful handshakes)
    const synAckCount = tcpPackets.filter(p => p.tcp_syn && p.tcp_ack).length;

    // Count RST packets (connection failures/resets)
    const rstCount = tcpPackets.filter(p => p.tcp_rst).length;

    if (synCount === 0) return 0;

    const failedConnections = Math.max(0, synCount - synAckCount) + rstCount;
    return Math.min(1, failedConnections / synCount);
}

// ==================== DNS METRICS ====================
function calculateDNSMetrics(packets) {
    const queryCount = packets.filter(p => p.dns_query === true).length;
    const responseCount = packets.filter(p => p.dns_response === true).length;

    // Unique domains from dns_qname field
    const domains = packets
        .filter(p => p.dns_qname)
        .map(p => p.dns_qname);
    const uniqueDomains = new Set(domains).size;

    // Average query length (domain name length)
    const queryLengths = domains.map(d => d.length);
    const avgQueryLength = queryLengths.length > 0
        ? queryLengths.reduce((a, b) => a + b, 0) / queryLengths.length
        : 0;

    return {
        dns_query_count: queryCount,
        dns_response_count: responseCount,
        dns_unique_domains: uniqueDomains,
        avg_dns_query_length: avgQueryLength
    };
}

// ==================== SYN-ACK RATIO ====================
function calculateSynAckRatio(packets) {
    const tcpPackets = packets.filter(p => p.protocol === 'TCP');

    const synCount = tcpPackets.filter(p => p.tcp_syn && !p.tcp_ack).length;
    const synAckCount = tcpPackets.filter(p => p.tcp_syn && p.tcp_ack).length;

    // Healthy ratio should be close to 1
    if (synAckCount === 0) return synCount > 0 ? synCount : 0;

    return synAckCount / Math.max(1, synCount);
}

// ==================== INTER-ARRIVAL TIME ====================
function calculateInterArrivalTime(packets) {
    if (packets.length < 2) return { inter_arrival_time_mean: 0, inter_arrival_time_std: 0 };

    // Sort by timestamp
    const sorted = [...packets].sort((a, b) => a.timestamp - b.timestamp);

    // Calculate intervals between consecutive packets
    const intervals = [];
    for (let i = 1; i < sorted.length; i++) {
        intervals.push(sorted[i].timestamp - sorted[i - 1].timestamp);
    }

    if (intervals.length === 0) return { inter_arrival_time_mean: 0, inter_arrival_time_std: 0 };

    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / intervals.length;

    return {
        inter_arrival_time_mean: mean,
        inter_arrival_time_std: Math.sqrt(variance)
    };
}

// ==================== PROTOCOL COUNTS ====================
function calculateProtocolCounts(packets) {
    return {
        tcp_count: packets.filter(p => p.protocol === 'TCP').length,
        udp_count: packets.filter(p => p.protocol === 'UDP').length,
        icmp_count: packets.filter(p => p.protocol && p.protocol.includes('ICMP')).length,
        arp_count: packets.filter(p => p.protocol === 'ARP').length,
        other_count: packets.filter(p => p.protocol === 'OTHER').length
    };
}

// ==================== TRAFFIC RATES ====================
function calculateTrafficRates(packets, durationSeconds = 5) {
    const totalPackets = packets.length;
    const totalBytes = packets.reduce((sum, p) => sum + (p.length || 0), 0);

    return {
        packet_count: totalPackets,
        byte_count: totalBytes,
        packet_rate_pps: totalPackets / durationSeconds,
        byte_rate_bps: (totalBytes * 8) / durationSeconds
    };
}

// ==================== UNIQUE DESTINATIONS ====================
function calculateUniqueDestinations(packets) {
    const uniqueIPs = new Set(packets.filter(p => p.dst_ip).map(p => p.dst_ip));
    const uniquePorts = new Set(packets.filter(p => p.dst_port).map(p => p.dst_port));

    return {
        unique_dst_ips: uniqueIPs.size,
        unique_dst_ports: uniquePorts.size
    };
}

// ==================== ARP METRICS ====================
function calculateARPMetrics(packets, durationSeconds = 5) {
    const arpPackets = packets.filter(p => p.protocol === 'ARP');

    return {
        arp_request_count: arpPackets.filter(p => p.arp_op === 1).length,
        arp_reply_count: arpPackets.filter(p => p.arp_op === 2).length,
        arp_request_rate_pps: arpPackets.filter(p => p.arp_op === 1).length / durationSeconds
    };
}

// ==================== AGGREGATE ALL FEATURES ====================
function calculateAllFeatures(packets, durationSeconds = 5) {
    return {
        ...calculateTrafficRates(packets, durationSeconds),
        ...calculatePacketSizeStats(packets),
        ...calculateProtocolCounts(packets),
        ...calculateTCPFlagCounts(packets),
        ...calculateUniqueDestinations(packets),
        ...calculateDNSMetrics(packets),
        ...calculateARPMetrics(packets, durationSeconds),
        ...calculateInterArrivalTime(packets),
        connection_failure_rate: calculateConnectionFailureRate(packets),
        syn_ack_ratio: calculateSynAckRatio(packets)
    };
}

// ==================== DERIVED ANALYTICS METRICS ====================
function calculateNetworkHealth(features) {
    let score = 100;
    const packetLossPenalty = (features.connection_failure_rate || 0) * 50;
    const retransPenalty = (features.tcp_rst_count / Math.max(1, features.tcp_count)) * 20;
    const arpPenalty = (features.arp_request_rate_pps > 10) ? 10 : 0;

    score -= packetLossPenalty + retransPenalty + arpPenalty;
    return Math.max(0, Math.min(100, score));
}

function calculateConnectionQuality(features) {
    const successRate = 1 - (features.connection_failure_rate || 0);
    const synAckHealth = Math.min(1, features.syn_ack_ratio || 0);
    const rstRatio = features.tcp_rst_count / Math.max(1, features.tcp_count);
    const rstHealth = Math.max(0, 1 - rstRatio);

    const quality = (successRate * 0.4 + synAckHealth * 0.4 + rstHealth * 0.2) * 100;
    return quality.toFixed(1);
}

function calculateProtocolDiversity(features) {
    const total = features.packet_count || 1;
    const protocols = [
        features.tcp_count / total,
        features.udp_count / total,
        features.icmp_count / total,
        (features.other_count || 0) / total
    ].filter(p => p > 0);

    let entropy = 0;
    protocols.forEach(p => {
        if (p > 0) entropy -= p * Math.log2(p);
    });

    return (entropy / 2).toFixed(3);
}

function calculateTrafficEfficiency(features) {
    const payloadRatio = Math.min(1, (features.avg_packet_size || 0) / 1500);
    const ackOverhead = (features.tcp_ack_count || 0) / Math.max(1, features.packet_count || 1);
    const protocolEfficiency = Math.max(0, 1 - ackOverhead);
    const retransWaste = ((features.tcp_rst_count || 0) + (features.tcp_fin_count || 0)) / Math.max(1, features.packet_count || 1);
    const retransEfficiency = Math.max(0, 1 - retransWaste);

    const efficiency = (payloadRatio * 0.4 + protocolEfficiency * 0.3 + retransEfficiency * 0.3) * 100;
    // Clamp to 0-100 range
    return Math.max(0, Math.min(100, efficiency)).toFixed(1);
}

function calculateDNSHealth(features) {
    let score = 100;
    const qrRatio = features.dns_query_count / Math.max(1, features.dns_response_count);
    if (qrRatio > 1.5 || qrRatio < 0.5) score -= 20;
    if ((features.avg_dns_query_length || 0) > 50) score -= 30;
    if ((features.dns_unique_domains || 0) > 300) score -= 25;
    const dnsRatio = (features.dns_query_count + features.dns_response_count) / Math.max(1, features.packet_count);
    if (dnsRatio > 0.3) score -= 15;

    return Math.max(0, score);
}

function calculateBandwidthUtilization(features, maxBandwidth = 1000000000) {
    const currentBps = (features.byte_rate_bps || 0) * 8;
    const utilization = (currentBps / maxBandwidth) * 100;
    return utilization.toFixed(2);
}

// Export for use in HTML or testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        calculateTCPFlagCounts,
        calculatePacketSizeStats,
        calculateConnectionFailureRate,
        calculateDNSMetrics,
        calculateSynAckRatio,
        calculateInterArrivalTime,
        calculateProtocolCounts,
        calculateTrafficRates,
        calculateUniqueDestinations,
        calculateARPMetrics,
        calculateAllFeatures,
        calculateNetworkHealth,
        calculateConnectionQuality,
        calculateProtocolDiversity,
        calculateTrafficEfficiency,
        calculateDNSHealth,
        calculateBandwidthUtilization
    };
}
