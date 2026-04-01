# Lab 3 — Intrusion Detection & Prevention with Snort and Juniper SRX IDS

**Subject:** 48730/32548 Cybersecurity — University of Technology Sydney  
**Tools Used:** Snort, Juniper SRX, tshark  
**Skills Demonstrated:** IDS/IPS rule writing, alert analysis, DoS attack detection, SSH/Telnet blocking, enterprise IDS configuration

---

## Overview

This lab covers the configuration and operation of intrusion detection and prevention systems — one of the most critical skill sets for a SOC analyst role. The work spans two platforms: Snort (the industry-standard open-source IDS/IPS running on Linux) and the Juniper SRX firewall's built-in IDS screening engine. Together they demonstrate both host-based detection and network-level attack screening.

The key distinction between IDS and IPS is important here:
- **IDS (Intrusion Detection System):** Monitors traffic and raises alerts passively. Traffic still flows.
- **IPS (Intrusion Prevention System):** Actively blocks traffic matching a rule. The attack is stopped in real time.

This lab covers both modes.

---

## Task 1 — Snort IDS Mode: ICMP Alert Rules

### What I did
Added a custom Snort rule to `local.rules` to detect ICMP packets (ping traffic) and generate alerts, then restarted Snort in IDS mode and triggered the rule by pinging between VMs.

### The Snort rule
```
alert icmp any any -> any any (msg:"ping ping"; sid:1000001; rev:1;)
```

Breaking this down:
- `alert` — the action: generate an alert and log the packet
- `icmp` — match only ICMP protocol traffic
- `any any -> any any` — any source IP/port to any destination IP/port
- `msg:"ping ping"` — the alert message written to the log
- `sid:1000001` — unique rule ID (local rules must use SIDs above 1000000)
- `rev:1` — rule revision number

### What I observed
The `/var/log/snort/alert` file immediately populated with entries for each ICMP Echo request, showing the source/destination IPs, TTL, packet length, and sequence numbers. Each ping generated a discrete log entry confirming Snort was detecting the traffic in real time.

### Why this matters
ICMP monitoring is relevant for detecting reconnaissance activity. A sudden burst of ICMP packets from an external source often indicates a network sweep or ping-based host discovery scan. While a single ping rule is simple, this exercise establishes the foundation for more complex detection logic.

---

## Task 2 — Snort IDS Mode: Web Traffic Detection

### What I did
Configured Snort in console-output IDS mode using a standard Snort configuration file, then generated HTTP web traffic to the server to trigger the web access detection rules.

### What I observed
The console output showed two distinct alert types appearing simultaneously:
- `ICMP Destination Unreachable Port Unreachable` — generated when connection attempts hit closed ports, indicating the network stack was responding to probes
- `Web access request` — triggered on TCP traffic to port 80, confirming HTTP connections were being detected

The alerts included the full 5-tuple (source IP, source port, destination IP, destination port, protocol) for each connection, giving complete visibility into who was accessing what.

### Why this matters
Web access monitoring is directly relevant to SOC work. In a real environment, Snort rules can be tuned to flag connections to known-malicious domains, unusual port combinations, or large data transfers that may indicate exfiltration. The ability to read and interpret Snort alert output is a core SOC analyst skill.

---

## Task 3 — ICMP Source Quench Detection

### What I did
Generated ICMP Source Quench packets (Type 4) in the lab and verified Snort detected and classified them correctly.

### What I observed
Snort correctly classified the Source Quench packets with the alert `Classification: Potentially Bad Traffic` at Priority 2. The alert log showed the packet flow alongside echo replies, demonstrating Snort can distinguish between different ICMP subtypes and apply appropriate priority classifications.

### Why this matters
ICMP Source Quench is a legacy flow control mechanism that is no longer used legitimately in modern networks. Its presence is often a sign of either a misconfigured legacy device or a deliberate attack. Snort's ability to classify this traffic as suspicious rather than benign shows the value of protocol-aware detection.

---

## Task 4 — Snort IPS Mode: Blocking SSH Connection Attempts

### What I did
Switched Snort from passive IDS mode to active IPS mode. In IPS mode, Snort sits inline in the traffic path and can drop packets, not just log them.

Added a custom rule to `local.rules` to detect and block SSH connection attempts on port 22, then attempted an SSH connection from the attacker VM to the server.

### What I observed
The alert log recorded multiple `SSH Connection Attempt (Request not accepted)` entries for each connection attempt from `10.0.2.7:54864` to `10.0.2.6:22`. Critically, the SSH connection itself **failed** — the IPS successfully dropped the packets before the TCP handshake could complete.

This is the operational difference between IDS and IPS in practice: IDS tells you an attack happened after the fact; IPS stops it from happening at all.

### Why this matters
Unauthorized SSH access is one of the most common attack vectors against Linux servers. Detecting and blocking brute-force attempts at the IPS layer is a standard defensive measure in hardened environments. In a real SOC, a rule like this combined with rate-limiting logic would alert on and automatically block automated SSH scanning tools like Hydra or Medusa.

---

## Task 5 — Custom IPS Rule: Telnet Detection and Blocking

### What I did
Wrote a custom Snort rule from scratch in `local.rules` to detect Telnet connection attempts on TCP port 23 and generate a named alert.

### The rule written
```
alert tcp any any -> 10.0.2.6 23 (msg:"Telnet Connection Rejected"; sid:1000006; rev:1;)
```

### What I observed
The alert log showed a continuous stream of `Telnet Connection Rejected` entries for every connection attempt from `10.0.2.7:36086` to `10.0.2.6:23`. All Telnet connection attempts were blocked and logged with the custom alert message, confirming the rule worked exactly as intended.

### Why this matters
Writing custom Snort rules is a practical SOC skill. While community rulesets cover thousands of known threats, real-world environments always have unique assets, internal services, or unusual traffic patterns that require custom detection logic. This task demonstrates the ability to analyse a threat (Telnet exposes credentials in cleartext) and write targeted detection logic to address it.

---

## Task 6 — Juniper SRX IDS Screen Configuration

### What I did
Configured the IDS screening engine on the Juniper SRX firewall (`untrust-screen`) to protect against multiple categories of network attacks simultaneously.

### Configuration applied

```
icmp {
    ping-death;
}
ip {
    source-route-option;
    tear-drop;
}
tcp {
    syn-flood {
        alarm-threshold 1024;
        attack-threshold 200;
        source-threshold 1024;
        destination-threshold 2048;
        timeout 20;
    }
    land;
}
udp {
    flood {
        threshold 1024;
    }
}
```

### What each protection does

| Protection | Attack Blocked | How it works |
|---|---|---|
| `ping-death` | Ping of Death (oversized ICMP) | Drops ICMP packets exceeding maximum fragment size |
| `source-route-option` | IP source routing | Drops packets with IP source route options set, preventing route manipulation |
| `tear-drop` | Teardrop fragmentation attack | Detects and drops malformed overlapping IP fragments designed to crash the TCP/IP stack |
| `syn-flood` | SYN flood DoS | Triggers SYN proxy mode when thresholds are exceeded, protecting the connection table |
| `land` | LAND attack | Drops packets where source and destination IP are identical, used to crash network stacks |
| `udp flood` | UDP flood DoS | Rate-limits UDP packets above the threshold to prevent bandwidth exhaustion |

### Why this matters
Enterprise network equipment like Juniper SRX is widely deployed in Australian corporate and government environments. The ability to configure IDS screens directly on the firewall provides a first line of defence before traffic even reaches host-based IDS tools. This is a practical skill directly relevant to network security engineer and SOC roles.

---

## Key Takeaways

This lab demonstrates the operational reality of intrusion detection: it is not a set-and-forget technology. Effective IDS/IPS requires understanding the protocols being monitored, writing precise detection rules, tuning thresholds to reduce false positives, and interpreting alert output to distinguish real threats from noise. The combination of Snort rule-writing and Juniper SRX configuration shows both open-source and enterprise approaches to the same problem.
