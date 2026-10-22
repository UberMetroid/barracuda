//! Fail-closed IPv4/IPv6 iptables killswitch and sysctl lockdown.

use crate::verify_peer::run_cmd;

fn rule(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).to_string()).collect()
}

pub fn lock_down_ipv6_and_sysctl() {
    for kv in [
        "net.ipv6.conf.all.disable_ipv6=1",
        "net.ipv6.conf.default.disable_ipv6=1",
        "net.ipv4.conf.all.rp_filter=2",
        "net.ipv4.conf.default.rp_filter=2",
    ] {
        let _ = run_cmd("sysctl", &["-w", kv]);
    }
    for args in [
        &["-P", "INPUT", "DROP"][..],
        &["-P", "FORWARD", "DROP"],
        &["-P", "OUTPUT", "DROP"],
        &["-F"],
        &["-X"],
        &["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
        &["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
    ] {
        let _ = run_cmd("ip6tables", args);
    }
}

pub fn apply_bootstrap_firewall(lan_cidrs: &[String]) {
    lock_down_ipv6_and_sysctl();
    for args in [
        &["-P", "INPUT", "DROP"][..],
        &["-P", "FORWARD", "DROP"],
        &["-P", "OUTPUT", "DROP"],
        &["-F"],
        &["-X"],
        &["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
        &["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        &[
            "-A",
            "INPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
        &[
            "-A",
            "OUTPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    ] {
        let _ = run_cmd("iptables", args);
    }

    for (proto, dport) in [("udp", "53"), ("tcp", "53"), ("tcp", "443")] {
        let _ = run_cmd(
            "iptables",
            &[
                "-A",
                "OUTPUT",
                "-p",
                proto,
                "--dport",
                dport,
                "-m",
                "owner",
                "--uid-owner",
                "0",
                "-j",
                "ACCEPT",
            ],
        );
    }

    for cidr in lan_cidrs {
        for port in ["8112", "8118", "9099"] {
            let _ = run_cmd(
                "iptables",
                &[
                    "-A", "INPUT", "-s", cidr, "-p", "tcp", "--dport", port, "-j", "ACCEPT",
                ],
            );
            let _ = run_cmd(
                "iptables",
                &[
                    "-A", "OUTPUT", "-d", cidr, "-p", "tcp", "--sport", port, "-j", "ACCEPT",
                ],
            );
        }
    }
}

pub fn build_killswitch_rules(
    wg_ip: &str,
    wg_port: u16,
    lan_cidrs: &[String],
    dns_servers: &[String],
) -> Vec<Vec<String>> {
    let port_str = wg_port.to_string();
    let mut rules: Vec<Vec<String>> = vec![
        rule(&["-P", "INPUT", "DROP"]),
        rule(&["-P", "FORWARD", "DROP"]),
        rule(&["-P", "OUTPUT", "DROP"]),
        rule(&["-F"]),
        rule(&["-X"]),
        rule(&["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"]),
        rule(&["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]),
        rule(&[
            "-A",
            "INPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ]),
        rule(&[
            "-A",
            "OUTPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ]),
        rule(&[
            "-A", "OUTPUT", "-d", wg_ip, "-p", "udp", "--dport", &port_str, "-j", "ACCEPT",
        ]),
    ];

    for cidr in lan_cidrs {
        for port in ["8112", "8118", "9099"] {
            rules.push(rule(&[
                "-A", "INPUT", "-s", cidr, "-p", "tcp", "--dport", port, "-j", "ACCEPT",
            ]));
            rules.push(rule(&[
                "-A", "OUTPUT", "-d", cidr, "-p", "tcp", "--sport", port, "-j", "ACCEPT",
            ]));
        }
        rules.push(rule(&[
            "-A",
            "OUTPUT",
            "-d",
            cidr,
            "-p",
            "tcp",
            "-m",
            "multiport",
            "--dports",
            "7878,8686,8989,9696",
            "-j",
            "ACCEPT",
        ]));
    }

    for dns in dns_servers {
        for proto in ["udp", "tcp"] {
            rules.push(rule(&[
                "-A", "OUTPUT", "-o", "wg0", "-d", dns, "-p", proto, "--dport", "53", "-j",
                "ACCEPT",
            ]));
        }
    }

    for (proto, dport) in [("udp", "53"), ("tcp", "53"), ("tcp", "853"), ("udp", "853")] {
        rules.push(rule(&[
            "-A", "OUTPUT", "-p", proto, "--dport", dport, "-j", "DROP",
        ]));
    }

    // Never accept unsolicited inbound traffic on wg0 to ports 8112, 8118, or 9099!
    rules.push(rule(&[
        "-A",
        "INPUT",
        "-i",
        "wg0",
        "-p",
        "tcp",
        "-m",
        "multiport",
        "--dports",
        "8112,8118,9099",
        "-j",
        "DROP",
    ]));
    rules.push(rule(&["-A", "OUTPUT", "-o", "wg0", "-j", "ACCEPT"]));
    rules
}

pub fn apply_strict_killswitch(
    wg_ip: &str,
    wg_port: u16,
    lan_cidrs: &[String],
    dns_servers: &[String],
) -> Result<(), String> {
    lock_down_ipv6_and_sysctl();
    for r in build_killswitch_rules(wg_ip, wg_port, lan_cidrs, dns_servers) {
        let refs: Vec<&str> = r.iter().map(String::as_str).collect();
        run_cmd("iptables", &refs)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_build_killswitch_rules() {
        let rules = build_killswitch_rules(
            "198.51.100.10",
            1337,
            &["192.168.1.0/24".to_string()],
            &["10.0.0.243".to_string()],
        );
        assert!(rules.iter().any(|r| r == &["-P", "OUTPUT", "DROP"]));
        assert!(rules
            .iter()
            .any(|r| r.contains(&"8112,8118,9099".to_string())));
        assert!(!rules
            .iter()
            .any(|r| r == &["-A", "INPUT", "-i", "wg0", "-j", "ACCEPT"]));
    }
}
