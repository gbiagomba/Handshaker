use crate::models::{ScanResult, ScoreSummary};

pub fn score(results: &[ScanResult]) -> ScoreSummary {
    let mut cert: u32 = 100;
    let mut protocol: u32 = 100;
    let mut key_exchange: u32 = 100;
    let mut cipher: u32 = 100;
    let mut caps: Vec<String> = Vec::new();

    for r in results {
        for f in &r.findings {
            match f.id.as_str() {
                "HS-TLS-CERT-0001" | "HS-TLS-CERT-0002" | "HS-TLS-CERT-0003" => {
                    cert = cert.saturating_sub(40);
                    caps.push("Invalid certificate".into());
                }
                "HS-TLS-CERT-0005" | "HS-TLS-CERT-0006" => {
                    cert = cert.saturating_sub(20);
                }
                "HS-TLS-PROTOCOL-0001" | "HS-TLS-PROTOCOL-0002" => {
                    protocol = protocol.saturating_sub(60);
                    caps.push("SSLv2/SSLv3 supported".into());
                }
                "HS-TLS-PROTOCOL-0003" | "HS-TLS-PROTOCOL-0004" => {
                    protocol = protocol.saturating_sub(20);
                    caps.push("TLS 1.0/1.1 enabled".into());
                }
                "HS-TLS-CIPHER-0001" | "HS-TLS-CIPHER-0002" | "HS-TLS-CIPHER-0003" => {
                    cipher = cipher.saturating_sub(50);
                    caps.push("NULL/aNULL/EXPORT ciphers".into());
                }
                "HS-TLS-CIPHER-0004" | "HS-TLS-CIPHER-0005" => {
                    cipher = cipher.saturating_sub(20);
                    caps.push("RC4/3DES supported".into());
                }
                "HS-TLS-CIPHER-0009" | "HS-TLS-CIPHER-0010" => {
                    key_exchange = key_exchange.saturating_sub(20);
                    caps.push("No forward secrecy".into());
                }
                "HS-TLS-SCENARIO-0004" => {
                    key_exchange = key_exchange.saturating_sub(30);
                    caps.push("Weak DH parameters".into());
                }
                _ => {}
            }
        }
    }

    let overall = ((cert * 30 + protocol * 30 + key_exchange * 20 + cipher * 20) / 100).min(100);
    let mut grade = grade_from_score(overall);
    let mut cap_reasons = Vec::new();
    for cap in &caps {
        if cap.contains("SSLv2") || cap.contains("SSLv3") {
            grade = cap_grade(&grade, "F");
            cap_reasons.push("Grade capped to F due to SSLv2/SSLv3".into());
        }
        if cap.contains("Invalid certificate") {
            grade = cap_grade(&grade, "C");
            cap_reasons.push("Grade capped to C due to invalid certificate".into());
        }
        if cap.contains("TLS 1.0/1.1 enabled") {
            grade = cap_grade(&grade, "B");
            cap_reasons.push("Grade capped to B due to TLS 1.0/1.1".into());
        }
        if cap.contains("No forward secrecy") {
            grade = cap_grade(&grade, "B");
            cap_reasons.push("Grade capped to B due to missing forward secrecy".into());
        }
        if cap.contains("NULL/aNULL/EXPORT ciphers") {
            grade = cap_grade(&grade, "C");
            cap_reasons.push("Grade capped to C due to NULL/aNULL/EXPORT".into());
        }
        if cap.contains("RC4/3DES supported") {
            grade = cap_grade(&grade, "B");
            cap_reasons.push("Grade capped to B due to RC4/3DES".into());
        }
    }
    caps.extend(cap_reasons);
    ScoreSummary {
        certificate: cert,
        protocol,
        key_exchange,
        cipher_strength: cipher,
        overall,
        grade,
        caps,
    }
}

fn grade_from_score(score: u32) -> String {
    match score {
        90..=100 => "A+".into(),
        80..=89 => "A".into(),
        70..=79 => "B".into(),
        60..=69 => "C".into(),
        50..=59 => "D".into(),
        _ => "F".into(),
    }
}

fn cap_grade(current: &str, cap: &str) -> String {
    let order = ["A+", "A", "B", "C", "D", "F"];
    let cur_idx = order.iter().position(|g| g == &current).unwrap_or(5);
    let cap_idx = order.iter().position(|g| g == &cap).unwrap_or(5);
    if cap_idx > cur_idx {
        cap.to_string()
    } else {
        current.to_string()
    }
}
