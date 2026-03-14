use crate::errors::{HandshakerError, Result};
use crate::models::Severity;

#[derive(Debug, Clone, Copy)]
pub struct CvssMetrics {
    av: f64,
    ac: f64,
    pr: f64,
    ui: f64,
    s: char,
    c: f64,
    i: f64,
    a: f64,
}

pub fn score(vector: &str) -> Result<f64> {
    let metrics = parse(vector)?;
    let isc = 1.0 - (1.0 - metrics.c) * (1.0 - metrics.i) * (1.0 - metrics.a);
    let impact = if metrics.s == 'U' {
        6.42 * isc
    } else {
        7.52 * (isc - 0.029) - 3.25 * (isc - 0.02).powf(15.0)
    };
    let exploitability = 8.22 * metrics.av * metrics.ac * metrics.pr * metrics.ui;
    let base = if impact <= 0.0 {
        0.0
    } else if metrics.s == 'U' {
        (impact + exploitability).min(10.0)
    } else {
        (1.08 * (impact + exploitability)).min(10.0)
    };
    Ok(roundup_1dp(base))
}

pub fn severity(score: f64) -> Severity {
    if score <= 0.0 {
        Severity::Info
    } else if score < 4.0 {
        Severity::Low
    } else if score < 7.0 {
        Severity::Medium
    } else if score < 9.0 {
        Severity::High
    } else {
        Severity::Critical
    }
}

fn parse(vector: &str) -> Result<CvssMetrics> {
    if !vector.starts_with("CVSS:3.1/") {
        return Err(HandshakerError::Parse("Invalid CVSS vector".into()));
    }
    let mut av = None;
    let mut ac = None;
    let mut pr_raw: Option<char> = None;
    let mut ui = None;
    let mut s = None;
    let mut c = None;
    let mut i = None;
    let mut a = None;

    for part in vector["CVSS:3.1/".len()..].split('/') {
        let mut kv = part.split(':');
        let key = kv.next().unwrap_or("");
        let val = kv.next().unwrap_or("");
        match key {
            "AV" => {
                av = Some(match val {
                    "N" => 0.85,
                    "A" => 0.62,
                    "L" => 0.55,
                    "P" => 0.2,
                    _ => return Err(HandshakerError::Parse("Invalid AV".into())),
                })
            }
            "AC" => {
                ac = Some(match val {
                    "L" => 0.77,
                    "H" => 0.44,
                    _ => return Err(HandshakerError::Parse("Invalid AC".into())),
                })
            }
            "PR" => pr_raw = Some(val.chars().next().unwrap_or('N')),
            "UI" => {
                ui = Some(match val {
                    "N" => 0.85,
                    "R" => 0.62,
                    _ => return Err(HandshakerError::Parse("Invalid UI".into())),
                })
            }
            "S" => s = Some(val.chars().next().unwrap_or('U')),
            "C" => {
                c = Some(match val {
                    "N" => 0.0,
                    "L" => 0.22,
                    "H" => 0.56,
                    _ => return Err(HandshakerError::Parse("Invalid C".into())),
                })
            }
            "I" => {
                i = Some(match val {
                    "N" => 0.0,
                    "L" => 0.22,
                    "H" => 0.56,
                    _ => return Err(HandshakerError::Parse("Invalid I".into())),
                })
            }
            "A" => {
                a = Some(match val {
                    "N" => 0.0,
                    "L" => 0.22,
                    "H" => 0.56,
                    _ => return Err(HandshakerError::Parse("Invalid A".into())),
                })
            }
            _ => {}
        }
    }
    let scope = s.ok_or_else(|| HandshakerError::Parse("Missing S".into()))?;
    let pr = match (
        scope,
        pr_raw.ok_or_else(|| HandshakerError::Parse("Missing PR".into()))?,
    ) {
        ('U', 'N') => 0.85,
        ('U', 'L') => 0.62,
        ('U', 'H') => 0.27,
        ('C', 'N') => 0.85,
        ('C', 'L') => 0.68,
        ('C', 'H') => 0.50,
        _ => return Err(HandshakerError::Parse("Invalid PR".into())),
    };
    Ok(CvssMetrics {
        av: av.ok_or_else(|| HandshakerError::Parse("Missing AV".into()))?,
        ac: ac.ok_or_else(|| HandshakerError::Parse("Missing AC".into()))?,
        pr,
        ui: ui.ok_or_else(|| HandshakerError::Parse("Missing UI".into()))?,
        s: scope,
        c: c.ok_or_else(|| HandshakerError::Parse("Missing C".into()))?,
        i: i.ok_or_else(|| HandshakerError::Parse("Missing I".into()))?,
        a: a.ok_or_else(|| HandshakerError::Parse("Missing A".into()))?,
    })
}

fn roundup_1dp(value: f64) -> f64 {
    (value * 10.0).ceil() / 10.0
}
