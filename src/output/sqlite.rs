use crate::errors::Result;
use crate::models::{BenchmarkResult, ComplianceResult, RunSummary, ScanResult, ScoreSummary};
use rand::RngCore;
use rusqlite::{params, Connection};

pub fn new_run_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn init_db(path: &str) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            started_at TEXT NOT NULL,
            targets INTEGER NOT NULL,
            findings INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS targets (
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            target TEXT NOT NULL,
            protocol TEXT NOT NULL,
            PRIMARY KEY (run_id, target)
        );
        CREATE TABLE IF NOT EXISTS findings (
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            target TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            details TEXT NOT NULL,
            cvss_vector TEXT NOT NULL,
            cvss_score REAL NOT NULL,
            UNIQUE (run_id, target, finding_id)
        );
        CREATE TABLE IF NOT EXISTS scores (
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            category TEXT NOT NULL,
            score INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS compliance (
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            profile TEXT NOT NULL,
            compliant INTEGER NOT NULL,
            failed_controls TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS benchmark (
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            profile TEXT NOT NULL,
            score INTEGER NOT NULL,
            failures TEXT NOT NULL
        );
        "#,
    )?;
    Ok(())
}

pub fn insert_run(path: &str, run: &RunSummary, results: &[ScanResult]) -> Result<()> {
    init_db(path)?;
    let conn = Connection::open(path)?;
    conn.execute(
        "INSERT INTO runs (run_id, started_at, targets, findings) VALUES (?1, ?2, ?3, ?4)",
        params![
            run.run_id,
            run.started_at.to_rfc3339(),
            run.targets as i64,
            run.findings as i64
        ],
    )?;
    for r in results {
        let target = format!("{}:{}", r.target.host, r.target.port);
        conn.execute(
            "INSERT INTO targets (run_id, target, protocol) VALUES (?1, ?2, ?3)",
            params![
                run.run_id,
                target,
                r.metadata["protocol"].as_str().unwrap_or("unknown")
            ],
        )?;
        for f in &r.findings {
            conn.execute(
                "INSERT INTO findings (run_id, target, finding_id, severity, title, details, cvss_vector, cvss_score)\n                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    run.run_id,
                    target,
                    f.id,
                    format!("{:?}", f.severity),
                    f.title,
                    f.details,
                    f.cvss_vector,
                    f.cvss_score
                ],
            )?;
        }
    }
    let score = crate::scoring::ssllabs::score(results);
    insert_score(&conn, &run.run_id, &score)?;
    Ok(())
}

fn insert_score(conn: &Connection, run_id: &str, score: &ScoreSummary) -> Result<()> {
    conn.execute(
        "INSERT INTO scores (run_id, category, score) VALUES (?1, ?2, ?3)",
        params![run_id, "certificate", score.certificate],
    )?;
    conn.execute(
        "INSERT INTO scores (run_id, category, score) VALUES (?1, ?2, ?3)",
        params![run_id, "protocol", score.protocol],
    )?;
    conn.execute(
        "INSERT INTO scores (run_id, category, score) VALUES (?1, ?2, ?3)",
        params![run_id, "key_exchange", score.key_exchange],
    )?;
    conn.execute(
        "INSERT INTO scores (run_id, category, score) VALUES (?1, ?2, ?3)",
        params![run_id, "cipher_strength", score.cipher_strength],
    )?;
    conn.execute(
        "INSERT INTO scores (run_id, category, score) VALUES (?1, ?2, ?3)",
        params![run_id, "overall", score.overall],
    )?;
    Ok(())
}

pub fn insert_compliance(path: &str, run_id: &str, result: &ComplianceResult) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute(
        "INSERT INTO compliance (run_id, profile, compliant, failed_controls) VALUES (?1, ?2, ?3, ?4)",
        params![run_id, result.profile, result.compliant as i64, result.failed_controls.join(",")],
    )?;
    Ok(())
}

pub fn insert_benchmark(path: &str, run_id: &str, result: &BenchmarkResult) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute(
        "INSERT INTO benchmark (run_id, profile, score, failures) VALUES (?1, ?2, ?3, ?4)",
        params![
            run_id,
            result.profile,
            result.score as i64,
            result.failures.join(",")
        ],
    )?;
    Ok(())
}

pub fn list_runs(path: &str) -> Result<()> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("SELECT run_id, started_at, targets, findings FROM runs")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    for row in rows {
        let (id, started_at, targets, findings) = row?;
        println!("{id} | {started_at} | targets={targets} | findings={findings}");
    }
    Ok(())
}

pub fn export_run(path: &str, run_id: &str) -> Result<()> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare(
        "SELECT target, finding_id, severity, title, details FROM findings WHERE run_id = ?1",
    )?;
    let rows = stmt.query_map(params![run_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    for row in rows {
        let (target, id, severity, title, details) = row?;
        println!("{target} | {id} | {severity} | {title} | {details}");
    }
    Ok(())
}
