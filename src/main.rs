use clap::Parser;
use handshaker::errors::Result;
use handshaker::models::{RunSummary, ScanResult};
use handshaker::output::OutputWriter;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = handshaker::cli::Cli::parse();
    match cli.command {
        handshaker::cli::Commands::Scan(args) => {
            let targets = handshaker::input::load_targets(&args)?;
            let engine = handshaker::engine::Engine::new(args.concurrency, args.timeout_secs);
            let results = engine.scan_targets(&targets).await?;

            let mut output = OutputWriter::new(args.output, args.out)?;
            output.write_scan(&results)?;

            let mut compliance_result = None;
            if let Some(profile) = args.policy.clone() {
                let compliance = handshaker::compliance::evaluate(&profile, &results)?;
                output.write_compliance(&compliance)?;
                if args.fail_on_noncompliant && !compliance.compliant {
                    return Err(handshaker::errors::HandshakerError::Config(
                        "Compliance check failed".into(),
                    ));
                }
                compliance_result = Some(compliance);
            }
            let mut benchmark_result = None;
            if let Some(profile) = args.benchmark.clone() {
                let bench = handshaker::benchmark::evaluate(&profile, &results)?;
                output.write_benchmark(&bench)?;
                benchmark_result = Some(bench);
            }

            if let Some(db_path) = args.db {
                let run = RunSummary {
                    run_id: handshaker::output::sqlite::new_run_id(),
                    started_at: chrono::Utc::now(),
                    targets: results.len(),
                    findings: results.iter().map(|r| r.findings.len()).sum(),
                };
                handshaker::output::sqlite::insert_run(&db_path, &run, &results)?;
                if let Some(c) = compliance_result {
                    handshaker::output::sqlite::insert_compliance(&db_path, &run.run_id, &c)?;
                }
                if let Some(b) = benchmark_result {
                    handshaker::output::sqlite::insert_benchmark(&db_path, &run.run_id, &b)?;
                }
            }
        }
        handshaker::cli::Commands::Explain(args) => {
            let meta = handshaker::findings::catalog::find_by_id(&args.id).ok_or_else(|| {
                handshaker::errors::HandshakerError::Parse("Unknown finding ID".into())
            })?;
            handshaker::output::write_explain(meta)?;
        }
        handshaker::cli::Commands::Score(args) => {
            let results: Vec<ScanResult> = handshaker::output::read_json(&args.input)?;
            let score = handshaker::scoring::aggregate_scores(&results)?;
            handshaker::output::write_score(&score)?;
            let cvss = handshaker::scoring::aggregate::aggregate_cvss(&results);
            println!("CVSS-aligned configuration risk score");
            println!(
                "risk_max: {:.1} | risk_weighted: {:.1}",
                cvss.risk_max, cvss.risk_weighted
            );
        }
        handshaker::cli::Commands::Benchmark(args) => {
            let results: Vec<ScanResult> = handshaker::output::read_json(&args.input)?;
            let bench = handshaker::benchmark::evaluate(&args.profile, &results)?;
            handshaker::output::write_benchmark(&bench)?;
        }
        handshaker::cli::Commands::Diff(args) => {
            let left: Vec<ScanResult> = handshaker::output::read_json(&args.left)?;
            let right: Vec<ScanResult> = handshaker::output::read_json(&args.right)?;
            let diff = handshaker::diff::compare(&left, &right);
            handshaker::output::write_diff(&diff)?;
        }
        handshaker::cli::Commands::Ai(args) => {
            let results: Vec<ScanResult> = handshaker::output::read_json(&args.input)?;
            handshaker::ai::run(&results, args.provider.as_deref())?;
        }
        handshaker::cli::Commands::Db(args) => match args.command {
            handshaker::cli::DbCommands::Init(i) => handshaker::output::sqlite::init_db(&i.path)?,
            handshaker::cli::DbCommands::List(l) => handshaker::output::sqlite::list_runs(&l.path)?,
            handshaker::cli::DbCommands::Export(e) => {
                handshaker::output::sqlite::export_run(&e.path, &e.run_id)?
            }
        },
        handshaker::cli::Commands::Help(args) => {
            handshaker::output::write_manual(args.command.as_deref())?;
        }
    }
    Ok(())
}
