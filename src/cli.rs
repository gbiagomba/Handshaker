use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "handshaker",
    version,
    about = "Native secure-transport posture engine",
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Scan(Box<ScanArgs>),
    Explain(ExplainArgs),
    Score(ScoreArgs),
    Benchmark(BenchmarkArgs),
    Diff(DiffArgs),
    Ai(AiArgs),
    Db(DbArgs),
    /// Show the detailed manual for a subcommand
    Help(HelpArgs),
}

#[derive(Debug, Parser)]
#[command(about = "Probe one or more targets for TLS/SSH/RDP security posture")]
pub struct ScanArgs {
    /// Single target: hostname, IP, host:port, or URL
    #[arg(short, long)]
    pub target: Option<String>,
    /// File input: plain targets, nmap grep/XML, nuclei JSON(L), or testssl JSON
    #[arg(short, long)]
    pub file: Option<String>,
    /// Read targets from stdin (one per line)
    #[arg(long)]
    pub stdin: bool,
    /// Comma-separated port list (e.g. 443,8443,25)
    #[arg(short, long, value_delimiter = ',')]
    pub ports: Vec<u16>,
    /// Output format: json|text|table|html|csv|sqlite  [default: json]
    #[arg(long, default_value = "json")]
    pub output: OutputFormat,
    /// Write output to this file instead of stdout
    #[arg(short, long)]
    pub out: Option<String>,
    /// Max parallel scans  [default: 32]
    #[arg(long, default_value = "32")]
    pub concurrency: usize,
    /// Per-target connection timeout in seconds  [default: 10]
    #[arg(long, default_value = "10")]
    pub timeout_secs: u64,
    /// YAML policy file for compliance evaluation
    #[arg(long)]
    pub policy: Option<String>,
    /// Exit non-zero when any policy finding fails
    #[arg(long, default_value = "false")]
    pub fail_on_noncompliant: bool,
    /// YAML benchmark profile to evaluate results against
    #[arg(long)]
    pub benchmark: Option<String>,
    /// SQLite database path to persist results
    #[arg(long)]
    pub db: Option<String>,
}

#[derive(Debug, Parser)]
#[command(about = "Print the full explanation for a finding ID from the catalog")]
pub struct ExplainArgs {
    /// Finding ID to look up (e.g. HS-TLS-PROTOCOL-0003)
    pub id: String,
}

#[derive(Debug, Parser)]
#[command(about = "Compute SSL Labs-style scores from a JSON results file")]
pub struct ScoreArgs {
    /// Path to JSON results file
    #[arg(long)]
    pub input: String,
}

#[derive(Debug, Parser)]
#[command(about = "Evaluate a JSON results file against a benchmark profile")]
pub struct BenchmarkArgs {
    /// Path to JSON results file
    #[arg(long)]
    pub input: String,
    /// Path to benchmark YAML profile
    #[arg(long)]
    pub profile: String,
}

#[derive(Debug, Parser)]
#[command(about = "Compare two JSON results files and show added/removed/changed findings")]
pub struct DiffArgs {
    /// Baseline JSON results file
    #[arg(long)]
    pub left: String,
    /// New JSON results file to compare against baseline
    #[arg(long)]
    pub right: String,
}

#[derive(Debug, Parser)]
#[command(about = "Run AI-powered analysis on a JSON results file")]
pub struct AiArgs {
    /// Path to JSON results file
    #[arg(long)]
    pub input: String,
    /// AI provider name (default: built-in)
    #[arg(long)]
    pub provider: Option<String>,
}

#[derive(Debug, Parser)]
#[command(about = "Manage the SQLite results database")]
pub struct DbArgs {
    #[command(subcommand)]
    pub command: DbCommands,
}

#[derive(Debug, Subcommand)]
pub enum DbCommands {
    /// Initialize a new SQLite database
    Init(DbInitArgs),
    /// List all scan runs stored in the database
    List(DbListArgs),
    /// Export a specific run from the database as JSON
    Export(DbExportArgs),
}

#[derive(Debug, Parser)]
#[command(about = "Initialize a new SQLite database at the given path")]
pub struct DbInitArgs {
    /// Path to SQLite database file to initialize
    #[arg(long)]
    pub path: String,
}

#[derive(Debug, Parser)]
#[command(about = "List all scan runs stored in the database")]
pub struct DbListArgs {
    /// Path to SQLite database file
    #[arg(long)]
    pub path: String,
}

#[derive(Debug, Parser)]
#[command(about = "Export a specific run from the database as JSON")]
pub struct DbExportArgs {
    /// Path to SQLite database file
    #[arg(long)]
    pub path: String,
    /// Run ID to export (from `db list`)
    #[arg(long)]
    pub run_id: String,
}

#[derive(Debug, Parser)]
#[command(about = "Show the detailed manual for a subcommand")]
pub struct HelpArgs {
    /// Subcommand name: scan, explain, score, benchmark, diff, ai, db
    pub command: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Json,
    Text,
    Table,
    Html,
    Csv,
    Sqlite,
}
