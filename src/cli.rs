use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "handshaker",
    version,
    about = "Native secure-transport posture engine"
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
}

#[derive(Debug, Parser)]
pub struct ScanArgs {
    #[arg(short, long)]
    pub target: Option<String>,
    #[arg(short, long)]
    pub file: Option<String>,
    #[arg(long)]
    pub nmap_grep: Option<String>,
    #[arg(long)]
    pub nmap_xml: Option<String>,
    #[arg(long)]
    pub nuclei_json: Option<String>,
    #[arg(long)]
    pub stdin: bool,
    #[arg(short, long, value_delimiter = ',')]
    pub ports: Vec<u16>,
    #[arg(long, default_value = "json")]
    pub output: OutputFormat,
    #[arg(short, long)]
    pub out: Option<String>,
    #[arg(long, default_value = "32")]
    pub concurrency: usize,
    #[arg(long, default_value = "10")]
    pub timeout_secs: u64,
    #[arg(long)]
    pub policy: Option<String>,
    #[arg(long, default_value = "false")]
    pub fail_on_noncompliant: bool,
    #[arg(long)]
    pub benchmark: Option<String>,
    #[arg(long)]
    pub db: Option<String>,
}

#[derive(Debug, Parser)]
pub struct ExplainArgs {
    pub id: String,
}

#[derive(Debug, Parser)]
pub struct ScoreArgs {
    #[arg(long)]
    pub input: String,
}

#[derive(Debug, Parser)]
pub struct BenchmarkArgs {
    #[arg(long)]
    pub input: String,
    #[arg(long)]
    pub profile: String,
}

#[derive(Debug, Parser)]
pub struct DiffArgs {
    #[arg(long)]
    pub left: String,
    #[arg(long)]
    pub right: String,
}

#[derive(Debug, Parser)]
pub struct AiArgs {
    #[arg(long)]
    pub input: String,
    #[arg(long)]
    pub provider: Option<String>,
}

#[derive(Debug, Parser)]
pub struct DbArgs {
    #[command(subcommand)]
    pub command: DbCommands,
}

#[derive(Debug, Subcommand)]
pub enum DbCommands {
    Init(DbInitArgs),
    List(DbListArgs),
    Export(DbExportArgs),
}

#[derive(Debug, Parser)]
pub struct DbInitArgs {
    #[arg(long)]
    pub path: String,
}

#[derive(Debug, Parser)]
pub struct DbListArgs {
    #[arg(long)]
    pub path: String,
}

#[derive(Debug, Parser)]
pub struct DbExportArgs {
    #[arg(long)]
    pub path: String,
    #[arg(long)]
    pub run_id: String,
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
