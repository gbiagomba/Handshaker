pub mod file;
pub mod nmap_grep;
pub mod nmap_xml;
pub mod nuclei_json;
pub mod scan_json;
pub mod stdin;
pub mod target_parse;

use crate::cli::ScanArgs;
use crate::errors::{HandshakerError, Result};
use crate::models::Target;

pub fn load_targets(args: &ScanArgs) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    if let Some(t) = &args.target {
        targets.extend(target_parse::parse_targets(t, &args.ports)?);
    }
    if let Some(path) = &args.file {
        targets.extend(file::load_file(path, &args.ports)?);
    }
    if args.stdin {
        targets.extend(stdin::load_stdin(&args.ports)?);
    }
    if targets.is_empty() {
        return Err(HandshakerError::Parse("No targets provided".into()));
    }
    Ok(targets)
}
