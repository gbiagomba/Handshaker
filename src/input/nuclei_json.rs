use crate::errors::Result;
use crate::models::Target;

pub fn load_nuclei_json(path: &str) -> Result<Vec<Target>> {
    super::scan_json::load_scan_json(path)
}
