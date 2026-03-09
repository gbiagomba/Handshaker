use crate::findings::catalog;
use crate::findings::types::FindingMeta;

pub fn explain(id: &str) -> Option<&'static FindingMeta> {
    catalog::find_by_id(id)
}
