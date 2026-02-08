/// Escape LIKE wildcards (% and _) in a search string
pub fn escape_like_wildcards(s: &str) -> String {
    s.replace('%', "\\%").replace('_', "\\_")
}