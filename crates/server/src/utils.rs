/// Escape LIKE wildcards (% and _) in a search string
pub fn escape_like_wildcards(s: &str) -> String {
    s.replace('%', "\\%").replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_like_wildcards() {
        assert_eq!(escape_like_wildcards("test%_"), "test\\%\\_");
        assert_eq!(escape_like_wildcards("no wildcards"), "no wildcards");
        assert_eq!(escape_like_wildcards("%_"), "\\%\\_");
    }
}