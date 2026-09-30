//! Plain-text sanitization for display strings (label descriptions).
//! Port of `sanitizeTrustContent` in `AttentionX/src/shared/trust-content.ts`.

/// Removes `<word>\s*:` case-insensitively (ASCII word).
fn strip_scheme(text: &str, word: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let word: Vec<char> = word.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let matches = i + word.len() <= chars.len()
            && chars[i..i + word.len()]
                .iter()
                .zip(&word)
                .all(|(a, b)| a.to_ascii_lowercase() == *b);
        if matches {
            let mut j = i + word.len();
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            if j < chars.len() && chars[j] == ':' {
                i = j + 1;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn strip_event_handlers(text: &str) -> String {
    // Removes `\bon[a-z]+\s*=` case-insensitively.
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let boundary = i == 0 || !is_word(chars[i - 1]);
        if boundary
            && i + 2 < chars.len()
            && chars[i].eq_ignore_ascii_case(&'o')
            && chars[i + 1].eq_ignore_ascii_case(&'n')
            && chars[i + 2].is_ascii_alphabetic()
        {
            let mut j = i + 2;
            while j < chars.len() && chars[j].is_ascii_alphabetic() {
                j += 1;
            }
            let mut k = j;
            while k < chars.len() && chars[k].is_whitespace() {
                k += 1;
            }
            if k < chars.len() && chars[k] == '=' {
                i = k + 1;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Sanitizes untrusted display text and clamps it to `limit` Unicode
/// characters.
pub fn sanitize(input: &str, limit: usize) -> String {
    if input.is_empty() {
        return String::new();
    }
    let text = input.replace("\r\n", "\n").replace('\r', "\n");
    let text: String = text
        .chars()
        .filter(|&ch| {
            if ch == '\n' {
                return true;
            }
            let code = ch as u32;
            !(code < 0x20 || (0x7f..=0x9f).contains(&code))
        })
        .filter(|&ch| ch != '<' && ch != '>')
        .collect();
    let text = strip_scheme(&text, "javascript");
    let text = strip_scheme(&text, "vbscript");
    let text = strip_scheme(&text, "data");
    let text = strip_event_handlers(&text);
    let mut collapsed = String::with_capacity(text.len());
    let mut newlines = 0;
    for ch in text.chars() {
        if ch == '\n' {
            newlines += 1;
            if newlines <= 2 {
                collapsed.push(ch);
            }
        } else {
            newlines = 0;
            collapsed.push(ch);
        }
    }
    let trimmed = collapsed.trim();
    trimmed.chars().take(limit).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_markup_and_schemes() {
        assert_eq!(sanitize("<b>hi</b>", 100), "bhi/b");
        assert_eq!(sanitize("javascript :alert(1)", 100), "alert(1)");
        assert_eq!(sanitize("x onClick = y", 100), "x  y");
        assert_eq!(sanitize("a\r\n\n\n\nb", 100), "a\n\nb");
        assert_eq!(sanitize("  ok\u{7}  ", 100), "ok");
        assert_eq!(sanitize("abcdef", 3), "abc");
    }
}
