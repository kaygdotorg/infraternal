//! Removes build-only SQL comments and outer whitespace while preserving quoted text verbatim [243].

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Sql,
    Quoted(u8),
    Bracket,
    Block,
}

/// SQLite still parses the SQL; this only removes whitespace known to be outside quoted text.
pub fn compact(sql: &str) -> String {
    let mut result = String::with_capacity(sql.len());
    let mut state = State::Sql;
    for line in sql.split_inclusive('\n') {
        let plain_start = state == State::Sql;
        let leading = line.trim_start_matches(|c: char| c.is_ascii_whitespace());
        if plain_start && leading.starts_with("--") {
            continue;
        }
        let end = advance(line.as_bytes(), &mut state);
        let line_text = &line[..end];
        let mut text = if plain_start {
            line_text.trim_start_matches(|c: char| c.is_ascii_whitespace())
        } else {
            line_text
        };
        if state == State::Sql {
            text = text.trim_end_matches(|c: char| c.is_ascii_whitespace());
        }
        if !text.is_empty() {
            result.push_str(text);
            if state == State::Sql && line.ends_with('\n') {
                result.push('\n');
            }
        }
    }
    result
}

fn advance(bytes: &[u8], state: &mut State) -> usize {
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        let next = bytes.get(at + 1).copied();
        match *state {
            State::Sql => match (byte, next) {
                (b'-', Some(b'-')) => return at,
                (b'/', Some(b'*')) => {
                    *state = State::Block;
                    at += 1;
                }
                (b'\'' | b'"' | b'`', _) => *state = State::Quoted(byte),
                (b'[', _) => *state = State::Bracket,
                _ => {}
            },
            State::Quoted(quote) if byte == quote => {
                if next == Some(quote) {
                    at += 1;
                } else {
                    *state = State::Sql;
                }
            }
            State::Bracket if byte == b']' => *state = State::Sql,
            State::Block if byte == b'*' && next == Some(b'/') => {
                *state = State::Sql;
                at += 1;
            }
            _ => {}
        }
        at += 1;
    }
    bytes.len()
}
