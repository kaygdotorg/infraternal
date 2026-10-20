//! Removes non-executable SQL formatting at build time while preserving quoted text verbatim [243].

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Sql,
    Quoted(u8),
    Bracket,
    Block,
    Line,
}

/// SQLite still parses the SQL; only comments and whitespace outside quoted text are compacted.
#[allow(clippy::expect_used)] // Only ASCII bytes change; the UTF-8 conversion is an invariant.
pub fn compact(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut state = State::Sql;
    let mut pending_space = false;
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        let next = bytes.get(at + 1).copied();
        match state {
            State::Sql => {
                if byte.is_ascii_whitespace() {
                    pending_space = true;
                    at += 1;
                    continue;
                }
                if byte == b'-' && next == Some(b'-') {
                    state = State::Line;
                    pending_space = true;
                    at += 2;
                    continue;
                }
                // Delimiters cannot join two tokens. Keep every other separator,
                // including between operators or adjacent quoted literals.
                if pending_space
                    && result.last().is_some_and(|last| !delimiter(*last))
                    && !delimiter(byte)
                {
                    result.push(b' ');
                }
                pending_space = false;
                match (byte, next) {
                    (b'/', Some(b'*')) => {
                        result.extend_from_slice(b"/*");
                        state = State::Block;
                        at += 2;
                        continue;
                    }
                    (b'\'' | b'"' | b'`', _) => state = State::Quoted(byte),
                    (b'[', _) => state = State::Bracket,
                    _ => {}
                }
            }
            State::Line => {
                if byte == b'\n' {
                    state = State::Sql;
                }
                at += 1;
                continue;
            }
            State::Quoted(quote) if byte == quote => {
                if next == Some(quote) {
                    result.extend_from_slice(&bytes[at..at + 2]);
                    at += 2;
                    continue;
                }
                state = State::Sql;
            }
            State::Bracket if byte == b']' => state = State::Sql,
            State::Block if byte == b'*' && next == Some(b'/') => {
                result.extend_from_slice(b"*/");
                state = State::Sql;
                at += 2;
                continue;
            }
            _ => {}
        }
        result.push(byte);
        at += 1;
    }
    // Only ASCII outside quoted text is removed or replaced; UTF-8 sequences stay intact.
    String::from_utf8(result).expect("SQL formatting preserves UTF-8")
}

fn delimiter(byte: u8) -> bool {
    matches!(byte, b'(' | b')' | b',' | b';')
}
