//! `--key value` argument parsing; the kit's scripts are the only callers.
use std::collections::HashMap;

/// Parsed values from the benchmark command's `--key value` arguments.
pub struct Args(HashMap<String, String>);

impl Args {
    /// Parse alternating option and value tokens, exiting on malformed input.
    pub fn parse(raw: &[String]) -> Self {
        let mut map = HashMap::new();
        let mut iter = raw.iter();
        while let Some(key) = iter.next() {
            let key = key.strip_prefix("--").unwrap_or_else(|| die(&format!("unexpected argument {key}")));
            let value = iter.next().cloned().unwrap_or_else(|| die(&format!("--{key} needs a value")));
            map.insert(key.to_owned(), value);
        }
        Self(map)
    }
    /// Return a required string option or print a usage error.
    pub fn str(&self, key: &str) -> String {
        self.0.get(key).cloned().unwrap_or_else(|| die(&format!("missing --{key}")))
    }
    /// Return an optional string option without applying a default.
    pub fn opt(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
    /// Parse a numeric option, using `default` only when it was omitted.
    pub fn num<T: std::str::FromStr>(&self, key: &str, default: T) -> T {
        match self.0.get(key) {
            Some(v) => v.parse().unwrap_or_else(|_| die(&format!("--{key}: not a number"))),
            None => default,
        }
    }
}

/// Print a command-line error and stop the benchmark process with status 2.
pub fn die(message: &str) -> ! {
    eprintln!("h2h: {message}");
    std::process::exit(2)
}
