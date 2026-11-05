//! Reproducible VT candidate throughput, scrollback RSS and repaint comparison [5][13].
use alacritty_terminal::{
    event::VoidListener,
    grid::Dimensions,
    term::{Config, Term},
    vte::ansi,
};
use std::{fs, time::Instant};
struct Size;
impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        60
    }
    fn screen_lines(&self) -> usize {
        60
    }
    fn columns(&self) -> usize {
        200
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let candidate = std::env::args().nth(1).unwrap_or_default();
    let fixture = std::env::args().nth(2);
    let has_fixture = fixture.is_some();
    let data = fixture.map_or_else(
        || Ok(b"1234567890 abcdefghijklmnopqrstuvwxyz\r\n".repeat(10_060)),
        fs::read,
    )?;
    let before = rss()?;
    let start = Instant::now();
    #[cfg(feature = "bench-ghostty")]
    if candidate == "ghostty" {
        use libghostty_vt::{
            fmt::{Format, Formatter, FormatterOptions},
            terminal::{Options, Terminal},
        };
        // The C/Rust docs say lines, but the pinned Screen.zig says bytes.
        // Use enough capacity for exactly 10,000 lines and measure that state
        // before the throughput workload grows its memory-limited history.
        let options = Options {
            cols: 200,
            rows: 60,
            max_scrollback: 64 * 1024 * 1024,
        };
        let mut term = Terminal::new(options)?;
        term.vt_write(&data);
        println!(
            "candidate=ghostty first_pass_RSS_delta_KiB={} history={}",
            rss()? - before,
            term.scrollback_rows()?
        );
        let start = Instant::now();
        for _ in 0..100 {
            term.vt_write(&data);
        }
        println!(
            "candidate=ghostty MB/s={:.2} total_RSS_KiB={} history={}",
            f64::from(u32::try_from(data.len())?) * 100.0 / start.elapsed().as_secs_f64() / 1e6,
            rss()?,
            term.scrollback_rows()?
        );
        if let Some(path) = std::env::args().nth(2) {
            let mut original = Terminal::new(options)?;
            original.vt_write(b"PRIMARY-SCREEN-CANARY\r\n");
            original.vt_write(&data);
            let snapshot_options = FormatterOptions::new()
                .with_format(Format::Vt)
                .with_modes(true)
                .with_cursor(true)
                .with_style(true)
                .with_scrolling_region(true)
                .with_tabstops(true)
                .with_charsets(true)
                .with_keyboard(true);
            let mut formatter = Formatter::new(&original, snapshot_options)?;
            let snapshot = formatter.format_alloc(None)?.to_vec();
            drop(formatter);
            let mut restored = Terminal::new(options)?;
            restored.vt_write(&snapshot);
            let plain = |term: &Terminal| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
                Ok(
                    Formatter::new(term, FormatterOptions::new().with_format(Format::Plain))?
                        .format_alloc(None)?
                        .to_vec(),
                )
            };
            println!(
                "repaint_equal={} cursor_equal={} bytes={}",
                plain(&original)? == plain(&restored)?,
                (original.cursor_x()?, original.cursor_y()?)
                    == (restored.cursor_x()?, restored.cursor_y()?),
                snapshot.len()
            );
            let continuation = fs::read(path.replace(".vt", ".continue.vt"))?;
            original.vt_write(&continuation);
            restored.vt_write(&continuation);
            println!(
                "continuation_equal={}",
                plain(&original)? == plain(&restored)?
            );
        }
        return Ok(());
    }
    if candidate == "alacritty" {
        let mut term = Term::new(
            Config {
                scrolling_history: 10_000,
                ..Config::default()
            },
            &Size,
            VoidListener,
        );
        let mut parser: ansi::Processor = ansi::Processor::new();
        for _ in 0..100 {
            parser.advance(&mut term, &data);
        }
        println!(
            "candidate=alacritty MB/s={:.2} RSS_delta_KiB={} total_RSS_KiB={} history={}",
            f64::from(u32::try_from(data.len())?) * 100.0 / start.elapsed().as_secs_f64() / 1e6,
            rss()? - before,
            rss()?,
            term.grid().history_size()
        );
    } else {
        let mut parser = vt100::Parser::new(60, 200, 10_000);
        if has_fixture {
            parser.process(b"PRIMARY-SCREEN-CANARY\r\n");
        }
        for _ in 0..100 {
            parser.process(&data);
        }
        println!(
            "candidate=vt100 MB/s={:.2} RSS_delta_KiB={} total_RSS_KiB={}",
            f64::from(u32::try_from(data.len())?) * 100.0 / start.elapsed().as_secs_f64() / 1e6,
            rss()? - before,
            rss()?
        );
        let start = Instant::now();
        let mut snapshot = Vec::new();
        for _ in 0..1000 {
            snapshot = parser.screen().state_formatted();
            std::hint::black_box(&snapshot);
        }
        println!(
            "screen_snapshot_us={:.2} bytes={}",
            start.elapsed().as_secs_f64() * 1e6 / 1000.0,
            snapshot.len()
        );
        let mut restored = vt100::Parser::new(60, 200, 10_000);
        restored.process(&snapshot);
        println!(
            "repaint_equal={} cursor_equal={}",
            restored.screen().contents() == parser.screen().contents(),
            restored.screen().cursor_position() == parser.screen().cursor_position()
        );
        if let Some(path) = std::env::args().nth(2) {
            println!(
                "alternate_mode_equal={}",
                parser.screen().alternate_screen() == restored.screen().alternate_screen()
            );
            let continuation = fs::read(path.replace(".vt", ".continue.vt"))?;
            parser.process(&continuation);
            restored.process(&continuation);
            println!(
                "continuation_equal={}",
                parser.screen().contents() == restored.screen().contents()
            );
        }
    }
    Ok(())
}
fn rss() -> Result<u64, Box<dyn std::error::Error>> {
    let status = fs::read_to_string("/proc/self/status")?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .ok_or("no RSS")?;
    Ok(value.split_whitespace().next().ok_or("no value")?.parse()?)
}
