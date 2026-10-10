//! Measures the same asynchronous runtime without linking the research SSH client.
#![forbid(unsafe_code)]
#[tokio::main]
async fn main() {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    let _ = tokio::io::stdin().take(65537).read_to_end(&mut bytes).await;
    println!("fixture baseline ready");
}
