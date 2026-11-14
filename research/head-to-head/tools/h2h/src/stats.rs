//! Sample summaries shared by every measurement: nearest-rank percentiles,
//! the same rank rule as `scripts/verify-latency.py`, so numbers compare.
use serde_json::{Value, json};

/// Nearest-rank percentile of an already sorted slice.
fn rank(sorted: &[f64], fraction: f64) -> f64 {
    let n = sorted.len();
    let index = ((n as f64 * fraction).ceil() as usize).clamp(1, n) - 1;
    sorted[index]
}

/// Summarise samples (milliseconds unless the caller says otherwise).
pub fn summary(samples: &[f64]) -> Value {
    if samples.is_empty() {
        return json!({"n": 0});
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let r = |v: f64| (v * 1000.0).round() / 1000.0;
    json!({
        "n": sorted.len(),
        "min": r(sorted[0]),
        "p50": r(rank(&sorted, 0.50)),
        "p90": r(rank(&sorted, 0.90)),
        "p99": r(rank(&sorted, 0.99)),
        "max": r(sorted[sorted.len() - 1]),
        "mean": r(mean),
    })
}

/// Summarize percentiles over the sent count, placing every missing reply at
/// an infinite RTT. A null rank is explicitly paired with `infinite_at` so
/// JSON never uses a non-standard NaN or infinity number.
pub fn loss_aware_summary(samples: &[f64], sent: usize) -> Value {
    if sent == 0 {
        return json!({"n": 0, "lost": 0, "p50": null, "p99": null, "p999": null,
                      "infinite_at": ["p50", "p99", "p999"]});
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let percentile = |fraction: f64| -> Option<f64> {
        let index = ((sent as f64 * fraction).ceil() as usize).clamp(1, sent) - 1;
        sorted.get(index).copied().map(|v| (v * 1000.0).round() / 1000.0)
    };
    let p50 = percentile(0.50);
    let p99 = percentile(0.99);
    let p999 = percentile(0.999);
    let mut infinite_at = Vec::new();
    for (name, value) in [("p50", p50), ("p99", p99), ("p999", p999)] {
        if value.is_none() {
            infinite_at.push(name);
        }
    }
    json!({
        "n": sent,
        "lost": sent.saturating_sub(samples.len()),
        "p50": p50,
        "p99": p99,
        "p999": p999,
        "infinite_at": infinite_at,
    })
}

/// Check percentile ranks when reply loss reaches the requested tail ranks.
#[cfg(test)]
mod tests {
    use super::loss_aware_summary;

    /// Missing replies make high percentile ranks unavailable at three percent loss.
    #[test]
    fn loss_pushes_percentile_ranks_to_unavailable_tail() {
        let samples: Vec<f64> = (1..=97).map(f64::from).collect();
        let value = loss_aware_summary(&samples, 100);
        assert_eq!(value["p50"], 50.0);
        assert_eq!(value["p99"], serde_json::Value::Null);
        assert_eq!(value["p999"], serde_json::Value::Null);
        assert_eq!(value["infinite_at"][0], "p99");
        assert_eq!(value["lost"], 3);
    }

    /// Sub-percent loss preserves p99 while p99.9 can still fall in the missing tail.
    #[test]
    fn sub_percent_loss_keeps_p99_but_not_p999_finite() {
        let samples: Vec<f64> = (1..=995).map(f64::from).collect();
        let value = loss_aware_summary(&samples, 1000);
        assert_eq!(value["p99"], 990.0);
        assert_eq!(value["p999"], serde_json::Value::Null);
        assert_eq!(value["infinite_at"][0], "p999");
    }
}
