use hdrhistogram::Histogram;
use parking_lot::Mutex;
use std::time::Duration;

pub struct Metrics {
    latency: Mutex<Histogram<u64>>, // micros
    qps_counter: parking_lot::Mutex<(std::time::Instant, u64)>,
    cache_hits: parking_lot::Mutex<u64>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            latency: Mutex::new(Histogram::new(3).expect("hist")),
            qps_counter: parking_lot::Mutex::new((std::time::Instant::now(), 0)),
            cache_hits: parking_lot::Mutex::new(0),
        }
    }

    pub fn observe_request(&self, dur: Duration) {
        if let Ok(mut h) = self.latency.lock() {
            let micros = dur.as_micros() as u64;
            let _ = h.record(micros);
        }
        let mut q = self.qps_counter.lock();
        q.1 += 1;
    }

    pub fn inc_cache_hit(&self) { *self.cache_hits.lock() += 1; }

    pub fn format(&self) -> String {
        let h = self.latency.lock();
        let p95 = h.value_at_quantile(0.95) as f64 / 1000.0;
        let p50 = h.value_at_quantile(0.50) as f64 / 1000.0;
        let p99 = h.value_at_quantile(0.99) as f64 / 1000.0;

        // QPS since start
        let q = self.qps_counter.lock();
        let elapsed = q.0.elapsed().as_secs_f64().max(1.0);
        let qps = q.1 as f64 / elapsed;
        let cache_hits = *self.cache_hits.lock();

        format!("qps {:.2}\np50_ms {:.3}\np95_ms {:.3}\np99_ms {:.3}\ncache_hits {}\n", qps, p50, p95, p99, cache_hits)
    }
}