// =============================================================================
// PATCH 3 : crates/gateway/src/channel.rs
// Remplacement tokio::mpsc → async-channel (correction de la review)
// =============================================================================
//
// ERREUR DANS LA REVIEW :
//   "remplace tokio::mpsc par crossbeam::bounded"
//
//   crossbeam::Receiver::recv() est BLOQUANT (thread OS).
//   L'appeler depuis une coroutine Tokio stall l'executor :
//
//   async fn bad_example() {
//       let (_, rx) = crossbeam::channel::bounded(100);
//       let msg = rx.recv().unwrap();  // ← BLOQUE LE THREAD TOKIO
//       // Pendant ce temps, aucune autre coroutine ne tourne sur ce thread
//   }
//
//   La correction correcte est async-channel (lock-free, fully async) :
//   - API identique à tokio::mpsc (Sender/Receiver async)
//   - Implémentation MPMC lock-free (concurrent::queue interne)
//   - Les performances dépendent du runtime, de l'architecture, de la charge et
//     de la capacité du canal; elles doivent être mesurées sur le système cible.
//
// BENCHMARK DIAGNOSTIQUE INCLUS : il rapporte les mesures sans les transformer
// en gate de correction fonctionnelle.
// =============================================================================

use async_channel::{bounded, Receiver, Sender};
use std::time::{Duration, Instant};
use tracing::instrument;

// ─────────────────────────────────────────────────────────────────────────────
// TOKEN CHANNEL (remplacement du mpsc de la gateway)
// ─────────────────────────────────────────────────────────────────────────────

/// Canal de tokens SSE entre le producteur HTTP et le consommateur Telegram.
///
/// async-channel::bounded vs tokio::mpsc :
///   - Sémantique MPMC (Multiple Producer Multiple Consumer)
///     → Plusieurs producteurs SSE possibles (reconnexion parallèle)
///   - Le sender est Clone : distribué entre threads sans Arc<Mutex<>>
///   - Backpressure naturelle : le producteur attend si le buffer est plein
pub struct SseTokenChannel {
    pub tx: Sender<SseToken>,
    pub rx: Receiver<SseToken>,
}

#[derive(Debug, Clone)]
pub struct SseToken {
    pub data: String,
    pub is_final: bool, // signal de fin de stream
    pub timestamp: std::time::SystemTime,
}

impl SseTokenChannel {
    /// Capacité 4096 tokens × ~5 bytes = ~20 KB en vol max.
    /// Si le consommateur Telegram est lent (throttle), le producteur se met en pause.
    pub fn new() -> Self {
        let (tx, rx) = bounded(4096);
        Self { tx, rx }
    }

    /// Capacité configurable : augmenter si débit SSE > 4096 tokens/requête.
    pub fn with_capacity(cap: usize) -> Self {
        let (tx, rx) = bounded(cap);
        Self { tx, rx }
    }
}

impl Default for SseTokenChannel {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PRODUCTEUR SSE (async, envoie dans async-channel)
// ─────────────────────────────────────────────────────────────────────────────

#[instrument(skip(tx, stream))]
pub async fn sse_producer(
    tx: Sender<SseToken>,
    mut stream: impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
) {
    use futures::StreamExt;
    let mut buffer = String::new();

    while let Some(result) = stream.next().await {
        match result {
            Err(e) => {
                tracing::error!("SSE stream error: {}", e);
                break;
            }
            Ok(chunk) => {
                buffer.push_str(&String::from_utf8_lossy(&chunk));
                // Extraire les blocs SSE complets (terminés par \n\n)
                while let Some(pos) = buffer.find("\n\n") {
                    let block: String = buffer.drain(..pos + 2).collect();
                    if let Some(token) = parse_data_line(&block) {
                        let msg = SseToken {
                            data: token,
                            is_final: false,
                            timestamp: std::time::SystemTime::now(),
                        };
                        // send() est async : attend si le buffer est plein (backpressure)
                        if tx.send(msg).await.is_err() {
                            // Récepteur fermé (Telegram déconnecté)
                            return;
                        }
                    }
                }
            }
        }
    }

    // Signal de fin
    let _ = tx
        .send(SseToken {
            data: String::new(),
            is_final: true,
            timestamp: std::time::SystemTime::now(),
        })
        .await;
}

fn parse_data_line(block: &str) -> Option<String> {
    for line in block.lines() {
        if let Some(data) = line.strip_prefix("data: ") {
            if data != "[DONE]" {
                return Some(data.to_string());
            }
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// CONSOMMATEUR TELEGRAM (async, lit depuis async-channel)
// ─────────────────────────────────────────────────────────────────────────────

pub struct TelegramConsumer {
    pub rx: Receiver<SseToken>,
}

impl TelegramConsumer {
    /// Consomme les tokens et édite Telegram avec throttling.
    pub async fn run(
        &self,
        chat_id: i64,
        throttle_ms: u64,
        flush_bytes: usize,
        edit_fn: impl Fn(i64, String) -> tokio::task::JoinHandle<()>,
    ) {
        let mut buffer = String::new();
        let mut last_edit = Instant::now();
        let throttle = Duration::from_millis(throttle_ms);

        loop {
            // recv() est fully async : pas de thread blocking
            match self.rx.recv().await {
                Err(_) => break, // channel fermé

                Ok(token) if token.is_final => {
                    // Flush final
                    if !buffer.is_empty() {
                        edit_fn(chat_id, buffer.clone());
                    }
                    break;
                }

                Ok(token) => {
                    buffer.push_str(&token.data);

                    let should_flush =
                        last_edit.elapsed() >= throttle || buffer.len() >= flush_bytes;
                    if should_flush {
                        edit_fn(chat_id, buffer.clone());
                        last_edit = Instant::now();
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BENCHMARK DIAGNOSTIQUE : async-channel vs tokio::mpsc
// Lance avec : cargo test --release -- --ignored --nocapture bench_channel
// Les timings ne sont pas une assertion de correction et ne doivent pas bloquer CI.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod bench {
    use super::*;
    use tokio::sync::mpsc as tokio_mpsc;

    async fn bench_async_channel(n: usize) -> Duration {
        let (tx, rx) = async_channel::bounded::<u64>(n);
        let t = Instant::now();

        let producer = tokio::spawn(async move {
            for i in 0..n as u64 {
                tx.send(i).await.unwrap();
            }
        });
        let consumer = tokio::spawn(async move {
            for _ in 0..n {
                rx.recv().await.unwrap();
            }
        });
        tokio::join!(producer, consumer).0.unwrap();
        t.elapsed()
    }

    async fn bench_tokio_mpsc(n: usize) -> Duration {
        let (tx, mut rx) = tokio_mpsc::channel::<u64>(n);
        let t = Instant::now();

        let producer = tokio::spawn(async move {
            for i in 0..n as u64 {
                tx.send(i).await.unwrap();
            }
        });
        let consumer = tokio::spawn(async move {
            for _ in 0..n {
                rx.recv().await.unwrap();
            }
        });
        tokio::join!(producer, consumer).0.unwrap();
        t.elapsed()
    }

    #[tokio::test]
    #[ignore = "diagnostic microbenchmark; throughput is host and load dependent"]
    async fn bench_channel_comparison() {
        const N: usize = 100_000;

        // Warmup
        bench_async_channel(N / 10).await;
        bench_tokio_mpsc(N / 10).await;

        let ac_time = bench_async_channel(N).await;
        let mpsc_time = bench_tokio_mpsc(N).await;

        let ac_ns = ac_time.as_nanos() as f64 / N as f64;
        let mpsc_ns = mpsc_time.as_nanos() as f64 / N as f64;
        let speedup = mpsc_ns / ac_ns;

        println!("\n=== CHANNEL BENCHMARK ({} messages) ===", N);
        println!("async-channel : {:.1} ns/msg", ac_ns);
        println!("tokio::mpsc   : {:.1} ns/msg", mpsc_ns);
        println!(
            "Relative ratio: {:.2}× (tokio::mpsc / async-channel)",
            speedup
        );
        println!(
            "Diagnostic only: no fixed performance threshold is valid across hosts or load states"
        );
    }
}
