use neural_metacognition::SystemAuditor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub struct ClinicalStreamingServer {
    auditor: Arc<SystemAuditor>,
    is_active: Arc<AtomicBool>,
    listen_port: u16,
}

impl ClinicalStreamingServer {
    pub fn new(auditor: Arc<SystemAuditor>, port: u16) -> Self {
        Self {
            auditor,
            is_active: Arc::new(AtomicBool::new(false)),
            listen_port: port,
        }
    }

    pub async fn start_streaming(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.listen_port)).await?;
        self.is_active.store(true, Ordering::SeqCst);
        tracing::info!(port = self.listen_port, "ClinicalStreamingServer en écoute");

        loop {
            if !self.is_active.load(Ordering::SeqCst) {
                break;
            }
            let (mut socket, _addr) = listener.accept().await?;
            let auditor = self.auditor.clone();
            let is_active = self.is_active.clone();

            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                // Lecture de la requete HTTP (GET /health ou GET /metrics)
                let n = match socket.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => return,
                };
                let request = String::from_utf8_lossy(&buf[..n]);

                if request.starts_with("GET /health") {
                    // Endpoint /health : retourne l'etat du systeme en JSON
                    let frame = auditor.get_latest();
                    let status = if is_active.load(Ordering::SeqCst) {
                        "healthy"
                    } else {
                        "shutting_down"
                    };
                    let response = format!(
                        "{{\"status\":\"{}\",\"timestamp_ns\":{},\"memory_throughput\":{},\"active_synapses\":{},\"meta_loss\":{:.4}}}",
                        status,
                        frame.timestamp_ns,
                        frame.memory_throughput_bytes_per_sec,
                        frame.active_synapse_count,
                        frame.current_meta_loss
                    );
                    let http_response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        response.len(),
                        response
                    );
                    let _ = socket.write_all(http_response.as_bytes()).await;
                } else if request.starts_with("GET /metrics") {
                    // Endpoint /metrics : flux JSON des TelemetryFrames
                    loop {
                        let frame = auditor.get_latest();
                        let body = format!(
                            "{{\"timestamp_ns\":{},\"memory_throughput_bytes_per_sec\":{},\"active_synapse_count\":{},\"current_meta_loss\":{}}}",
                            frame.timestamp_ns,
                            frame.memory_throughput_bytes_per_sec,
                            frame.active_synapse_count,
                            frame.current_meta_loss
                        );
                        if socket.write_all(body.as_bytes()).await.is_err() {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(16)).await;
                    }
                } else {
                    let response =
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = socket.write_all(response.as_bytes()).await;
                }
            });
        }
        Ok(())
    }

    pub fn shutdown(&self) {
        self.is_active.store(false, Ordering::SeqCst);
    }
}
