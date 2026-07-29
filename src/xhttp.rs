use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{timeout, Duration};

use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;

/// Tipo de erro unificado para o projeto
type XhttpError = Box<dyn std::error::Error + Send + Sync>;

/// Sessão xHTTP ativa com canais para comunicação GET<->POST<->SSH
#[allow(dead_code)]
struct XhttpSession {
    post_tx: mpsc::Sender<Vec<u8>>,
    get_tx: mpsc::Sender<Vec<u8>>,
    active: Arc<RwLock<bool>>,
}

static SESSIONS: once_cell::sync::Lazy<Arc<Mutex<HashMap<String, XhttpSession>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

#[tokio::main]
async fn main() -> Result<(), XhttpError> {
    let port = get_port();
    let status = get_status();
    let ssh_port = get_ssh_port();

    println!("[Mpro] xHTTP v3.6.0 – Latency Optimized for Low Latency Networks");
    println!("[xHTTP] Porta: {} | SSH Backend: 127.0.0.1:{}", port, ssh_port);
    println!("[xHTTP] Keep-Alive: timeout=30 max=100 | Canal GET/POST: 16384");
    println!("[xHTTP] TCP_QUICKACK | Peek=200ms | TLS read=1.5s | SSH connect=3s");

    let listener = TcpListener::bind(format!("[::]:{}", port)).await.map_err(|e| Box::new(e) as XhttpError)?;
    let status_arc = Arc::new(status);

    loop {
        match listener.accept().await {
            Ok((client_stream, _addr)) => {
                let _ = client_stream.set_nodelay(true);
                // Fator 2: TCP_QUICKACK – ACK imediato, elimina delay do Nagle
                #[cfg(target_os = "linux")]
                {
                    use std::os::fd::AsFd;
                    use std::os::fd::AsRawFd;
                    let fd = client_stream.as_fd().as_raw_fd();
                    unsafe { libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_QUICKACK, &(1i32) as *const i32 as *const libc::c_void, std::mem::size_of::<i32>() as libc::socklen_t); }
                }
                let status = status_arc.clone();
                tokio::spawn(async move {
                    let _ = handle_xhttp_client(client_stream, &status, ssh_port).await;
                });
            }
            Err(e) => {
                println!("[xHTTP] Erro aceitar conexao: {}", e);
            }
        }
    }
}

async fn handle_xhttp_client(
    stream: TcpStream,
    status: &str,
    ssh_port: u16,
) -> Result<(), XhttpError> {
    let mut peek_buf = [0u8; 32];
    // Fator 3: Peek timeout reduzido para 200ms (detecção ultra rápida)
    let peek_result = timeout(Duration::from_millis(200), stream.peek(&mut peek_buf)).await;
    let bytes_peeked = match peek_result {
        Ok(Ok(n)) => n,
        _ => 0,
    };

    if bytes_peeked == 0 {
        return handle_ssh_direct(stream, ssh_port).await;
    }
    
    let first_byte = peek_buf[0];

    // Detecta TLS (0x16 = TLS ClientHello)
    if first_byte == 0x16 {
        return handle_tls_dual(stream, status, ssh_port).await;
    }

    // Detecta se parece ser HTTP (GET, POST, etc)
    if first_byte >= 0x41 && first_byte <= 0x5A {
        return handle_http_dual_raw(stream, status, ssh_port).await;
    }

    // Fallback para SSH direto
    handle_ssh_direct(stream, ssh_port).await
}

async fn handle_tls_dual(
    stream: TcpStream,
    status: &str,
    ssh_port: u16,
) -> Result<(), XhttpError> {
    let cert_path = "/opt/mpro/cert.pem";
    let key_path = "/opt/mpro/key.pem";

    let mut config = build_tls_config(cert_path, key_path)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let mut tls_stream = acceptor.accept(stream).await.map_err(|e| Box::new(e) as XhttpError)?;

    let mut buf = vec![0u8; 4096];
    // Fator 3: TLS read timeout reduzido para 1.5s
    let n = match timeout(Duration::from_millis(1500), tls_stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => {
            return handle_ssh_direct_tls(tls_stream, ssh_port, None).await;
        }
    };

    let data = &buf[..n];
    let http_str = String::from_utf8_lossy(data);
    
    if http_str.contains("x-session-id") || http_str.contains("/ssh/") || http_str.contains("/xhttp/") || http_str.contains("/split/") {
        if let Some((method, path)) = parse_http_request(&http_str) {
            match method.as_str() {
                "GET" => return handle_xhttp_get_tls(&mut tls_stream, &path, status, ssh_port).await,
                "POST" => return handle_xhttp_post_tls(&mut tls_stream, data, &path, status).await,
                _ => {}
            }
        }
    }

    if http_str.contains("HTTP/1.") {
        // Fator 1: Keep-Alive nos headers (timeout=30, max=100)
        let resp = format!("HTTP/1.1 101 ({})\r\nConnection: keep-alive\r\nKeep-Alive: timeout=30, max=100\r\n\r\nHTTP/1.1 200 ({})\r\nConnection: keep-alive\r\nKeep-Alive: timeout=30, max=100\r\n\r\n", status, status);
        tls_stream.write_all(resp.as_bytes()).await.map_err(|e| Box::new(e) as XhttpError)?;
        return handle_ssh_direct_tls(tls_stream, ssh_port, None).await;
    }

    handle_ssh_direct_tls(tls_stream, ssh_port, Some(data.to_vec())).await
}

async fn handle_http_dual_raw(mut stream: TcpStream, status: &str, ssh_port: u16) -> Result<(), XhttpError> {
    // Fator 1: Canal GET/POST ampliado para 16384
    let mut buf = vec![0u8; 16384];
    let n = stream.read(&mut buf).await.map_err(|e| Box::new(e) as XhttpError)?;
    let http_str = String::from_utf8_lossy(&buf[..n]);
    
    if http_str.contains("x-session-id") || http_str.contains("/ssh/") || http_str.contains("/xhttp/") || http_str.contains("/split/") {
        if let Some((method, path)) = parse_http_request(&http_str) {
            match method.as_str() {
                "GET" => return handle_xhttp_get_raw(&mut stream, &path, status, ssh_port).await,
                "POST" => return handle_xhttp_post_raw(&mut stream, &buf[..n], &path, status).await,
                _ => {}
            }
        }
    }

    if http_str.contains("HTTP/1.") {
        // Fator 1: Keep-Alive nos headers (timeout=30, max=100)
        let resp = format!("HTTP/1.1 101 ({})\r\nConnection: keep-alive\r\nKeep-Alive: timeout=30, max=100\r\n\r\nHTTP/1.1 200 ({})\r\nConnection: keep-alive\r\nKeep-Alive: timeout=30, max=100\r\n\r\n", status, status);
        stream.write_all(resp.as_bytes()).await.map_err(|e| Box::new(e) as XhttpError)?;
    }
    
    // Fator 3: SSH connect timeout reduzido para 3s
    let ssh = timeout(Duration::from_secs(3), TcpStream::connect(format!("127.0.0.1:{}", ssh_port))).await.map_err(|_| Box::new(std::io::Error::new(std::io::ErrorKind::TimedOut, "SSH Connect Timeout")) as XhttpError)?.map_err(|e| Box::new(e) as XhttpError)?;
    let (mut r, mut w) = stream.into_split();
    let (mut sr, mut sw) = ssh.into_split();
    let _ = tokio::join!(tokio::io::copy(&mut r, &mut sw), tokio::io::copy(&mut sr, &mut w));
    Ok(())
}

async fn handle_ssh_direct(stream: TcpStream, ssh_port: u16) -> Result<(), XhttpError> {
    // Fator 3: SSH connect timeout reduzido para 3s
    let ssh = timeout(Duration::from_secs(3), TcpStream::connect(format!("127.0.0.1:{}", ssh_port))).await.map_err(|_| Box::new(std::io::Error::new(std::io::ErrorKind::TimedOut, "SSH Connect Timeout")) as XhttpError)?.map_err(|e| Box::new(e) as XhttpError)?;
    let (mut r, mut w) = stream.into_split();
    let (mut sr, mut sw) = ssh.into_split();
    let _ = tokio::join!(tokio::io::copy(&mut r, &mut sw), tokio::io::copy(&mut sr, &mut w));
    Ok(())
}

async fn handle_ssh_direct_tls(tls_stream: tokio_rustls::server::TlsStream<TcpStream>, ssh_port: u16, initial_data: Option<Vec<u8>>) -> Result<(), XhttpError> {
    // Fator 3: SSH connect timeout reduzido para 3s
    let mut ssh = timeout(Duration::from_secs(3), TcpStream::connect(format!("127.0.0.1:{}", ssh_port))).await.map_err(|_| Box::new(std::io::Error::new(std::io::ErrorKind::TimedOut, "SSH Connect Timeout")) as XhttpError)?.map_err(|e| Box::new(e) as XhttpError)?;
    if let Some(data) = initial_data {
        ssh.write_all(&data).await.map_err(|e| Box::new(e) as XhttpError)?;
    }
    let (mut r, mut w) = tokio::io::split(tls_stream);
    let (mut sr, mut sw) = ssh.into_split();
    let _ = tokio::join!(tokio::io::copy(&mut r, &mut sw), tokio::io::copy(&mut sr, &mut w));
    Ok(())
}

// --- XHTTP Acceleration Logic ---

async fn handle_xhttp_get_tls(tls: &mut tokio_rustls::server::TlsStream<TcpStream>, path: &str, status: &str, ssh_port: u16) -> Result<(), XhttpError> {
    let (sid, _) = extract_path_info(path);
    
    {
        let mut sessions = SESSIONS.lock().await;
        if let Some(old) = sessions.get(&sid) {
            let _ = old.active.write().await;
        }
        sessions.remove(&sid);
    }

    // Fator 1: RESPOSTA IMEDIATA com Keep-Alive (timeout=30, max=100)
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
        Content-Type: application/octet-stream\r\n\
        Transfer-Encoding: chunked\r\n\
        Connection: keep-alive\r\n\
        Keep-Alive: timeout=30, max=100\r\n\
        Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n\
        Pragma: no-cache\r\n\
        Expires: 0\r\n\
        X-Session-ID: {}\r\n\
        X-Status: {}\r\n\r\n", 
        sid, status
    );
    tls.write_all(resp.as_bytes()).await.map_err(|e| Box::new(e) as XhttpError)?;
    tls.flush().await.map_err(|e| Box::new(e) as XhttpError)?;

    // Fator 3: SSH connect timeout reduzido para 3s
    let ssh = timeout(Duration::from_secs(3), TcpStream::connect(format!("127.0.0.1:{}", ssh_port))).await.map_err(|_| Box::new(std::io::Error::new(std::io::ErrorKind::TimedOut, "SSH Connect Timeout")) as XhttpError)?.map_err(|e| Box::new(e) as XhttpError)?;
    let (mut sr, mut sw) = ssh.into_split();
    // Fator 1: Canal GET/POST ampliado para 16384
    let (ptx, mut prx) = mpsc::channel::<Vec<u8>>(16384); 
    let (gtx, mut grx) = mpsc::channel::<Vec<u8>>(16384); 
    let act = Arc::new(RwLock::new(true));
    
    SESSIONS.lock().await.insert(sid.clone(), XhttpSession { post_tx: ptx, get_tx: gtx.clone(), active: act.clone() });
    
    let act_c = act.clone();
    tokio::spawn(async move { 
        while let Some(d) = prx.recv().await { 
            if !*act_c.read().await { break; } 
            if sw.write_all(&d).await.is_err() { break; }
        }
        let mut a = act_c.write().await;
        *a = false;
    });

    let gtx_c = gtx.clone();
    let act_c2 = act.clone();
    tokio::spawn(async move { 
        let mut b = vec![0u8; 32768]; 
        while let Ok(Ok(n)) = timeout(Duration::from_secs(600), sr.read(&mut b)).await { 
            if n == 0 || gtx_c.send(b[..n].to_vec()).await.is_err() { break; } 
            if !*act_c2.read().await { break; }
        }
        let mut a = act_c2.write().await;
        *a = false;
    });

    while let Some(d) = grx.recv().await {
        if !*act.read().await { break; }
        if tls.write_all(format!("{:x}\r\n", d.len()).as_bytes()).await.is_err() { break; }
        if tls.write_all(&d).await.is_err() { break; }
        if tls.write_all(b"\r\n").await.is_err() { break; }
        let _ = tls.flush().await;
    }
    
    let mut a = act.write().await;
    *a = false;
    SESSIONS.lock().await.remove(&sid);
    Ok(())
}

async fn handle_xhttp_get_raw(stream: &mut TcpStream, path: &str, status: &str, ssh_port: u16) -> Result<(), XhttpError> {
    let (sid, _) = extract_path_info(path);
    
    {
        let mut sessions = SESSIONS.lock().await;
        if let Some(old) = sessions.get(&sid) {
            let _ = old.active.write().await;
        }
        sessions.remove(&sid);
    }

    // Fator 1: RESPOSTA IMEDIATA com Keep-Alive (timeout=30, max=100)
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
        Content-Type: application/octet-stream\r\n\
        Transfer-Encoding: chunked\r\n\
        Connection: keep-alive\r\n\
        Keep-Alive: timeout=30, max=100\r\n\
        Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n\
        Pragma: no-cache\r\n\
        Expires: 0\r\n\
        X-Session-ID: {}\r\n\
        X-Status: {}\r\n\r\n", 
        sid, status
    );
    stream.write_all(resp.as_bytes()).await.map_err(|e| Box::new(e) as XhttpError)?;
    stream.flush().await.map_err(|e| Box::new(e) as XhttpError)?;

    // Fator 3: SSH connect timeout reduzido para 3s
    let ssh = timeout(Duration::from_secs(3), TcpStream::connect(format!("127.0.0.1:{}", ssh_port))).await.map_err(|_| Box::new(std::io::Error::new(std::io::ErrorKind::TimedOut, "SSH Connect Timeout")) as XhttpError)?.map_err(|e| Box::new(e) as XhttpError)?;
    let (mut sr, mut sw) = ssh.into_split();
    // Fator 1: Canal GET/POST ampliado para 16384
    let (ptx, mut prx) = mpsc::channel::<Vec<u8>>(16384);
    let (gtx, mut grx) = mpsc::channel::<Vec<u8>>(16384);
    let act = Arc::new(RwLock::new(true));

    SESSIONS.lock().await.insert(sid.clone(), XhttpSession { post_tx: ptx, get_tx: gtx.clone(), active: act.clone() });
    
    let act_c = act.clone();
    tokio::spawn(async move { 
        while let Some(d) = prx.recv().await { 
            if !*act_c.read().await { break; }
            if sw.write_all(&d).await.is_err() { break; }
        } 
        let mut a = act_c.write().await;
        *a = false;
    });

    let gtx_c = gtx.clone();
    let act_c2 = act.clone();
    tokio::spawn(async move { 
        let mut b = vec![0u8; 32768]; 
        while let Ok(Ok(n)) = timeout(Duration::from_secs(600), sr.read(&mut b)).await { 
            if n == 0 || gtx_c.send(b[..n].to_vec()).await.is_err() { break; } 
            if !*act_c2.read().await { break; }
        }
        let mut a = act_c2.write().await;
        *a = false;
    });

    while let Some(d) = grx.recv().await {
        if !*act.read().await { break; }
        if stream.write_all(format!("{:x}\r\n", d.len()).as_bytes()).await.is_err() { break; }
        if stream.write_all(&d).await.is_err() { break; }
        if stream.write_all(b"\r\n").await.is_err() { break; }
        let _ = stream.flush().await;
    }
    
    let mut a = act.write().await;
    *a = false;
    SESSIONS.lock().await.remove(&sid);
    Ok(())
}

async fn handle_xhttp_post_tls(tls: &mut tokio_rustls::server::TlsStream<TcpStream>, req: &[u8], path: &str, _: &str) -> Result<(), XhttpError> {
    let (sid, _) = extract_path_info(path);
    let cl = extract_content_length_from_bytes(req).unwrap_or(0);
    let h_end = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
    let mut body = req[h_end..].to_vec();
    
    // Fator 2: POST read_exact sem timeout – lê o corpo completo sem esperar, mais rápido em redes lentas
    if body.len() < cl {
        let mut b = vec![0u8; cl - body.len()];
        tls.read_exact(&mut b).await.map_err(|e| Box::new(e) as XhttpError)?;
        body.extend_from_slice(&b);
    }
    
    if let Some(s) = SESSIONS.lock().await.get(&sid) { 
        let _ = s.post_tx.send(body).await; 
    }
    
    // Fator 1: Keep-Alive na resposta POST
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\nKeep-Alive: timeout=30, max=100\r\n\r\n").await.map_err(|e| Box::new(e) as XhttpError)?;
    Ok(())
}

async fn handle_xhttp_post_raw(stream: &mut TcpStream, req: &[u8], path: &str, _: &str) -> Result<(), XhttpError> {
    let (sid, _) = extract_path_info(path);
    let cl = extract_content_length_from_bytes(req).unwrap_or(0);
    let h_end = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
    let mut body = req[h_end..].to_vec();
    
    // Fator 2: POST read_exact sem timeout – lê o corpo completo sem esperar
    if body.len() < cl {
        let mut b = vec![0u8; cl - body.len()];
        stream.read_exact(&mut b).await.map_err(|e| Box::new(e) as XhttpError)?;
        body.extend_from_slice(&b);
    }
    
    if let Some(s) = SESSIONS.lock().await.get(&sid) { 
        let _ = s.post_tx.send(body).await; 
    }
    
    // Fator 1: Keep-Alive na resposta POST
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\nKeep-Alive: timeout=30, max=100\r\n\r\n").await.map_err(|e| Box::new(e) as XhttpError)?;
    Ok(())
}

fn parse_http_request(data: &str) -> Option<(String, String)> {
    let line = data.lines().next()?;
    let p: Vec<&str> = line.split_whitespace().collect();
    if p.len() >= 2 { Some((p[0].to_string(), p[1].to_string())) } else { None }
}

fn extract_path_info(path: &str) -> (String, Option<u64>) {
    let p = path.split('?').next().unwrap_or(path).trim_start_matches('/').split('/').collect::<Vec<&str>>();
    if p.is_empty() || p[0].is_empty() { return (String::new(), None); }
    if p.len() >= 2 {
        if ["ssh", "xhttp", "split"].contains(&p[0]) {
            return (p[1].to_string(), if p.len() >= 3 { p[2].parse().ok() } else { None });
        }
        return (p[0].to_string(), p[1].parse().ok());
    }
    (p[0].to_string(), None)
}

fn extract_content_length_from_bytes(data: &[u8]) -> Option<usize> {
    let s = String::from_utf8_lossy(data);
    for l in s.lines() { 
        if l.to_lowercase().starts_with("content-length:") { 
            return l.split(':').nth(1)?.trim().parse().ok(); 
        } 
    }
    None
}

fn build_tls_config(cp: &str, kp: &str) -> Result<rustls::ServerConfig, XhttpError> {
    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cp).map_err(|e| Box::new(e) as XhttpError)?)).map_err(|e| Box::new(e) as XhttpError)?.into_iter().map(Certificate).collect();
    let keys: Vec<PrivateKey> = rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(std::fs::File::open(kp).map_err(|e| Box::new(e) as XhttpError)?)).map_err(|e| Box::new(e) as XhttpError)?.into_iter().map(PrivateKey).collect();
    if certs.is_empty() || keys.is_empty() { return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Certs empty")) as XhttpError); }
    
    let mut c = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.into_iter().next().unwrap())
        .map_err(|e| Box::new(e) as XhttpError)?;
    
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(c)
}

fn get_port() -> u16 { std::env::args().enumerate().find(|(_, a)| a == "--port" || a == "-p").and_then(|(i, _)| std::env::args().nth(i+1)).and_then(|a| a.parse().ok()).unwrap_or(443) }
fn get_ssh_port() -> u16 { std::env::args().enumerate().find(|(_, a)| a == "--ssh-port").and_then(|(i, _)| std::env::args().nth(i+1)).and_then(|a| a.parse().ok()).unwrap_or(22) }
fn get_status() -> String { std::env::args().enumerate().find(|(_, a)| a == "--status" || a == "-s").and_then(|(i, _)| std::env::args().nth(i+1)).unwrap_or("@Mpro".to_string()) }
