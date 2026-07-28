use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{timeout, Duration};
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;

type Error = Box<dyn std::error::Error + Send + Sync>;
type SessionMap = Arc<Mutex<HashMap<String, Session>>>;

const C: usize = 16384;          // Channel size
const T_PEEK: u64 = 200;         // Peek timeout (ms)
const T_TLS: u64 = 1500;         // TLS read timeout (ms)
const T_SSH: u64 = 3;            // SSH connect timeout (s)
const T_IDLE: u64 = 600;         // Idle timeout (s)
const BUF: usize = 32768;        // Buffer size

struct Session {
    post: mpsc::Sender<Vec<u8>>,
    get: mpsc::Sender<Vec<u8>>,
    active: Arc<AtomicBool>,
}

impl Session {
    fn new() -> (Self, mpsc::Receiver<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        let (pt, pr) = mpsc::channel(C);
        let (gt, gr) = mpsc::channel(C);
        (Self { post: pt, get: gt, active: Arc::new(AtomicBool::new(true)) }, pr, gr)
    }
}

static SESSIONS: once_cell::sync::Lazy<SessionMap> = 
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

#[tokio::main]
async fn main() -> Result<(), Error> {
    let (port, ssh, status) = (get_port(), get_ssh_port(), get_status());
    println!("[Mpro] xHTTP v3.6.1 – Fixed Connection Lag");
    println!("[xHTTP] Port: {} | SSH: 127.0.0.1:{} | KA: 30/100 | Chan: {}", port, ssh, C);
    
    let listener = TcpListener::bind(format!("[::]:{}", port)).await?;
    let status = Arc::new(status);
    
    while let Ok((mut stream, _)) = listener.accept().await {
        let _ = stream.set_nodelay(true);
        #[cfg(target_os = "linux")] 
        { use std::os::fd::AsFd; let fd = stream.as_fd().as_raw_fd(); 
          unsafe { libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_QUICKACK, &1i32 as *const _ as *const _, std::mem::size_of::<i32>() as _); } }
        
        let status = status.clone();
        tokio::spawn(async move { 
            let _ = handle(stream, &status, ssh).await; 
        });
    }
    Ok(())
}

async fn handle(mut stream: TcpStream, status: &str, ssh: u16) -> Result<(), Error> {
    let mut buf = [0u8; 32];
    let n = timeout(Duration::from_millis(T_PEEK), stream.peek(&mut buf)).await
        .map_err(|_| "peek timeout")?.map_err(|_| "peek failed")?;
    
    if n == 0 { return bridge(stream, connect_ssh(ssh).await?).await; }
    
    match buf[0] {
        0x16 => handle_tls(stream, status, ssh).await,
        0x41..=0x5A => handle_http(stream, status, ssh).await,
        _ => bridge(stream, connect_ssh(ssh).await?).await,
    }
}

async fn handle_tls(stream: TcpStream, status: &str, ssh: u16) -> Result<(), Error> {
    let mut tls = TlsAcceptor::from(Arc::new(build_tls_config()?)).accept(stream).await?;
    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_millis(T_TLS), tls.read(&mut buf)).await
        .map_err(|_| "tls timeout")?.map_err(|_| "tls read")?;
    
    if n == 0 { return bridge_tls(tls, connect_ssh(ssh).await?, None).await; }
    
    let data = &buf[..n];
    if let Some((method, path)) = parse(data) {
        return match method {
            "GET" => xhttp_get_tls(tls, &path, status, ssh).await,
            "POST" => xhttp_post_tls(tls, data, &path).await,
            _ => bridge_tls(tls, connect_ssh(ssh).await?, Some(data.to_vec())).await,
        };
    }
    
    if String::from_utf8_lossy(data).contains("HTTP/1.") {
        let resp = format!("HTTP/1.1 101 ({})\r\nConnection: keep-alive\r\nKeep-Alive: timeout=30, max=100\r\n\r\n", status);
        tls.write_all(resp.as_bytes()).await?;
        return bridge_tls(tls, connect_ssh(ssh).await?, None).await;
    }
    
    bridge_tls(tls, connect_ssh(ssh).await?, Some(data.to_vec())).await
}

async fn handle_http(mut stream: TcpStream, status: &str, ssh: u16) -> Result<(), Error> {
    let mut buf = vec![0u8; C];
    let n = stream.read(&mut buf).await?;
    let data = &buf[..n];
    
    if let Some((method, path)) = parse(data) {
        return match method {
            "GET" => xhttp_get_raw(stream, &path, status, ssh).await,
            "POST" => xhttp_post_raw(stream, data, &path).await,
            _ => bridge(stream, connect_ssh(ssh).await?).await,
        };
    }
    
    if String::from_utf8_lossy(data).contains("HTTP/1.") {
        let resp = format!("HTTP/1.1 101 ({})\r\nConnection: keep-alive\r\nKeep-Alive: timeout=30, max=100\r\n\r\n", status);
        stream.write_all(resp.as_bytes()).await?;
    }
    
    bridge(stream, connect_ssh(ssh).await?).await
}

// ===== XHTTP Handlers =====
async fn xhttp_get_tls(mut tls: tokio_rustls::server::TlsStream<TcpStream>, path: &str, status: &str, ssh: u16) -> Result<(), Error> {
    let sid = extract(path);
    cleanup(&sid).await;
    
    // Immediate response (critical for "Connecting..." fix)
    tls.write_all(format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nKeep-Alive: timeout=30, max=100\r\nX-Session-ID: {}\r\nX-Status: {}\r\n\r\n", sid, status).as_bytes()).await?;
    tls.flush().await?;
    
    let ssh_stream = connect_ssh(ssh).await?;
    let (mut sr, mut sw) = ssh_stream.into_split();
    let (session, mut post_rx, mut get_rx) = Session::new();
    
    SESSIONS.lock().await.insert(sid.clone(), session);
    
    // POST -> SSH
    let active = session.active.clone();
    tokio::spawn(async move {
        while let Some(d) = post_rx.recv().await {
            if !active.load(Ordering::Relaxed) || sw.write_all(&d).await.is_err() { break; }
        }
        active.store(false, Ordering::Relaxed);
    });
    
    // SSH -> GET
    let active2 = session.active.clone();
    let get_tx = session.get.clone();
    tokio::spawn(async move {
        let mut b = vec![0u8; BUF];
        while let Ok(Ok(n)) = timeout(Duration::from_secs(T_IDLE), sr.read(&mut b)).await {
            if n == 0 || get_tx.send(b[..n].to_vec()).await.is_err() { break; }
            if !active2.load(Ordering::Relaxed) { break; }
        }
        active2.store(false, Ordering::Relaxed);
    });
    
    // GET -> Client (chunked)
    while let Some(d) = get_rx.recv().await {
        if !session.active.load(Ordering::Relaxed) { break; }
        if tls.write_all(format!("{:x}\r\n", d.len()).as_bytes()).await.is_err() { break; }
        if tls.write_all(&d).await.is_err() { break; }
        if tls.write_all(b"\r\n").await.is_err() { break; }
        let _ = tls.flush().await;
    }
    
    session.active.store(false, Ordering::Relaxed);
    SESSIONS.lock().await.remove(&sid);
    Ok(())
}

async fn xhttp_get_raw(mut stream: TcpStream, path: &str, status: &str, ssh: u16) -> Result<(), Error> {
    let sid = extract(path);
    cleanup(&sid).await;
    
    stream.write_all(format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nKeep-Alive: timeout=30, max=100\r\nX-Session-ID: {}\r\nX-Status: {}\r\n\r\n", sid, status).as_bytes()).await?;
    stream.flush().await?;
    
    let ssh_stream = connect_ssh(ssh).await?;
    let (mut sr, mut sw) = ssh_stream.into_split();
    let (session, mut post_rx, mut get_rx) = Session::new();
    
    SESSIONS.lock().await.insert(sid.clone(), session);
    
    let active = session.active.clone();
    tokio::spawn(async move {
        while let Some(d) = post_rx.recv().await {
            if !active.load(Ordering::Relaxed) || sw.write_all(&d).await.is_err() { break; }
        }
        active.store(false, Ordering::Relaxed);
    });
    
    let active2 = session.active.clone();
    let get_tx = session.get.clone();
    tokio::spawn(async move {
        let mut b = vec![0u8; BUF];
        while let Ok(Ok(n)) = timeout(Duration::from_secs(T_IDLE), sr.read(&mut b)).await {
            if n == 0 || get_tx.send(b[..n].to_vec()).await.is_err() { break; }
            if !active2.load(Ordering::Relaxed) { break; }
        }
        active2.store(false, Ordering::Relaxed);
    });
    
    while let Some(d) = get_rx.recv().await {
        if !session.active.load(Ordering::Relaxed) { break; }
        if stream.write_all(format!("{:x}\r\n", d.len()).as_bytes()).await.is_err() { break; }
        if stream.write_all(&d).await.is_err() { break; }
        if stream.write_all(b"\r\n").await.is_err() { break; }
        let _ = stream.flush().await;
    }
    
    session.active.store(false, Ordering::Relaxed);
    SESSIONS.lock().await.remove(&sid);
    Ok(())
}

async fn xhttp_post_tls(mut tls: tokio_rustls::server::TlsStream<TcpStream>, req: &[u8], path: &str) -> Result<(), Error> {
    let sid = extract(path);
    let body = read_body(&mut tls, req).await?;
    
    if let Some(s) = SESSIONS.lock().await.get(&sid) {
        let _ = s.post.send(body).await;
    }
    
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\nKeep-Alive: timeout=30, max=100\r\n\r\n").await?;
    Ok(())
}

async fn xhttp_post_raw(mut stream: TcpStream, req: &[u8], path: &str) -> Result<(), Error> {
    let sid = extract(path);
    let body = read_body(&mut stream, req).await?;
    
    if let Some(s) = SESSIONS.lock().await.get(&sid) {
        let _ = s.post.send(body).await;
    }
    
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\nKeep-Alive: timeout=30, max=100\r\n\r\n").await?;
    Ok(())
}

// ===== Utilities =====
async fn connect_ssh(port: u16) -> Result<TcpStream, Error> {
    timeout(Duration::from_secs(T_SSH), TcpStream::connect(format!("127.0.0.1:{}", port)))
        .await.map_err(|_| "ssh timeout")?.map_err(|e| e.into())
}

async fn bridge(mut s1: TcpStream, mut s2: TcpStream) -> Result<(), Error> {
    let (r1, w1) = s1.into_split();
    let (r2, w2) = s2.into_split();
    let _ = tokio::join!(tokio::io::copy(&mut r1, &mut w2), tokio::io::copy(&mut r2, &mut w1));
    Ok(())
}

async fn bridge_tls(tls: tokio_rustls::server::TlsStream<TcpStream>, mut ssh: TcpStream, init: Option<Vec<u8>>) -> Result<(), Error> {
    if let Some(d) = init { ssh.write_all(&d).await?; }
    let (r1, w1) = tokio::io::split(tls);
    let (r2, w2) = ssh.into_split();
    let _ = tokio::join!(tokio::io::copy(&mut r1, &mut w2), tokio::io::copy(&mut r2, &mut w1));
    Ok(())
}

async fn cleanup(sid: &str) {
    if let Some(old) = SESSIONS.lock().await.remove(sid) {
        old.active.store(false, Ordering::Relaxed);
    }
}

async fn read_body<R: AsyncReadExt + Unpin>(r: &mut R, req: &[u8]) -> Result<Vec<u8>, Error> {
    let cl = extract_cl(req).unwrap_or(0);
    let h_end = req.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(0);
    let mut body = req[h_end..].to_vec();
    
    if body.len() < cl {
        let mut extra = vec![0u8; cl - body.len()];
        r.read_exact(&mut extra).await?;
        body.extend(extra);
    }
    Ok(body)
}

fn parse(data: &[u8]) -> Option<(String, String)> {
    let s = String::from_utf8_lossy(data);
    let parts: Vec<&str> = s.lines().next()?.split_whitespace().collect();
    if parts.len() >= 2 { Some((parts[0].to_string(), parts[1].to_string())) } else { None }
}

fn extract(path: &str) -> String {
    path.split('?').next().unwrap_or(path)
        .trim_start_matches('/')
        .split('/')
        .find(|p| !p.is_empty() && !["ssh", "xhttp", "split"].contains(p))
        .unwrap_or("default")
        .to_string()
}

fn extract_cl(data: &[u8]) -> Option<usize> {
    String::from_utf8_lossy(data)
        .lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1)?.trim().parse().ok())
}

fn build_tls_config() -> Result<rustls::ServerConfig, Error> {
    use std::io::BufReader;
    use std::fs::File;
    
    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut BufReader::new(File::open("/opt/mpro/cert.pem")?))
        .collect::<Result<Vec<_>, _>>()?.into_iter().map(Certificate).collect();
    let keys: Vec<PrivateKey> = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(File::open("/opt/mpro/key.pem")?))
        .collect::<Result<Vec<_>, _>>()?.into_iter().map(PrivateKey).collect();
    
    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.into_iter().next().ok_or("no key")?)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn get_port() -> u16 { 
    std::env::args().enumerate().find(|(_, a)| a == "--port" || a == "-p")
        .and_then(|(i, _)| std::env::args().nth(i+1))
        .and_then(|a| a.parse().ok()).unwrap_or(443) 
}
fn get_ssh_port() -> u16 { 
    std::env::args().enumerate().find(|(_, a)| a == "--ssh-port")
        .and_then(|(i, _)| std::env::args().nth(i+1))
        .and_then(|a| a.parse().ok()).unwrap_or(22) 
}
fn get_status() -> String { 
    std::env::args().enumerate().find(|(_, a)| a == "--status" || a == "-s")
        .and_then(|(i, _)| std::env::args().nth(i+1))
        .unwrap_or_else(|| "@Mpro".to_string()) 
}
