//! Local RSM-branded block page for domains redirected to 127.0.0.1.
//! Same markup as agent/blockpage.py; everything is inline so it works offline.

use crate::error::Result;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::https_blockpage::BlockedDomains;
use crate::runtime::StopSignal;

const LOGO: &[u8] = include_bytes!("../assets/rsm-logo.png");

const PAGE: &str = include_str!("blockpage.html");

fn base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let bytes = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let triple = u32::from(bytes[0]) << 16 | u32::from(bytes[1]) << 8 | u32::from(bytes[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(TABLE[(triple >> (18 - 6 * index) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn escape_html(text: &str) -> String {
    text.chars().fold(String::with_capacity(text.len()), |mut out, character| {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            other => out.push(other),
        }
        out
    })
}

pub fn render(host: &str, category: Option<&str>) -> String {
    let host = if host.is_empty() { "este site".to_owned() } else { escape_html(host) };
    let category = category
        .map_or_else(String::new, |label| format!("<div class=\"category\">Categoria: {}</div>", escape_html(label)));
    PAGE.replace("{logo}", &base64(LOGO)).replace("{host}", &host).replace("{category}", &category)
}

fn host_header(request: &str) -> String {
    request
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.trim().eq_ignore_ascii_case("host"))
                .map(|(_, value)| value.trim())
        })
        .map(|value| {
            value
                .rsplit_once(':')
                .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
                .map_or(value, |(host, _)| host)
        })
        .unwrap_or_default()
        .chars()
        .take(253)
        .collect()
}

fn serve(mut stream: TcpStream, blocked: &BlockedDomains) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut buffer = [0u8; 8192];
    let length = stream.read(&mut buffer).unwrap_or(0);
    let request = String::from_utf8_lossy(&buffer[..length]);
    let host = host_header(&request);
    let body = render(&host, blocked.category_label(&host));
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

/// Bind before returning so callers can report startup failures.
pub fn start(port: u16, blocked: Arc<BlockedDomains>, stop: Arc<StopSignal>) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    listener.set_nonblocking(true)?;
    Ok(std::thread::Builder::new().name("openems-blockpage".into()).spawn(move || {
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let listener = &listener;
                let stop = &stop;
                let blocked = &blocked;
                scope.spawn(move || {
                    while !stop.is_stopped() {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                if stream.set_nonblocking(false).is_ok() {
                                    serve(stream, blocked);
                                }
                            }
                            Err(_) => {
                                stop.wait(Duration::from_millis(200));
                            }
                        }
                    }
                });
            }
        });
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_is_branded_offline_and_escapes_hosts() {
        let page = render("<script>alert(1)</script>", None);
        assert!(page.contains("Acesso bloqueado") && page.contains("#009cde") && page.contains("Prelo"));
        assert!(page.contains("data:image/png;base64,iVBORw0KGgo"));
        assert!(page.contains("&lt;script&gt;") && !page.contains("<script>"));
        assert!(!page.contains("http://") && !page.contains("https://"));
    }

    #[test]
    fn base64_matches_rfc_4648() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn serves_the_page_for_any_host() {
        let stop = Arc::new(StopSignal::default());
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let worker = start(port, Arc::new(BlockedDomains::default()), Arc::clone(&stop)).unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client.write_all(b"GET /x HTTP/1.1\r\nHost: blocked.example:80\r\n\r\n").unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK") && response.contains("blocked.example"));
        stop.stop();
        worker.join().unwrap();
    }
}
