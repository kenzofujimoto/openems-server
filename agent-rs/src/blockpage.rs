//! Local block and warning page for domains redirected to 127.0.0.1, in the build's edition (see `brand`).
//! Same markup as agent/blockpage.py; everything is inline so it works offline.

use crate::error::Result;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::https_blockpage::BlockedDomains;
use crate::runtime::StopSignal;

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

const BLOCKED: &str = "Este site foi bloqueado pela pol&iacute;tica de seguran&ccedil;a da sua organiza&ccedil;&atilde;o.\n      Se voc&ecirc; acredita que isto &eacute; um engano, fale com o time de TI.";
const WARNED: &str = "A pol&iacute;tica da sua organiza&ccedil;&atilde;o pede aten&ccedil;&atilde;o a sites desta categoria.\n      Se ele for necess&aacute;rio, voc&ecirc; pode continuar; o acesso fica registrado.";
const PROCEEDED: &str = "Voc&ecirc; pode acessar sites desta categoria nos pr&oacute;ximos minutos. A p&aacute;gina ser&aacute; recarregada.";
/// Path of the warning page's form; never a real site path that matters, the page is only served locally.
pub const PROCEED_PATH: &str = "/__openems/proceed";

/// What the local page shows for a name redirected to the agent.
pub enum Page<'a> {
    Blocked,
    /// Warning with a single-use token for the "continue" form.
    Warning(&'a str),
    Proceeded,
}

pub fn render(host: &str, category: Option<&str>) -> String {
    render_page(host, category, &Page::Blocked)
}

pub fn render_page(host: &str, category: Option<&str>, page: &Page<'_>) -> String {
    let host = if host.is_empty() { "este site".to_owned() } else { escape_html(host) };
    let category = category
        .map_or_else(String::new, |label| format!("<div class=\"category\">Categoria: {}</div>", escape_html(label)));
    let (title, message, action, head) = match page {
        Page::Blocked => ("Acesso bloqueado", BLOCKED, String::new(), ""),
        Page::Warning(token) => (
            "Aten&ccedil;&atilde;o",
            WARNED,
            format!(
                "<form method=\"post\" action=\"{PROCEED_PATH}?token={}\"><button type=\"submit\">Continuar mesmo assim</button></form>",
                escape_html(token)
            ),
            "",
        ),
        Page::Proceeded => {
            ("Acesso liberado", PROCEEDED, String::new(), "<meta http-equiv=\"refresh\" content=\"6;url=/\">")
        }
    };
    PAGE.replace("{theme}", crate::brand::THEME)
        .replace("{logo_mime}", crate::brand::LOGO_MIME)
        .replace("{logo_alt}", crate::brand::LOGO_ALT)
        .replace("{footer}", crate::brand::FOOTER)
        .replace("{logo}", &base64(crate::brand::LOGO))
        .replace("{head}", head)
        .replace("{title}", title)
        .replace("{message}", message)
        .replace("{action}", &action)
        .replace("{host}", &host)
        .replace("{category}", &category)
}

/// `POST /__openems/proceed?token=…` from the warning form; None for every other request.
pub fn proceed_token(request: &str) -> Option<&str> {
    let target = request.strip_prefix("POST ")?.split(' ').next()?;
    let token = target.strip_prefix(PROCEED_PATH)?.strip_prefix("?token=")?;
    (token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(token)
}

/// The page for `host`, acting on the warning form when the request carries a valid token.
pub fn respond(request: &str, host: &str, blocked: &BlockedDomains) -> String {
    let label = blocked.category_label(host);
    if let Some(token) = proceed_token(request) {
        let page = if blocked.proceed(host, token) { Page::Proceeded } else { Page::Blocked };
        return render_page(host, label, &page);
    }
    if blocked.warns(host) {
        return render_page(host, label, &Page::Warning(&blocked.issue_token(host)));
    }
    render_page(host, label, &Page::Blocked)
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
    let body = respond(&request, &host, blocked);
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
        assert!(page.contains("Acesso bloqueado") && page.contains(crate::brand::FOOTER));
        if cfg!(feature = "rsm-brand") {
            assert!(page.contains("#009cde") && page.contains("Prelo"));
            assert!(page.contains("data:image/png;base64,iVBORw0KGgo") && page.contains("alt=\"RSM\""));
        } else {
            assert!(page.contains("#4f46e5") && page.contains("IBM Plex Sans") && !page.contains("RSM"));
            assert!(page.contains("data:image/svg+xml;base64,PHN2Zy"));
        }
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
