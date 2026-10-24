//! Policy validation, a port of agent/policy.py checked against shared vectors.

use crate::canonical::canonical_json;
use crate::error::{AgentError, Result};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const MAX_ENTRIES: usize = 10_000;
const MAX_WINDOWS: usize = 50;
const SAFE_SEARCH_ENGINES: [&str; 4] = ["google", "bing", "youtube", "duckduckgo"];
const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
/// Display names of the reference taxonomy, for the block page; pinned by the vectors.
const CATEGORY_LABELS: [(&str, &str); 21] = [
    ("adult", "Conteúdo adulto"),
    ("dating", "Relacionamentos"),
    ("gambling", "Jogos de azar"),
    ("malware", "Malware"),
    ("phishing", "Phishing"),
    ("hacking", "Hacking"),
    ("proxy", "VPN e proxies"),
    ("drugs", "Drogas"),
    ("violence", "Violência e ódio"),
    ("weapons", "Materiais perigosos"),
    ("warez", "Pirataria"),
    ("games", "Jogos"),
    ("streaming", "Áudio e vídeo"),
    ("filehosting", "Armazenamento e download de arquivos"),
    ("social", "Redes sociais"),
    ("chat", "Chat e mensageiros"),
    ("webmail", "Webmail"),
    ("shopping", "Compras"),
    ("sports", "Esportes"),
    ("press", "Notícias"),
    ("ads", "Publicidade"),
];

pub fn category_label(id: &str) -> Option<&'static str> {
    CATEGORY_LABELS.iter().find(|(known, _)| *known == id).map(|(_, label)| *label)
}

/// Category ids of the reference taxonomy (agent/policy.py CATEGORIES), pinned by the vectors.
pub const CATEGORY_IDS: [&str; 21] = [
    "adult",
    "dating",
    "gambling",
    "malware",
    "phishing",
    "hacking",
    "proxy",
    "drugs",
    "violence",
    "weapons",
    "warez",
    "games",
    "streaming",
    "filehosting",
    "social",
    "chat",
    "webmail",
    "shopping",
    "sports",
    "press",
    "ads",
];
const ZONE_PUNCTUATION: &str = "_+-";
const YOUTUBE_NAMES: [&str; 5] = [
    "www.youtube.com",
    "m.youtube.com",
    "youtubei.googleapis.com",
    "youtube.googleapis.com",
    "www.youtube-nocookie.com",
];

/// Published at https://www.google.com/supported_domains (187 entries, read 2026-10-23); vectors pin it to Python.
pub const GOOGLE_DOMAINS: &[&str] = &[
    "google.com",
    "google.ad",
    "google.ae",
    "google.com.af",
    "google.com.ag",
    "google.al",
    "google.am",
    "google.co.ao",
    "google.com.ar",
    "google.as",
    "google.at",
    "google.com.au",
    "google.az",
    "google.ba",
    "google.com.bd",
    "google.be",
    "google.bf",
    "google.bg",
    "google.com.bh",
    "google.bi",
    "google.bj",
    "google.com.bn",
    "google.com.bo",
    "google.com.br",
    "google.bs",
    "google.bt",
    "google.co.bw",
    "google.by",
    "google.com.bz",
    "google.ca",
    "google.cd",
    "google.cf",
    "google.cg",
    "google.ch",
    "google.ci",
    "google.co.ck",
    "google.cl",
    "google.cm",
    "google.cn",
    "google.com.co",
    "google.co.cr",
    "google.com.cu",
    "google.cv",
    "google.com.cy",
    "google.cz",
    "google.de",
    "google.dj",
    "google.dk",
    "google.dm",
    "google.com.do",
    "google.dz",
    "google.com.ec",
    "google.ee",
    "google.com.eg",
    "google.es",
    "google.com.et",
    "google.fi",
    "google.com.fj",
    "google.fm",
    "google.fr",
    "google.ga",
    "google.ge",
    "google.gg",
    "google.com.gh",
    "google.com.gi",
    "google.gl",
    "google.gm",
    "google.gr",
    "google.com.gt",
    "google.gy",
    "google.com.hk",
    "google.hn",
    "google.hr",
    "google.ht",
    "google.hu",
    "google.co.id",
    "google.ie",
    "google.co.il",
    "google.im",
    "google.co.in",
    "google.iq",
    "google.is",
    "google.it",
    "google.je",
    "google.com.jm",
    "google.jo",
    "google.co.jp",
    "google.co.ke",
    "google.com.kh",
    "google.ki",
    "google.kg",
    "google.co.kr",
    "google.com.kw",
    "google.kz",
    "google.la",
    "google.com.lb",
    "google.li",
    "google.lk",
    "google.co.ls",
    "google.lt",
    "google.lu",
    "google.lv",
    "google.com.ly",
    "google.co.ma",
    "google.md",
    "google.me",
    "google.mg",
    "google.mk",
    "google.ml",
    "google.com.mm",
    "google.mn",
    "google.com.mt",
    "google.mu",
    "google.mv",
    "google.mw",
    "google.com.mx",
    "google.com.my",
    "google.co.mz",
    "google.com.na",
    "google.com.ng",
    "google.com.ni",
    "google.ne",
    "google.nl",
    "google.no",
    "google.com.np",
    "google.nr",
    "google.nu",
    "google.co.nz",
    "google.com.om",
    "google.com.pa",
    "google.com.pe",
    "google.com.pg",
    "google.com.ph",
    "google.com.pk",
    "google.pl",
    "google.pn",
    "google.com.pr",
    "google.ps",
    "google.pt",
    "google.com.py",
    "google.com.qa",
    "google.ro",
    "google.ru",
    "google.rw",
    "google.com.sa",
    "google.com.sb",
    "google.sc",
    "google.se",
    "google.com.sg",
    "google.sh",
    "google.si",
    "google.sk",
    "google.com.sl",
    "google.sn",
    "google.so",
    "google.sm",
    "google.sr",
    "google.st",
    "google.com.sv",
    "google.td",
    "google.tg",
    "google.co.th",
    "google.com.tj",
    "google.tl",
    "google.tm",
    "google.tn",
    "google.to",
    "google.com.tr",
    "google.tt",
    "google.com.tw",
    "google.co.tz",
    "google.com.ua",
    "google.co.ug",
    "google.co.uk",
    "google.com.uy",
    "google.co.uz",
    "google.com.vc",
    "google.co.ve",
    "google.co.vi",
    "google.com.vn",
    "google.vu",
    "google.ws",
    "google.rs",
    "google.co.za",
    "google.co.zm",
    "google.co.zw",
    "google.cat",
];

type Normalizer = fn(&str) -> Result<String>;

pub fn policy_digest(body: &Map<String, Value>) -> String {
    let encoded = canonical_json(&Value::Object(body.clone()));
    hex::encode(Sha256::digest(encoded.as_bytes()))
}

fn invalid(message: &str) -> AgentError {
    AgentError::Policy(message.to_owned())
}

fn is_python_space(character: char) -> bool {
    // str.isspace() also treats the ASCII information separators as spaces.
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

fn valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let alphanumeric = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    !bytes.is_empty()
        && bytes.len() <= 63
        && alphanumeric(&bytes[0])
        && alphanumeric(&bytes[bytes.len() - 1])
        && bytes.iter().all(|byte| alphanumeric(byte) || *byte == b'-')
}

pub fn normalize_domain(value: &str) -> Result<String> {
    if value.is_empty() || value.chars().any(is_python_space) {
        return Err(invalid("blocked domain must be a nonempty hostname without whitespace"));
    }
    if value.chars().any(|c| "*/\\:@?#%".contains(c)) || value.ends_with('.') {
        return Err(invalid("URLs, wildcards, addresses and paths are not supported domains"));
    }
    let domain = if value.is_ascii() {
        value.to_ascii_lowercase()
    } else {
        idna::domain_to_ascii(value).map_err(|_| invalid("invalid IDNA hostname"))?
    };
    let labels: Vec<&str> = domain.split('.').collect();
    if domain.len() > 253 || labels.len() < 2 || !labels.iter().all(|label| valid_label(label)) {
        return Err(invalid("invalid hostname"));
    }
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return Err(invalid("IP addresses are not supported domains"));
    }
    Ok(domain)
}

/// Exact domain, or a leading wildcard covering the domain and every subdomain.
pub fn normalize_domain_rule(value: &str) -> Result<String> {
    match value.strip_prefix("*.") {
        Some(rest) => Ok(format!("*.{}", normalize_domain(rest)?)),
        None => normalize_domain(value),
    }
}

fn rule_matches(rule: &str, name: &str) -> bool {
    match rule.strip_prefix("*.") {
        Some(base) => name == base || name.strip_suffix(base).is_some_and(|prefix| prefix.ends_with('.')),
        None => name == rule || (!rule.starts_with("www.") && name.strip_prefix("www.") == Some(rule)),
    }
}

/// Normalized blocking and allow rules; the resolver and the block page share this decision.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WebRules {
    blocked: Vec<String>,
    allowed: Vec<String>,
}

impl WebRules {
    pub fn new(blocked: &[String], allowed: &[String]) -> Result<Self> {
        let normalize = |rules: &[String]| rules.iter().map(|rule| normalize_domain_rule(rule)).collect::<Result<_>>();
        Ok(WebRules { blocked: normalize(blocked)?, allowed: normalize(allowed)? })
    }

    pub fn blocked(&self) -> &[String] {
        &self.blocked
    }

    /// Allowed rules win; names that are not valid hostnames are never blocked.
    pub fn blocks(&self, name: &str) -> bool {
        let Ok(domain) = normalize_domain(name) else { return false };
        self.blocked.iter().any(|rule| rule_matches(rule, &domain))
            && !self.allowed.iter().any(|rule| rule_matches(rule, &domain))
    }

    /// Names a hosts file can hold: wildcards degrade to the domain and its www name.
    pub fn hosts_names(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for rule in &self.blocked {
            let base = rule.strip_prefix("*.").unwrap_or(rule);
            let candidates = if base.starts_with("www.") {
                vec![base.to_owned()]
            } else {
                vec![base.to_owned(), format!("www.{base}")]
            };
            for name in candidates {
                if self.blocks(&name) && !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        names
    }
}

pub fn normalize_process(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let first_ok = bytes.first().is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
    let rest_ok = bytes.iter().skip(1).all(|byte| byte.is_ascii_alphanumeric() || b"_. -".contains(byte));
    if !first_ok || !rest_ok || bytes.len() > 254 {
        return Err(invalid("blocked application must be an exact executable image name"));
    }
    if value != value.trim() || value.contains("..") || value.ends_with('.') {
        return Err(invalid("invalid executable image name"));
    }
    Ok(value.to_ascii_lowercase())
}

/// Validate and normalize a policy body; unknown sections pass through untouched.
pub fn validate_policy(body: &Value) -> Result<Value> {
    let Some(object) = body.as_object() else {
        return Err(invalid("policy body must be an object"));
    };
    let mut normalized = object.clone();
    let sections: [(&str, &str, Normalizer); 3] = [
        ("web_filter", "blocked", normalize_domain_rule),
        ("web_filter", "allowed", normalize_domain_rule),
        ("app_control", "blocked", normalize_process),
    ];
    for (section, key, normalize) in sections {
        let Some(settings) = normalized.get_mut(section) else { continue };
        let Some(settings) = settings.as_object_mut() else {
            return Err(AgentError::Policy(format!("{section}.{key} must be a list")));
        };
        let entries = match settings.get(key) {
            // "blocked" is always materialized; "allowed" only when the policy sets it.
            None if key != "blocked" => continue,
            None => Vec::new(),
            Some(Value::Array(items)) => items.clone(),
            Some(_) => return Err(AgentError::Policy(format!("{section}.{key} must be a list"))),
        };
        if entries.len() > MAX_ENTRIES {
            return Err(invalid("policy list exceeds 10000 entries"));
        }
        let mut unique: Vec<Value> = Vec::with_capacity(entries.len());
        for entry in entries {
            let Some(text) = entry.as_str() else {
                return Err(invalid("policy entries must be strings"));
            };
            let value = Value::String(normalize(text)?);
            if !unique.contains(&value) {
                unique.push(value);
            }
        }
        settings.insert(key.to_owned(), Value::Array(unique));
    }
    if let Some(Value::Object(settings)) = normalized.get_mut("web_filter") {
        validate_web_extensions(settings)?;
    }
    Ok(Value::Object(normalized))
}

/// Minutes since midnight for a strict `HH:MM` value.
fn clock_minutes(value: &Value) -> Option<u16> {
    let text = value.as_str()?;
    let bytes = text.as_bytes();
    let digits = [0, 1, 3, 4].iter().all(|index| bytes.get(*index).is_some_and(u8::is_ascii_digit));
    if bytes.len() != 5 || bytes[2] != b':' || !digits {
        return None;
    }
    let (hours, minutes) = (text[..2].parse::<u16>().ok()?, text[3..].parse::<u16>().ok()?);
    (hours < 24 && minutes < 60).then_some(hours * 60 + minutes)
}

fn zone_part(part: &str) -> bool {
    !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || ZONE_PUNCTUATION.contains(c))
}

fn valid_zone_name(name: &str) -> bool {
    name.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) && name.split('/').all(zone_part)
}

fn time_zone(value: &Value) -> Result<jiff::tz::TimeZone> {
    let name = value
        .as_str()
        .filter(|name| valid_zone_name(name))
        .ok_or_else(|| invalid("timezone must be an IANA zone name"))?;
    jiff::tz::db().get(name).map_err(|_| invalid("unknown timezone"))
}

fn distinct_members(value: &Value, allowed: &[&str], nonempty: bool) -> Option<Vec<String>> {
    let items = value.as_array()?;
    let mut seen: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let text = item.as_str().filter(|text| allowed.contains(text))?;
        if seen.iter().any(|known| known == text) {
            return None;
        }
        seen.push(text.to_owned());
    }
    (!nonempty || !seen.is_empty()).then_some(seen)
}

fn normalized_rules(rules: &[Value]) -> Result<Vec<Value>> {
    let mut unique: Vec<Value> = Vec::with_capacity(rules.len());
    for rule in rules {
        let text = rule.as_str().ok_or_else(|| invalid("policy entries must be strings"))?;
        let value = Value::String(normalize_domain_rule(text)?);
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    Ok(unique)
}

fn validate_categories(value: &Value) -> Result<()> {
    distinct_members(value, &CATEGORY_IDS, false)
        .map(|_| ())
        .ok_or_else(|| invalid("blocked_categories must list distinct known categories"))
}

/// Port of `_validate_web_extensions`: categories, safe_search, timezone and scheduled windows.
fn validate_web_extensions(settings: &mut Map<String, Value>) -> Result<()> {
    if let Some(value) = settings.get("blocked_categories") {
        validate_categories(value)?;
    }
    if let Some(value) = settings.get("safe_search") {
        let Some(safe) = value.as_object().filter(|safe| safe.keys().all(|key| key == "engines" || key == "youtube"))
        else {
            return Err(invalid("safe_search must be an object with engines and youtube"));
        };
        let engines = safe.get("engines").cloned().unwrap_or(Value::Array(Vec::new()));
        if distinct_members(&engines, &SAFE_SEARCH_ENGINES, false).is_none() {
            return Err(invalid("safe_search.engines must list distinct supported engines"));
        }
        if !matches!(safe.get("youtube").map(Value::as_str), None | Some(Some("strict" | "moderate"))) {
            return Err(invalid("safe_search.youtube must be strict or moderate"));
        }
    }
    if let Some(value) = settings.get("timezone") {
        time_zone(value)?;
    }
    let Some(windows) = settings.get("scheduled").cloned() else { return Ok(()) };
    let Some(windows) = windows.as_array().filter(|windows| windows.len() <= MAX_WINDOWS) else {
        return Err(invalid("scheduled must be a list of at most 50 windows"));
    };
    if !windows.is_empty() && !settings.contains_key("timezone") {
        return Err(invalid("scheduled rules require a timezone"));
    }
    let mut normalized = Vec::with_capacity(windows.len());
    for window in windows {
        let allowed = ["blocked", "blocked_categories", "days", "from", "to"];
        let Some(mut window) = window.as_object().cloned().filter(|window| {
            window.keys().all(|key| allowed.contains(&key.as_str()))
                && ["days", "from", "to"].iter().all(|key| window.contains_key(*key))
                && (window.contains_key("blocked") || window.contains_key("blocked_categories"))
        }) else {
            return Err(invalid("schedule window needs days, from, to and blocked rules or categories"));
        };
        let rules = window.get("blocked").cloned().unwrap_or(Value::Array(Vec::new()));
        let Some(rules) = rules.as_array().filter(|rules| rules.len() <= MAX_ENTRIES).cloned() else {
            return Err(invalid("schedule window blocked must be a list of at most 10000 rules"));
        };
        if distinct_members(&window["days"], &DAYS, true).is_none() {
            return Err(invalid("schedule window days must list distinct weekdays"));
        }
        let (Some(start), Some(end)) = (clock_minutes(&window["from"]), clock_minutes(&window["to"])) else {
            return Err(invalid("schedule window times must be HH:MM"));
        };
        if start >= end {
            return Err(invalid("schedule window must start before it ends; split windows across midnight"));
        }
        if window.contains_key("blocked") {
            window.insert("blocked".to_owned(), Value::Array(normalized_rules(&rules)?));
        }
        if let Some(categories) = window.get("blocked_categories") {
            validate_categories(categories)?;
        }
        normalized.push(Value::Object(window));
    }
    settings.insert("scheduled".to_owned(), Value::Array(normalized));
    Ok(())
}

#[derive(Debug, Clone)]
struct Window {
    blocked: Vec<String>,
    categories: Vec<String>,
    days: [bool; 7],
    from: u16,
    to: u16,
}

/// Why a name is blocked, for the block log and the block page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    Rule,
    Category(String),
}

impl BlockReason {
    /// Same shape as `block_reason` in agent/policy.py.
    pub fn to_json(&self) -> Value {
        match self {
            BlockReason::Rule => serde_json::json!({"reason": "rule"}),
            BlockReason::Category(id) => serde_json::json!({"reason": "category", "category": id}),
        }
    }
}

/// Validated web filter: unscheduled rules, scheduled windows in the policy timezone and SafeSearch.
#[derive(Debug, Clone, Default)]
pub struct WebFilter {
    blocked: Vec<String>,
    allowed: Vec<String>,
    categories: Vec<String>,
    windows: Vec<Window>,
    timezone: Option<jiff::tz::TimeZone>,
    engines: Vec<String>,
    youtube_moderate: bool,
}

impl From<WebRules> for WebFilter {
    fn from(rules: WebRules) -> Self {
        WebFilter { blocked: rules.blocked, allowed: rules.allowed, ..WebFilter::default() }
    }
}

fn text_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default()
}

impl WebFilter {
    /// Build from a `web_filter` object that already passed `validate_policy` (or null).
    pub fn from_settings(settings: &Value) -> Result<Self> {
        let rules = WebRules::new(&text_list(settings.get("blocked")), &text_list(settings.get("allowed")))?;
        let mut windows = Vec::new();
        for window in settings.get("scheduled").and_then(Value::as_array).into_iter().flatten() {
            let mut days = [false; 7];
            for day in text_list(window.get("days")) {
                if let Some(index) = DAYS.iter().position(|known| *known == day) {
                    days[index] = true;
                }
            }
            let bound =
                |key: &str| window.get(key).and_then(clock_minutes).ok_or_else(|| invalid("invalid schedule window"));
            windows.push(Window {
                blocked: WebRules::new(&text_list(window.get("blocked")), &[])?.blocked,
                categories: text_list(window.get("blocked_categories")),
                days,
                from: bound("from")?,
                to: bound("to")?,
            });
        }
        let safe = settings.get("safe_search");
        Ok(WebFilter {
            blocked: rules.blocked,
            allowed: rules.allowed,
            categories: text_list(settings.get("blocked_categories")),
            windows,
            timezone: settings.get("timezone").map(time_zone).transpose()?,
            engines: text_list(safe.and_then(|safe| safe.get("engines"))),
            youtube_moderate: safe.and_then(|safe| safe.get("youtube")).and_then(Value::as_str) == Some("moderate"),
        })
    }

    /// Which windows are open at `when`; a change in this mask is a schedule edge.
    pub fn active_windows(&self, when: jiff::Timestamp) -> Vec<bool> {
        let Some(zone) = &self.timezone else { return vec![false; self.windows.len()] };
        let local = when.to_zoned(zone.clone());
        let day = local.weekday().to_monday_zero_offset() as usize;
        let minute = local.hour() as u16 * 60 + local.minute() as u16;
        self.windows.iter().map(|window| window.days[day] && window.from <= minute && minute < window.to).collect()
    }

    /// Unscheduled rules plus every window open at `when`, with the allow list.
    pub fn rules_at(&self, when: jiff::Timestamp) -> WebRules {
        let mut blocked = self.blocked.clone();
        for (window, open) in self.windows.iter().zip(self.active_windows(when)) {
            if open {
                blocked.extend(window.blocked.iter().cloned());
            }
        }
        WebRules { blocked, allowed: self.allowed.clone() }
    }

    pub fn blocks_at(&self, name: &str, when: jiff::Timestamp) -> bool {
        self.blocks_at_with(name, when, &crate::categories::NoCategories)
    }

    /// Categories blocked at `when`: unscheduled ones plus those of every open window.
    pub fn active_categories(&self, when: jiff::Timestamp) -> Vec<String> {
        let mut categories = self.categories.clone();
        for (window, open) in self.windows.iter().zip(self.active_windows(when)) {
            if open {
                categories.extend(window.categories.iter().cloned());
            }
        }
        categories.dedup();
        categories
    }

    /// Every category the policy can use at any time; these are the ones to download.
    pub fn referenced_categories(&self) -> Vec<String> {
        let mut categories: Vec<String> = self
            .categories
            .iter()
            .chain(self.windows.iter().flat_map(|window| window.categories.iter()))
            .cloned()
            .collect();
        categories.sort();
        categories.dedup();
        categories
    }

    /// Rules, then categories; allowed rules win over both, and missing category data never blocks.
    pub fn blocks_at_with(
        &self,
        name: &str,
        when: jiff::Timestamp,
        lookup: &dyn crate::categories::CategoryLookup,
    ) -> bool {
        self.block_reason_at(name, when, lookup).is_some()
    }

    /// A rule, else the first active category containing the name; None when it is not blocked.
    pub fn block_reason_at(
        &self,
        name: &str,
        when: jiff::Timestamp,
        lookup: &dyn crate::categories::CategoryLookup,
    ) -> Option<BlockReason> {
        if self.rules_at(when).blocks(name) {
            return Some(BlockReason::Rule);
        }
        let domain = normalize_domain(name).ok()?;
        let category = self.active_categories(when).into_iter().find(|category| lookup.contains(category, &domain))?;
        if self.allowed.iter().any(|rule| rule_matches(rule, &domain)) {
            return None;
        }
        Some(BlockReason::Category(category))
    }

    pub fn has_schedule(&self) -> bool {
        !self.windows.is_empty()
    }

    /// Enforced SafeSearch host for a search engine name, or None.
    pub fn safe_search_target(&self, name: &str) -> Option<&'static str> {
        let domain = normalize_domain(name).ok()?;
        let enabled = |engine: &str| self.engines.iter().any(|known| known == engine);
        if enabled("google") && GOOGLE_DOMAINS.contains(&domain.strip_prefix("www.").unwrap_or(&domain)) {
            return Some("forcesafesearch.google.com");
        }
        if enabled("youtube") && YOUTUBE_NAMES.contains(&domain.as_str()) {
            return Some(if self.youtube_moderate { "restrictmoderate.youtube.com" } else { "restrict.youtube.com" });
        }
        if enabled("bing") && domain == "www.bing.com" {
            return Some("strict.bing.com");
        }
        if enabled("duckduckgo") && (domain == "duckduckgo.com" || domain == "www.duckduckgo.com") {
            return Some("safe.duckduckgo.com");
        }
        None
    }
}

/// Server assignment: either a signed policy or an explicit release (version 0).
#[derive(Debug, Clone, PartialEq)]
pub struct Assignment {
    pub vdom: String,
    pub version: i64,
    pub digest: String,
    pub body: Option<Map<String, Value>>,
    pub unassigned: bool,
    /// Exact payload as received, persisted so a restart re-verifies the same bytes.
    pub raw: Value,
}

impl Assignment {
    pub fn identity(&self) -> (String, i64, String) {
        (self.vdom.clone(), self.version, self.digest.clone())
    }

    fn effective_body(&self) -> Result<Value> {
        match &self.body {
            Some(body) if !self.unassigned => validate_policy(&Value::Object(body.clone())),
            _ => Ok(Value::Object(Map::new())),
        }
    }

    /// Effective blocking lists; a release enforces an empty policy.
    pub fn blocked_lists(&self) -> Result<(Vec<String>, Vec<String>)> {
        let body = self.effective_body()?;
        Ok((string_list(&body, "web_filter", "blocked"), string_list(&body, "app_control", "blocked")))
    }

    /// Full web filter (schedules, SafeSearch); a release yields an empty filter.
    pub fn web_filter(&self) -> Result<WebFilter> {
        let body = self.effective_body()?;
        WebFilter::from_settings(body.get("web_filter").unwrap_or(&Value::Null))
    }

    /// Web filter rules including the allow list; a release yields no rules.
    pub fn web_rules(&self) -> Result<WebRules> {
        let body = self.effective_body()?;
        WebRules::new(&string_list(&body, "web_filter", "blocked"), &string_list(&body, "web_filter", "allowed"))
    }
}

fn string_list(body: &Value, section: &str, key: &str) -> Vec<String> {
    body.get(section)
        .and_then(|settings| settings.get(key))
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default()
}

/// Port of `_validated_profile`: reject anything whose digest does not match its body.
pub fn validate_assignment(value: &Value) -> Result<Assignment> {
    let vdom = value
        .get("vdom")
        .and_then(Value::as_str)
        .filter(|vdom| !vdom.is_empty())
        .ok_or_else(|| invalid("invalid assignment identity"))?;
    let version = value.get("version").and_then(Value::as_i64).ok_or_else(|| invalid("invalid assignment version"))?;
    let digest = value.get("digest").and_then(Value::as_str).unwrap_or_default();
    let body = value.get("body");
    let unassigned = value.get("unassigned").and_then(Value::as_bool) == Some(true);
    if unassigned {
        if version != 0
            || !matches!(body, None | Some(Value::Null))
            || value.get("digest").and_then(Value::as_str) != Some("")
        {
            return Err(invalid("invalid policy release"));
        }
        return Ok(Assignment {
            vdom: vdom.into(),
            version,
            digest: String::new(),
            body: None,
            unassigned,
            raw: value.clone(),
        });
    }
    let Some(Value::Object(body)) = body else {
        return Err(invalid("policy integrity check failed"));
    };
    if version <= 0 || digest != policy_digest(body) {
        return Err(invalid("policy integrity check failed"));
    }
    validate_policy(&Value::Object(body.clone()))?;
    Ok(Assignment {
        vdom: vdom.into(),
        version,
        digest: digest.into(),
        body: Some(body.clone()),
        unassigned,
        raw: value.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn signed_assignment_is_verified() {
        let body = json!({"web_filter": {"blocked": ["example.com"]}});
        let digest = policy_digest(body.as_object().unwrap());
        let assignment =
            validate_assignment(&json!({"vdom": "Default", "version": 2, "digest": digest, "body": body})).unwrap();
        assert_eq!(assignment.blocked_lists().unwrap(), (vec!["example.com".to_owned()], vec![]));
        let tampered = json!({"vdom": "Default", "version": 2, "digest": digest, "body": {"web_filter": {"blocked": ["evil.com"]}}});
        assert!(validate_assignment(&tampered).is_err());
    }

    #[test]
    fn release_must_be_exact() {
        let release = json!({"vdom": "Empty", "version": 0, "digest": "", "body": null, "unassigned": true});
        let assignment = validate_assignment(&release).unwrap();
        assert_eq!(assignment.blocked_lists().unwrap(), (vec![], vec![]));
        assert!(
            validate_assignment(
                &json!({"vdom": "Empty", "version": 1, "digest": "", "body": null, "unassigned": true})
            )
            .is_err()
        );
        assert!(validate_assignment(&json!({"vdom": "", "version": 0, "digest": "", "unassigned": true})).is_err());
        assert!(validate_assignment(&json!({"vdom": "X", "version": true, "digest": ""})).is_err());
    }
}
