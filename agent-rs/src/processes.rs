//! Application control by exact executable image name (pre-execution blocking is F3).

use crate::error::{AgentError, Result};
use crate::policy::normalize_process;
use std::process::Command;

pub fn processes_to_kill(running: &[String], blocked: &[String]) -> Result<Vec<String>> {
    let wanted = blocked.iter().map(|name| normalize_process(name)).collect::<Result<Vec<_>>>()?;
    let mut seen: Vec<String> = Vec::new();
    let mut matches = Vec::new();
    for name in running {
        let lower = name.to_ascii_lowercase();
        if wanted.contains(&lower) && !seen.contains(&lower) {
            seen.push(lower);
            matches.push(name.clone());
        }
    }
    Ok(matches)
}

/// First field of `tasklist /fo csv /nh` lines.
pub fn parse_tasklist(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            line.strip_prefix('"').and_then(|rest| rest.split_once('"')).map(|(name, _)| name.to_owned())
        })
        .filter(|name| !name.is_empty())
        .collect()
}

pub fn list_processes() -> Result<Vec<String>> {
    let output = if cfg!(windows) {
        Command::new("tasklist").args(["/fo", "csv", "/nh"]).output()?
    } else {
        Command::new("ps").args(["-eo", "comm="]).output()?
    };
    if !output.status.success() {
        return Err(AgentError::Local("process listing failed".into()));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(if cfg!(windows) {
        parse_tasklist(&text)
    } else {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|line| line.rsplit('/').next().unwrap_or(line).to_owned())
            .collect()
    })
}

pub fn kill_process(name: &str) -> Result<()> {
    normalize_process(name)?;
    let status = if cfg!(windows) {
        Command::new("taskkill").args(["/f", "/im", name]).output()?.status
    } else {
        Command::new("pkill").args(["-x", name]).output()?.status
    };
    if status.success() { Ok(()) } else { Err(AgentError::Local("process termination failed".into())) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_are_case_insensitive_and_deduplicated() {
        let running: Vec<String> = ["chrome.exe", "PING.EXE", "ping.exe", "notepad.exe"].map(String::from).to_vec();
        assert_eq!(processes_to_kill(&running, &["ping.exe".into()]).unwrap(), vec!["PING.EXE".to_owned()]);
        assert!(processes_to_kill(&running, &["../evil.exe".into()]).is_err());
    }

    #[test]
    fn parses_tasklist_csv() {
        let output = "\"System Idle Process\",\"0\",\"Services\",\"0\",\"8 K\"\r\n\"chrome.exe\",\"4242\",\"Console\",\"1\",\"120.000 K\"\r\n";
        assert_eq!(parse_tasklist(output), vec!["System Idle Process".to_owned(), "chrome.exe".to_owned()]);
    }
}
