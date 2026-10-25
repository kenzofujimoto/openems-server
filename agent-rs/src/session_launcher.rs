//! Opens openems-session.exe in every active user session and closes them all when the service stops
//! (session-component.md, decisions 1 and 5). Runs as SYSTEM inside the service.

use crate::error::{AgentError, Result};
use std::path::Path;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive, WTSEnumerateSessionsW,
    WTSFreeMemory, WTSQueryUserToken,
};
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, OpenProcess, PROCESS_INFORMATION, PROCESS_TERMINATE,
    STARTUPINFOW, TerminateProcess,
};

pub const COMPONENT: &str = "openems-session.exe";

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// (process id, session id) of every running component.
fn components() -> Result<Vec<(u32, u32)>> {
    // SAFETY: the snapshot handle is checked and closed; the entry has its size set before the walk.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut found = Vec::new();
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snapshot, &mut entry) != 0;
        while more {
            let length = entry.szExeFile.iter().position(|&unit| unit == 0).unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..length]);
            let mut session = u32::MAX;
            if name.eq_ignore_ascii_case(COMPONENT) && ProcessIdToSessionId(entry.th32ProcessID, &mut session) != 0 {
                found.push((entry.th32ProcessID, session));
            }
            more = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
        Ok(found)
    }
}

/// Sessions with a signed-in user at the console or over Remote Desktop (session 0 is services only).
fn active_sessions() -> Result<Vec<u32>> {
    // SAFETY: Windows allocates the array; it is read within `count` and released with WTSFreeMemory.
    unsafe {
        let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count = 0u32;
        if WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut info, &mut count) == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let sessions = std::slice::from_raw_parts(info, count as usize)
            .iter()
            .filter(|session| session.State == WTSActive && session.SessionId != 0)
            .map(|session| session.SessionId)
            .collect();
        WTSFreeMemory(info.cast());
        Ok(sessions)
    }
}

fn launch(executable: &Path, session: u32) -> Result<()> {
    let application = wide(&executable.to_string_lossy());
    let mut command_line = wide(&format!("\"{}\"", executable.to_string_lossy()));
    let directory = executable.parent().map(|parent| wide(&parent.to_string_lossy()));
    let mut desktop = wide("winsta0\\default");
    // SAFETY: the user token and environment block are released on every path; buffers are
    // NUL-terminated and outlive CreateProcessAsUserW; the process and thread handles are closed.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if WTSQueryUserToken(session, &mut token) == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut environment: *mut core::ffi::c_void = std::ptr::null_mut();
        let has_environment = CreateEnvironmentBlock(&mut environment, token, 0) != 0;
        let mut startup: STARTUPINFOW = std::mem::zeroed();
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        startup.lpDesktop = desktop.as_mut_ptr();
        let mut process: PROCESS_INFORMATION = std::mem::zeroed();
        let created = CreateProcessAsUserW(
            token,
            application.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_UNICODE_ENVIRONMENT,
            if has_environment { environment } else { std::ptr::null() },
            directory.as_ref().map_or(std::ptr::null(), |directory| directory.as_ptr()),
            &startup,
            &mut process,
        );
        let error = std::io::Error::last_os_error();
        if has_environment {
            DestroyEnvironmentBlock(environment);
        }
        CloseHandle(token);
        if created == 0 {
            return Err(error.into());
        }
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    Ok(())
}

/// Open the component in each active session that has none. Returns the sessions it was opened in.
pub fn ensure_components(executable: &Path) -> Result<Vec<u32>> {
    if !executable.is_file() {
        return Err(AgentError::Local(format!("{COMPONENT} is not installed next to the agent")));
    }
    let running: Vec<u32> = components()?.into_iter().map(|(_, session)| session).collect();
    let mut opened = Vec::new();
    for session in active_sessions()? {
        if !running.contains(&session) {
            launch(executable, session)?;
            opened.push(session);
        }
    }
    Ok(opened)
}

/// Close every component so upgrades and removal never find the executable in use.
pub fn stop_components() -> Result<()> {
    for (process_id, _) in components()? {
        // SAFETY: the handle is checked and closed; terminating our own component is the intent.
        unsafe {
            let process = OpenProcess(PROCESS_TERMINATE, 0, process_id);
            if !process.is_null() {
                TerminateProcess(process, 0);
                CloseHandle(process);
            }
        }
    }
    Ok(())
}
