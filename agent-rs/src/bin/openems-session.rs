//! Session component (session-component.md): tray icon with the protection status and balloons for the
//! notices the service writes to session.json. Opened by the service in each user session; no console.
#![cfg_attr(windows, windows_subsystem = "windows")]

use clap::Parser;
use openems_agent::session::{SessionState, load, notices_to_show, tooltip};
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "openems-session", version, about = "openems session component")]
struct Cli {
    /// session.json to read (defaults to the service location).
    #[arg(long)]
    board: Option<PathBuf>,
    /// Print the tooltip and the notices a fresh component would show, then exit (no user interface).
    #[arg(long)]
    print: bool,
}

fn board_path(cli: &Cli) -> PathBuf {
    cli.board.clone().unwrap_or_else(|| openems_agent::config::data_dir().join("session.json"))
}

fn read(path: &std::path::Path) -> SessionState {
    load(path).ok().flatten().unwrap_or_default()
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let path = board_path(&cli);
    if cli.print {
        let state = read(&path);
        let now = jiff::Timestamp::now();
        let shown = json!({ "tooltip": tooltip(&state, now), "notices": notices_to_show(&state, None, now) });
        println!("{shown}");
        return ExitCode::SUCCESS;
    }
    #[cfg(windows)]
    {
        tray::run(path);
        ExitCode::SUCCESS
    }
    #[cfg(not(windows))]
    {
        eprintln!("the session component needs Windows; use --print elsewhere");
        ExitCode::FAILURE
    }
}

#[cfg(windows)]
mod tray {
    use super::read;
    use openems_agent::session::{notices_to_show, tooltip};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Threading::CreateMutexW;
    use windows_sys::Win32::UI::Shell::{
        NIF_ICON, NIF_INFO, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW, Shell_NotifyIconW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, IDI_SHIELD, LoadIconW, MSG, PostQuitMessage,
        RegisterClassW, RegisterWindowMessageW, SetTimer, TranslateMessage, WM_CLOSE, WM_DESTROY, WM_ENDSESSION,
        WM_QUERYENDSESSION, WM_TIMER, WNDCLASSW, WS_OVERLAPPED,
    };

    const POLL_MS: u32 = 5000;
    const TITLE: &str = "RSM Endpoint";

    struct Tray {
        board: PathBuf,
        window: HWND,
        last_shown: Option<u64>,
        tip: String,
        taskbar_created: u32,
    }

    // SAFETY: the window handle is only used from the UI thread that owns the message loop.
    unsafe impl Send for Tray {}

    static STATE: Mutex<Option<Tray>> = Mutex::new(None);

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    fn copy_into(target: &mut [u16], text: &str) {
        let units: Vec<u16> = text.encode_utf16().take(target.len() - 1).collect();
        target[..units.len()].copy_from_slice(&units);
        target[units.len()] = 0;
    }

    fn icon_data(window: HWND) -> NOTIFYICONDATAW {
        // SAFETY: NOTIFYICONDATAW is plain data; zero is a valid starting value for every field.
        let mut data: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        data.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        data.hWnd = window;
        data.uID = 1;
        data
    }

    fn add_icon(tray: &Tray) {
        let mut data = icon_data(tray.window);
        data.uFlags = NIF_ICON | NIF_TIP;
        // SAFETY: the shield is a shared system icon; null module means a predefined icon.
        data.hIcon = unsafe { LoadIconW(std::ptr::null_mut(), IDI_SHIELD) };
        copy_into(&mut data.szTip, &tray.tip);
        // SAFETY: data is fully initialised for NIM_ADD.
        unsafe { Shell_NotifyIconW(NIM_ADD, &data) };
    }

    fn remove_icon(window: HWND) {
        let data = icon_data(window);
        // SAFETY: removing an icon that may not exist is harmless.
        unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
    }

    fn refresh(tray: &mut Tray) {
        let state = read(&tray.board);
        let now = jiff::Timestamp::now();
        let tip = tooltip(&state, now);
        let fresh = notices_to_show(&state, tray.last_shown, now);
        if let Some(last) = state.notices.last() {
            tray.last_shown = Some(tray.last_shown.map_or(last.id, |shown| shown.max(last.id)));
        }
        let mut data = icon_data(tray.window);
        if tip != tray.tip {
            data.uFlags |= NIF_TIP;
            copy_into(&mut data.szTip, &tip);
            tray.tip = tip;
        }
        if let Some(latest) = fresh.last() {
            let text = match fresh.len() {
                1 => latest.text.clone(),
                count => format!("{} (e mais {} aviso(s))", latest.text, count - 1),
            };
            data.uFlags |= NIF_INFO;
            data.dwInfoFlags = NIIF_INFO;
            copy_into(&mut data.szInfoTitle, TITLE);
            copy_into(&mut data.szInfo, &text);
        }
        if data.uFlags != 0 {
            // SAFETY: data names our icon and carries only the flagged fields.
            unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
        }
    }

    unsafe extern "system" fn window_proc(window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        // The lock is released before DefWindowProcW, which may send messages back to this procedure.
        let handled = {
            let mut guard = STATE.lock().unwrap_or_else(|poison| poison.into_inner());
            match (message, guard.as_mut()) {
                (WM_TIMER, Some(tray)) => {
                    refresh(tray);
                    true
                }
                // Explorer restarted: the icon is gone and must be added again.
                (message, Some(tray)) if message == tray.taskbar_created => {
                    add_icon(tray);
                    true
                }
                _ => false,
            }
        };
        match message {
            _ if handled => 0,
            // Sign-out, shutdown or the Restart Manager closing the component for an update.
            WM_QUERYENDSESSION => 1,
            WM_ENDSESSION | WM_CLOSE | WM_DESTROY => {
                remove_icon(window);
                // SAFETY: ends this thread's message loop.
                unsafe { PostQuitMessage(0) };
                0
            }
            // SAFETY: default handling for every other message.
            _ => unsafe { DefWindowProcW(window, message, wparam, lparam) },
        }
    }

    pub fn run(board: PathBuf) {
        let mutex_name = wide("Local\\openems-session");
        let class_name = wide("OpenemsSessionWindow");
        // SAFETY: Win32 calls with NUL-terminated buffers that outlive them; the window lives until the
        // message loop ends, and the process exits right after.
        unsafe {
            let mutex = CreateMutexW(std::ptr::null(), 1, mutex_name.as_ptr());
            if mutex.is_null() || GetLastError() == ERROR_ALREADY_EXISTS {
                return;
            }
            let instance = GetModuleHandleW(std::ptr::null());
            let mut class: WNDCLASSW = std::mem::zeroed();
            class.lpfnWndProc = Some(window_proc);
            class.hInstance = instance;
            class.lpszClassName = class_name.as_ptr();
            RegisterClassW(&class);
            let window = CreateWindowExW(
                0,
                class_name.as_ptr(),
                class_name.as_ptr(),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                instance,
                std::ptr::null(),
            );
            if window.is_null() {
                return;
            }
            let taskbar_created = RegisterWindowMessageW(wide("TaskbarCreated").as_ptr());
            {
                let mut tray = Tray { board, window, last_shown: None, tip: String::new(), taskbar_created };
                tray.tip = tooltip(&read(&tray.board), jiff::Timestamp::now());
                add_icon(&tray);
                refresh(&mut tray);
                *STATE.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(tray);
            }
            SetTimer(window, 1, POLL_MS, None);
            let mut message: MSG = std::mem::zeroed();
            while GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
}
