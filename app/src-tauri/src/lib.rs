// app/src-tauri/src/lib.rs
//
// supervises the c++ engine sidecar and tells the web ui where to reach it
// the engine is a separate process because the c++ tree links the static crt
// and rust links the dynamic one, loopback costs a json round trip and buys
// crash isolation

use serde::Serialize;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Condvar, Mutex};
use std::time::Duration;
use tauri::{Manager, State};

#[derive(Clone, Debug, Default, Serialize)]
pub struct Endpoint {
    pub port: u16,
    pub token: String,
}

#[derive(Default)]
struct Inner {
    endpoint: Option<Endpoint>,
    failure: Option<String>,
}

#[derive(Default)]
pub struct Engine {
    inner: Mutex<Inner>,
    ready: Condvar,
    child: Mutex<Option<Child>>,
}

impl Engine {
    fn publish(&self, endpoint: Endpoint) {
        let mut inner = self.inner.lock().expect("engine state poisoned");
        inner.endpoint = Some(endpoint);
        inner.failure = None;
        drop(inner);
        self.ready.notify_all();
    }

    fn fail(&self, reason: impl Into<String>) {
        let mut inner = self.inner.lock().expect("engine state poisoned");
        if inner.endpoint.is_none() {
            inner.failure = Some(reason.into());
        }
        drop(inner);
        self.ready.notify_all();
    }

    /// waits for the handshake, the timeout is long because a human might be
    /// clicking through the mapper's uac prompt
    fn wait(&self, timeout: Duration) -> Result<Endpoint, String> {
        let mut inner = self.inner.lock().expect("engine state poisoned");
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(ep) = inner.endpoint.clone() {
                return Ok(ep);
            }
            if let Some(err) = inner.failure.clone() {
                return Err(err);
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err("engine did not report a listening port in time".into());
            }
            let (guard, _) = self
                .ready
                .wait_timeout(inner, remaining)
                .expect("engine state poisoned");
            inner = guard;
        }
    }
}

#[tauri::command]
fn engine_endpoint(engine: State<'_, Engine>) -> Result<Endpoint, String> {
    engine.wait(Duration::from_secs(180))
}

/// where the engine binary lives, next to us once installed, the cmake tree
/// during development
/// debug builds check the cmake tree first on purpose, tauri copies the
/// resource engine at cargo build time and a stale copy cost an afternoon
/// of debugging once
fn sidecar_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    const NAME: &str = "reverse-slop-engine.exe";

    let dev_tree = || -> Option<PathBuf> {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../build/src/engine")
            .join(NAME);
        p.is_file().then(|| p.canonicalize().unwrap_or(p))
    };

    let installed = |app: &tauri::AppHandle| -> Option<PathBuf> {
        if let Ok(dir) = app.path().resource_dir() {
            let bundled = dir.join("engine").join(NAME);
            if bundled.is_file() {
                return Some(bundled);
            }
        }
        let exe = std::env::current_exe().ok()?;
        let dir = exe.parent()?;
        [dir.join(NAME), dir.join("engine").join(NAME)]
            .into_iter()
            .find(|c| c.is_file())
    };

    let found = if cfg!(debug_assertions) {
        dev_tree().or_else(|| installed(app))
    } else {
        installed(app).or_else(dev_tree)
    };

    found.ok_or_else(|| {
        format!("{NAME} not found, build it with tools/build.ps1 (SLOP_BUILD_ENGINE=ON)")
    })
}

/// kill on close job object, the engine usually exits cleanly through
/// parent-pid and this is the backstop for a wedged one
#[cfg(windows)]
mod job {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
        JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    /// Leaked deliberately: the handle must outlive every scope in this process,
    /// because closing it is exactly what kills the engine
    pub fn adopt(child: &std::process::Child) -> Result<(), String> {
        unsafe {
            let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if handle.is_null() {
                return Err("CreateJobObject failed".into());
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                return Err("SetInformationJobObject failed".into());
            }
            if AssignProcessToJobObject(handle, child.as_raw_handle() as HANDLE) == 0 {
                return Err("AssignProcessToJobObject failed".into());
            }
        }
        Ok(())
    }
}

fn spawn_engine(app: &tauri::AppHandle) -> Result<(), String> {
    let path = sidecar_path(app)?;
    let mut cmd = Command::new(&path);
    cmd.arg("--headless")
        .arg("--parent-pid")
        .arg(std::process::id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // The engine is a console subsystem binary; without this a black console
    // flashes up beside the window on every launch
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to start {}: {e}", path.display()))?;

    #[cfg(windows)]
    if let Err(e) = job::adopt(&child) {
        eprintln!("engine job object unavailable ({e}); relying on parent watch");
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "engine stdout unavailable".to_string())?;
    let stderr = child.stderr.take();

    let engine_handle = app.clone();
    std::thread::spawn(move || {
        let engine = engine_handle.state::<Engine>();
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let mut parts = line.split_whitespace();
            match parts.next() {
                Some("SLOP_ENGINE_READY") => {
                    let port = parts.next().and_then(|p| p.parse::<u16>().ok());
                    let token = parts.next().unwrap_or("").to_string();
                    match port {
                        Some(port) if port != 0 => engine.publish(Endpoint { port, token }),
                        _ => engine.fail(format!("malformed handshake: {line}")),
                    }
                }
                Some("SLOP_ENGINE_FAILED") => {
                    engine.fail(line.trim_start_matches("SLOP_ENGINE_FAILED").trim())
                }
                _ => eprintln!("engine: {line}"),
            }
        }
        // stdout closed: the engine is gone. If it never announced a port, stop
        // the UI waiting on a handshake that will not arrive
        engine.fail("engine exited before reporting a port");
    });

    if let Some(stderr) = stderr {
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("engine: {line}");
            }
        });
    }

    app.state::<Engine>()
        .child
        .lock()
        .expect("engine child poisoned")
        .replace(child);
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Engine::default())
        .invoke_handler(tauri::generate_handler![engine_endpoint])
        .setup(|app| {
            if let Err(e) = spawn_engine(app.handle()) {
                // Surface it through the same channel a late handshake uses, so
                // the UI shows one "engine unavailable" state either way
                app.state::<Engine>().fail(e.clone());
                eprintln!("engine spawn failed: {e}");
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                // the engine sees our exit through parent-pid and runs its own teardown,
                // give it a moment before the job object forces the issue
                let engine = window.state::<Engine>();
                let mut child = engine.child.lock().expect("engine child poisoned");
                if let Some(proc) = child.as_mut() {
                    for _ in 0..40 {
                        match proc.try_wait() {
                            Ok(Some(_)) => break,
                            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                            Err(_) => break,
                        }
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running reverse-slop UI");
}




