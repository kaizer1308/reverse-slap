fn main() {
    // Release ships requireAdministrator, matching the ImGui shell's
    // src/app/app.manifest — the kernel bridge maps slopdrvr, and the engine
    // sidecar (asInvoker) inherits the elevated token so only one UAC prompt
    // appears for the whole app.
    //
    // Debug builds are asInvoker instead. An elevated exe cannot be launched by
    // an ordinary terminal, so requiring it here would mean `tauri dev` only
    // works from an elevated shell — and front-end work does not need the
    // driver: an unelevated engine just reports the user-mode backend.
    #[cfg(windows)]
    {
        let dev = std::env::var("PROFILE").is_ok_and(|p| p == "debug");
        let manifest = if dev {
            include_str!("app.dev.manifest")
        } else {
            include_str!("app.manifest")
        };
        let attrs = tauri_build::WindowsAttributes::new().app_manifest(manifest);
        tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(attrs))
            .expect("failed to run tauri-build");
    }
    #[cfg(not(windows))]
    tauri_build::build();
}
