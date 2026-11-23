// Ponto de entrada do aplicativo desktop (Windows). No Android o entrypoint é `run` em lib.rs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    ure_desktop_lib::run()
}
