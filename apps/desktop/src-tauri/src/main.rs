// NÃO COMPILADO. Abre a interface do backend local já em execução.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("erro ao iniciar o Universal Reverse Engine");
}
