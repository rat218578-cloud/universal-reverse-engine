// Universal Reverse Engine — ponto de entrada compartilhado (Tauri 2).
//
// Desktop (Windows): o módulo `desktop` inicia o backend Python como processo filho, aguarda a
// saúde e abre a janela na origem do backend. Ver `desktop.rs`.
//
// Android: o backend roda dentro do próprio processo do app (Chaquopy, ver
// apps/desktop/android). Este crate não inicia processo nenhum; a atividade Android carrega a
// janela. Por isso o módulo desktop não é compilado para mobile.
#[cfg(desktop)]
mod backend;
#[cfg(desktop)]
mod desktop;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default().plugin(tauri_plugin_dialog::init());
    #[cfg(desktop)]
    let builder = builder
        .manage(desktop::Running::default())
        .setup(|app| {
            desktop::setup(app.handle().clone());
            Ok(())
        });
    let app = builder
        .build(tauri::generate_context!())
        .expect("erro ao construir o Universal Reverse Engine");

    app.run(|handle, event| {
        #[cfg(desktop)]
        desktop::on_event(handle, &event);
        #[cfg(not(desktop))]
        let _ = (handle, event);
    });
}
