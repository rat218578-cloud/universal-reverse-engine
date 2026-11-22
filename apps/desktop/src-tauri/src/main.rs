// Aplicativo desktop do Universal Reverse Engine (Tauri 2).
//
// Fluxo: o lançador inicia o backend Python local, aguarda /api/v1/health responder 200 e só
// então abre a janela apontando para o próprio backend (mesma origem da versão web).
// Ao sair, o backend é encerrado. O token é gerado a cada execução e entregue ao backend
// por variável de ambiente; a janela o recebe por um script injetado somente nessa origem.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod backend;

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use tauri::{AppHandle, Manager, RunEvent, Url, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_dialog::{DialogExt, MessageDialogKind};

const APP_TITLE: &str = "Universal Reverse Engine";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(40);

/// Processo do backend em execução, guardado para ser encerrado na saída do aplicativo.
#[derive(Default)]
struct Running(Mutex<Option<backend::Backend>>);

fn main() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Running::default())
        .setup(|app| {
            let handle = app.handle().clone();
            // Inicialização em segundo plano: a janela só é criada após a saúde do backend.
            std::thread::spawn(move || start(handle));
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("erro ao construir o Universal Reverse Engine");

    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            if let Some(state) = handle.try_state::<Running>() {
                if let Ok(mut slot) = state.0.lock() {
                    if let Some(mut running) = slot.take() {
                        running.stop();
                    }
                }
            }
        }
    });
}

fn start(handle: AppHandle) {
    match launch(&handle) {
        Ok((port, token)) => {
            let outcome = backend::injection_script(&token).and_then(|script| {
                let main_handle = handle.clone();
                handle
                    .run_on_main_thread(move || {
                        if let Err(message) = open_window(&main_handle, port, script) {
                            fail(&main_handle, message);
                        }
                    })
                    .map_err(|e| e.to_string())
            });
            if let Err(message) = outcome {
                fail(&handle, message);
            }
        }
        Err(message) => fail(&handle, message),
    }
}

/// Mostra o erro em caixa de diálogo nativa e encerra. Em Windows o app não tem console,
/// então esta é a única forma de o usuário ver o motivo.
fn fail(handle: &AppHandle, message: String) {
    let handle = handle.clone();
    std::thread::spawn(move || {
        handle
            .dialog()
            .message(message)
            .title(APP_TITLE)
            .kind(MessageDialogKind::Error)
            .blocking_show();
        handle.exit(1);
    });
}

/// Inicia o backend e aguarda a verificação de saúde. Devolve a porta e o token da sessão.
fn launch(handle: &AppHandle) -> Result<(u16, String), String> {
    let app_data = handle.path().app_data_dir().map_err(|e| format!("pasta de dados indisponível: {e}"))?;
    let resource_dir = handle.path().resource_dir().ok();
    let backend_root = find_backend_root(resource_dir.as_deref())?;
    let bundled_python = resource_dir.as_deref().map(|r| {
        if cfg!(windows) {
            r.join("python").join("python.exe")
        } else {
            r.join("python").join("bin").join("python3")
        }
    });
    let python = backend::choose_python(std::env::var("URE_PYTHON").ok(), bundled_python, backend::python_is_supported)?;

    let port = backend::free_port()?;
    let token = backend::new_token()?;
    let spec = backend::LaunchSpec {
        python,
        backend_root,
        data_dir: app_data.join("data"),
        port,
        token: token.clone(),
    };

    let mut running = backend::Backend::spawn(&spec)?;
    running.wait_healthy(STARTUP_TIMEOUT)?;

    let state = handle.state::<Running>();
    let mut slot = state.0.lock().map_err(|_| "estado interno do aplicativo corrompido".to_string())?;
    *slot = Some(running);
    Ok((port, token))
}

/// Pasta que contém o pacote `ure/`: variável URE_BACKEND_ROOT, depois os recursos do
/// instalador, depois o repositório (execução a partir do código-fonte).
fn find_backend_root(resource_dir: Option<&Path>) -> Result<PathBuf, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(path) = std::env::var("URE_BACKEND_ROOT") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(resources) = resource_dir {
        candidates.push(resources.join("backend"));
    }
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("backend"));
    candidates
        .into_iter()
        .find(|root| root.join("ure").join("__init__.py").is_file())
        .ok_or_else(|| "o pacote do backend (ure) não foi encontrado".to_string())
}

fn open_window(handle: &AppHandle, port: u16, script: String) -> Result<(), String> {
    let url: Url = backend::base_url(port).parse().map_err(|e| format!("URL do backend inválida: {e}"))?;
    WebviewWindowBuilder::new(handle, "main", WebviewUrl::External(url))
        .title(APP_TITLE)
        .inner_size(1280.0, 820.0)
        .min_inner_size(960.0, 600.0)
        // Script só no quadro principal, e só para a origem do backend (ver on_navigation).
        .initialization_script(script)
        .on_navigation(move |target: &Url| backend::navigation_allowed(target.as_str(), port))
        .build()
        .map_err(|e| format!("não foi possível abrir a janela: {e}"))?;
    Ok(())
}
