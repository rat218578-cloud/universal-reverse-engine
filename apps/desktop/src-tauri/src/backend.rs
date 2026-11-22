//! Gerência do backend Python (`python -m ure.server`) iniciado pelo aplicativo.
//!
//! Responsabilidades: escolher Python e pasta do backend, reservar uma porta livre, gerar um
//! token de sessão novo a cada execução, iniciar o processo, aguardar `/api/v1/health` e
//! encerrar a árvore de processos ao sair. Nada aqui depende de Tauri, para que a lógica
//! possa ser testada com `cargo test` em qualquer plataforma.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

/// Versão mínima do Python, conforme apps/backend/pyproject.toml (requires-python >= 3.11).
const MIN_PYTHON: (u32, u32) = (3, 11);
/// Flag do Windows que impede a abertura de uma janela de console para o processo filho.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Um interpretador Python: programa mais argumentos anteriores ao `-m` (ex.: `py -3`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Python {
    pub program: String,
    pub prefix: Vec<String>,
}

/// Tudo o que o lançador precisa para iniciar o backend.
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    pub python: Python,
    /// Pasta que contém o pacote `ure/` (vira o diretório de trabalho e o sys.path).
    pub backend_root: PathBuf,
    pub data_dir: PathBuf,
    pub port: u16,
    pub token: String,
}

/// Processo do backend em execução.
pub struct Backend {
    child: Child,
    /// Pipe mantido aberto enquanto o aplicativo vive. Quando o aplicativo morre, o sistema
    /// fecha o pipe e o backend encerra sozinho (ver `_watch_parent_pipe` em ure/server.py).
    parent_pipe: Option<ChildStdin>,
    pub port: u16,
    pub log_path: PathBuf,
}

/// Token de sessão: 32 bytes aleatórios em hexadecimal (64 caracteres).
/// Gerado a cada execução do aplicativo e nunca gravado em disco pelo lançador.
pub fn new_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("não foi possível gerar o token: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Porta TCP livre no loopback. Há uma pequena janela entre liberar e o backend abri-la;
/// se a porta for tomada nesse intervalo, o backend termina e o erro é exibido.
pub fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("sem porta livre: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    drop(listener);
    Ok(port)
}

/// Verifica se a resposta HTTP é de sucesso (status 200). Não aceita outros códigos.
pub fn is_healthy_response(raw: &[u8]) -> bool {
    let head = &raw[..raw.len().min(64)];
    head.starts_with(b"HTTP/1.1 200") || head.starts_with(b"HTTP/1.0 200")
}

/// URL local do backend. Sempre loopback: o backend nunca escuta em outra interface aqui.
pub fn base_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

/// Regra de navegação da janela: só a própria origem do backend (e about:blank).
pub fn navigation_allowed(url: &str, port: u16) -> bool {
    if url == "about:blank" {
        return true;
    }
    let prefix = format!("{}/", base_url(port));
    url == base_url(port) || url.starts_with(&prefix)
}

/// Script injetado somente no quadro principal da janela do backend. Contém apenas o token,
/// que é hexadecimal por construção; a validação abaixo garante que não há caracteres especiais.
pub fn injection_script(token: &str) -> Result<String, String> {
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("token com formato inesperado".into());
    }
    Ok(format!("window.URE_DESKTOP = {{ token: \"{token}\" }};"))
}

/// Escolhe o Python: `URE_PYTHON`, depois o Python empacotado, depois o do sistema.
/// `candidate_ok` testa um candidato (em produção, executa a versão e compara).
pub fn choose_python(
    override_program: Option<String>,
    bundled: Option<PathBuf>,
    candidate_ok: impl Fn(&Python) -> bool,
) -> Result<Python, String> {
    if let Some(program) = override_program.filter(|p| !p.trim().is_empty()) {
        let py = Python { program, prefix: vec![] };
        return if candidate_ok(&py) { Ok(py) } else { Err(format!("URE_PYTHON não aponta para Python >= {}.{}", MIN_PYTHON.0, MIN_PYTHON.1)) };
    }
    if let Some(path) = bundled.filter(|p| p.is_file()) {
        let py = Python { program: path.to_string_lossy().into_owned(), prefix: vec![] };
        if candidate_ok(&py) {
            return Ok(py);
        }
    }
    for py in system_candidates() {
        if candidate_ok(&py) {
            return Ok(py);
        }
    }
    Err(format!(
        "Python {}.{} ou superior não foi encontrado. Instale o Python ou defina URE_PYTHON.",
        MIN_PYTHON.0, MIN_PYTHON.1
    ))
}

fn system_candidates() -> Vec<Python> {
    let mut list = vec![
        Python { program: "python3".into(), prefix: vec![] },
        Python { program: "python".into(), prefix: vec![] },
    ];
    if cfg!(windows) {
        list.push(Python { program: "py".into(), prefix: vec!["-3".into()] });
    }
    list
}

/// Executa `python -c "<teste de versão>"` e confirma >= 3.11.
pub fn python_is_supported(py: &Python) -> bool {
    let script = format!(
        "import sys; sys.exit(0 if sys.version_info >= ({}, {}) else 1)",
        MIN_PYTHON.0, MIN_PYTHON.1
    );
    let mut cmd = Command::new(&py.program);
    cmd.args(&py.prefix).arg("-c").arg(script).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.status().map(|s| s.success()).unwrap_or(false)
}

impl Backend {
    /// Inicia o processo do backend. Variáveis `URE_*` herdadas do ambiente do usuário são
    /// removidas antes: só valem as definidas aqui.
    pub fn spawn(spec: &LaunchSpec) -> Result<Backend, String> {
        let logs = spec.data_dir.join("logs");
        fs::create_dir_all(&logs).map_err(|e| format!("não foi possível criar {}: {e}", logs.display()))?;
        let log_path = logs.join("backend.log");
        let log = open_log(&log_path)?;
        let log_err = log.try_clone().map_err(|e| e.to_string())?;

        let mut cmd = Command::new(&spec.python.program);
        cmd.args(&spec.python.prefix)
            .arg("-m")
            .arg("ure.server")
            .current_dir(&spec.backend_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("URE_") {
                cmd.env_remove(key);
            }
        }
        cmd.env("URE_HOST", "127.0.0.1")
            .env("URE_PORT", spec.port.to_string())
            .env("URE_TOKEN", &spec.token)
            .env("URE_DATA_DIR", &spec.data_dir)
            // Arquivo de configuração opcional do usuário fica ao lado dos dados, não no cwd.
            .env("URE_CONFIG", spec.data_dir.join("ure.env"))
            .env("URE_PARENT_WATCH", "1")
            .env("PYTHONUNBUFFERED", "1")
            .env("PYTHONIOENCODING", "utf-8");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = cmd.spawn().map_err(|e| format!("não foi possível iniciar o backend: {e}"))?;
        let parent_pipe = child.stdin.take();
        Ok(Backend { child, parent_pipe, port: spec.port, log_path })
    }

    /// Aguarda `/api/v1/health` responder 200. Falha se o processo terminar antes ou se o prazo
    /// expirar. Em caso de erro, o caminho do log é incluído na mensagem.
    pub fn wait_healthy(&mut self, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().map_err(|e| e.to_string())? {
                return Err(format!("o backend encerrou ({status}). Veja {}", self.log_path.display()));
            }
            if probe_health(self.port) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("o backend não respondeu em {} s. Veja {}", timeout.as_secs(), self.log_path.display()));
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    }

    /// Encerra o backend e seus filhos. Idempotente.
    pub fn stop(&mut self) {
        // Fechar o pipe já pede o encerramento ao backend; o kill abaixo garante o fim.
        drop(self.parent_pipe.take());
        if let Ok(None) = self.child.try_wait() {
            #[cfg(windows)]
            {
                // taskkill /T derruba a árvore: ferramentas como apktool.bat iniciam um java filho.
                use std::os::windows::process::CommandExt;
                let pid = self.child.id().to_string();
                let _ = Command::new("taskkill")
                    .args(["/PID", pid.as_str(), "/T", "/F"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .creation_flags(CREATE_NO_WINDOW)
                    .status();
            }
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.stop();
    }
}

fn open_log(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("não foi possível abrir o log {}: {e}", path.display()))
}

fn probe_health(port: u16) -> bool {
    let addr: SocketAddr = match format!("127.0.0.1:{port}").parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1000)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(1000)));
    let request = format!("GET /api/v1/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    // Lê a resposta até o fim (Connection: close). Fechar cedo faria o servidor escrever
    // num socket já fechado e registrar um ConnectionResetError no log.
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 256];
    while buf.len() < 4096 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    is_healthy_response(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_64_hex_chars_and_unique() {
        let a = new_token().unwrap();
        let b = new_token().unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn health_accepts_only_200() {
        assert!(is_healthy_response(b"HTTP/1.1 200 OK\r\n\r\n{}"));
        assert!(is_healthy_response(b"HTTP/1.0 200 OK\r\n"));
        assert!(!is_healthy_response(b"HTTP/1.1 401 Unauthorized\r\n"));
        assert!(!is_healthy_response(b"HTTP/1.1 500 Internal\r\n"));
        assert!(!is_healthy_response(b""));
        assert!(!is_healthy_response(b"garbage"));
    }

    #[test]
    fn navigation_is_restricted_to_backend_origin() {
        assert!(navigation_allowed("http://127.0.0.1:8765/", 8765));
        assert!(navigation_allowed("http://127.0.0.1:8765/#/p/abc", 8765));
        assert!(navigation_allowed("about:blank", 8765));
        assert!(!navigation_allowed("http://127.0.0.1:9999/", 8765));
        assert!(!navigation_allowed("https://accounts.google.com/", 8765));
        assert!(!navigation_allowed("http://127.0.0.1.evil.example/", 8765));
        assert!(!navigation_allowed("http://localhost:8765/", 8765));
        assert!(!navigation_allowed("file:///etc/passwd", 8765));
    }

    #[test]
    fn injection_script_only_accepts_hex_tokens() {
        let token = "ab".repeat(32);
        let script = injection_script(&token).unwrap();
        assert!(script.contains(&token));
        assert!(injection_script("x\"; alert(1); \"").is_err());
        assert!(injection_script("abc").is_err());
    }

    #[test]
    fn free_port_is_nonzero() {
        assert!(free_port().unwrap() > 0);
    }

    #[test]
    fn python_override_wins_when_supported() {
        let chosen = choose_python(Some("/opt/py".into()), None, |_| true).unwrap();
        assert_eq!(chosen.program, "/opt/py");
    }

    #[test]
    fn unsupported_override_is_an_error_not_a_fallback() {
        let err = choose_python(Some("/opt/py2".into()), None, |_| false).unwrap_err();
        assert!(err.contains("URE_PYTHON"));
    }

    #[test]
    fn bundled_python_is_preferred_over_system() {
        let dir = std::env::temp_dir().join(format!("ure-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let bundled = dir.join("python.exe");
        File::create(&bundled).unwrap();
        let chosen = choose_python(None, Some(bundled.clone()), |_| true).unwrap();
        assert_eq!(chosen.program, bundled.to_string_lossy());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_python_reports_how_to_fix() {
        let err = choose_python(None, None, |_| false).unwrap_err();
        assert!(err.contains("URE_PYTHON"));
    }
}
