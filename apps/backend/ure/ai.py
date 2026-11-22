"""Roteador de IA opcional. Desligado por padrão (URE_AI_ENABLED=1 para ligar).

Implementado: provedor local Ollama (HTTP em loopback). Provedores externos são reconhecidos,
exigem consentimento explícito e retornam 501 porque nenhum adaptador externo foi implementado
nesta versão. O contexto enviado nunca inclui valores de segredos, apenas contagens por regra.
"""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .config import Settings
from .db import Store

LOCAL_PROVIDERS = frozenset({"ollama"})
EXTERNAL_PROVIDERS = frozenset({"openai", "anthropic"})
EVIDENCE_IDS = ("E1", "E2", "E3", "E4")
MAX_QUESTION = 2000


class AIError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def build_context(report: dict[str, Any]) -> str:
    """Contexto com evidências numeradas. Nenhum valor de segredo é incluído."""
    findings = report.get("secrets", {}).get("findings", [])
    by_rule = dict(Counter(f["rule"] for f in findings))
    engines = {k: v.get("status") for k, v in report.get("engines", {}).items()}
    lines = [
        f"[E1] Dependências: {json.dumps(report.get('dependencies', {}), ensure_ascii=False)[:4000]}",
        f"[E2] Indicadores estáticos: {json.dumps(report.get('indicators', []), ensure_ascii=False)[:2000]}",
        f"[E3] Motores externos (status): {json.dumps(engines, ensure_ascii=False)}",
        f"[E4] Segredos encontrados por regra (valores omitidos): {json.dumps(by_rule, ensure_ascii=False)}",
    ]
    header = f"Arquivo: {report.get('filename')} ({report.get('kind')}), integridade: {report.get('integrity')}"
    return header + "\n" + "\n".join(lines)


class AIRouter:
    def __init__(self, settings: Settings, store: Store) -> None:
        self.settings = settings
        self.store = store

    def _get_json(self, path: str, timeout: float = 3.0) -> dict[str, Any]:
        url = self.settings.ollama_url.rstrip("/") + path
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return json.loads(r.read(4 * 1024 * 1024))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise AIError(503, "Ollama indisponível em loopback; a IA é opcional e o modo básico segue funcionando") from exc

    def _post_json(self, path: str, body: dict[str, Any], timeout: float = 180.0) -> dict[str, Any]:
        url = self.settings.ollama_url.rstrip("/") + path
        req = urllib.request.Request(
            url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read(8 * 1024 * 1024))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise AIError(503, "falha ao consultar o Ollama local") from exc

    def _model_version(self, model: str) -> str:
        tags = self._get_json("/api/tags").get("models", [])
        wanted = {model, model if ":" in model else f"{model}:latest"}
        for item in tags:
            if item.get("name") in wanted or item.get("model") in wanted:
                return str(item.get("digest") or item.get("modified_at") or "desconhecida")
        raise AIError(503, f"modelo '{model}' não instalado no Ollama local")

    def status(self) -> dict[str, Any]:
        info: dict[str, Any] = {
            "enabled": self.settings.ai_enabled,
            "local_provider": "ollama",
            "external_providers": sorted(EXTERNAL_PROVIDERS),
            "external_implemented": False,
            "daily_budget": self.settings.ai_daily_budget,
            "calls_today": self.store.ai_calls_today(_today()),
            "ollama_reachable": False,
            "models": [],
        }
        if self.settings.ai_enabled:
            try:
                info["models"] = [m.get("name") for m in self._get_json("/api/tags").get("models", [])]
                info["ollama_reachable"] = True
            except AIError:
                pass
        return info

    def ask(self, question: str, report: dict[str, Any], *, provider: str, model: str | None,
            consent: bool) -> dict[str, Any]:
        if not self.settings.ai_enabled:
            raise AIError(503, "IA desativada; defina URE_AI_ENABLED=1 para habilitar o provedor local")
        if provider in EXTERNAL_PROVIDERS:
            if not consent:
                raise AIError(403, "envio a serviço externo exige consentimento explícito (consent=true)")
            raise AIError(501, "provedor externo não implementado nesta versão; use o provedor local ollama")
        if provider not in LOCAL_PROVIDERS:
            raise AIError(400, "provedor desconhecido")
        question = question.strip()
        if not 1 <= len(question) <= MAX_QUESTION:
            raise AIError(400, f"pergunta deve ter de 1 a {MAX_QUESTION} caracteres")
        model = model or self.settings.ollama_model
        version = self._model_version(model)
        context = build_context(report)
        key = hashlib.sha256(f"{model}|{version}|{question}|{context}".encode("utf-8")).hexdigest()
        cached = self.store.cache_get(key)
        if cached:
            return {"answer": json.loads(cached["response"]), "cached": True}
        day = _today()
        if self.store.ai_calls_today(day) >= self.settings.ai_daily_budget:
            raise AIError(429, "orçamento diário de chamadas de IA esgotado")
        prompt = (
            "Você responde somente com base nas evidências abaixo. Cite as evidências pelo identificador "
            "entre colchetes (ex.: [E1]). Se a evidência não bastar, diga que não há informação suficiente. "
            "Não afirme que o arquivo é malicioso sem evidência explícita.\n\n"
            f"{context}\n\nPergunta: {question}"
        )
        resp = self._post_json("/api/generate", {"model": model, "prompt": prompt, "stream": False})
        answer = {
            "text": str(resp.get("response", "")),
            "model": model,
            "model_version": version,
            "evidence": list(EVIDENCE_IDS),
        }
        self.store.ai_increment(day)
        self.store.cache_put(key, model, json.dumps(answer, ensure_ascii=False))
        return {"answer": answer, "cached": False}


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")
