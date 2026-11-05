#!/usr/bin/env python3
"""Launcher 0.35.11: реальные замеры производительности процессов и сети.

Каждая нативная проверка запускает предоставленный скомпилированный Launcher. Имитировать
длительность нативных команд запрещено. Фикстуры синтетические и явно обозначены; для замеров
настоящего дистрибутива Minecraft дополнительно нужны предоставленные подписанный манифест и
установленные файлы.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
from threading import Event, Lock, Thread
import time
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

try:
    import psutil
except ImportError:  # явная ошибка измерения процесса, а не вымышленные нулевые значения
    psutil = None

MIB = 1024 * 1024
SEED = "42" * 32  # начальное значение подписи только для тестового набора, никогда не рабочий ключ подписи


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        raise ValueError("Нельзя составить отчёт по пустым измерениям")
    a = sorted(values)
    rank = (len(a) - 1) * fraction
    lo = math.floor(rank)
    hi = math.ceil(rank)
    return a[lo] + (a[hi] - a[lo]) * (rank - lo)


def describe(values: list[float]) -> dict:
    return {
        "count": len(values),
        "median": statistics.median(values),
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "min": min(values),
        "max": max(values),
    }


def hash_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(MIB), b""):
            hasher.update(block)
    return hasher.hexdigest()


def binary(path: Path, name: str) -> dict:
    path = path.resolve()
    if not path.is_file():
        raise ValueError(f"Исполняемый файл {name} не найден: {path}")
    if os.name != "nt" and not os.access(path, os.X_OK):
        raise ValueError(f"{name}: файл не является исполняемым: {path}")
    return {
        "path": str(path),
        "sha256": hash_file(path),
        "sizeBytes": path.stat().st_size,
    }


def metadata() -> dict:
    repository = Path(__file__).resolve().parents[2]
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        capture_output=True,
        text=True,
        timeout=10,
    )
    clean = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repository,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return {
        "productVersion": (repository / "VERSION").read_text().strip(),
        "commit": revision.stdout.strip() if revision.returncode == 0 else None,
        "gitTreeClean": clean.returncode == 0 and not clean.stdout.strip()
        if revision.returncode == 0
        else None,
        "timestampUtc": datetime.now(timezone.utc).isoformat(),
        "os": platform.platform(),
        "python": platform.python_version(),
        "cpuLogical": os.cpu_count(),
        "cpuModel": platform.processor() or None,
        "totalMemoryBytes": psutil.virtual_memory().total if psutil else None,
        "psutil": psutil.__version__ if psutil else None,
        "fixtureType": "synthetic signed certification manifest; real native binary and actual bytes",
        "disclaimer": "Нет сравнительного теста с другим лаунчером, подтверждения реального запуска Minecraft или заявлений о производительности рабочей среды",
    }


class ProcessMonitor:
    """Измерять фактическую загрузку CPU и RSS дерева процессов; без psutil завершаться с ошибкой."""

    def __init__(self, pid: int):
        if psutil is None:
            raise RuntimeError(
                "Для измерений процессора и памяти требуется psutil: pip install psutil==7.2.2"
            )
        self.parent = psutil.Process(pid)
        self.stop = Event()
        self.samples: list[dict] = []
        self.thread = Thread(target=self._run, daemon=True)

    def _run(self):
        while not self.stop.is_set():
            try:
                procs = [self.parent, *self.parent.children(recursive=True)]
                rss = 0
                cpu_seconds = 0.0
                for proc in procs:
                    try:
                        with proc.oneshot():
                            rss += proc.memory_info().rss
                            cpu = proc.cpu_times()
                            cpu_seconds += cpu.user + cpu.system
                    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                        continue
                self.samples.append({"rssBytes": rss, "cpuSeconds": cpu_seconds})
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                break
            self.stop.wait(0.05)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(timeout=3)

    def report(self) -> dict:
        if not self.samples:
            raise RuntimeError("Процесс завершился до измерения нагрузки CPU и RAM")
        cpu = [x["cpuSeconds"] for x in self.samples]
        delta = max(cpu) - min(cpu)
        # Процент загрузки CPU измеряется в единицах одного логического процессора
        # (100% на ядро). Многопоточный процесс может закономерно превышать 100%.
        return {
            "peakRssBytes": max(x["rssBytes"] for x in self.samples),
            "sampledCpuSeconds": delta,
            "sampleCount": len(self.samples),
            "samplingIntervalMs": 50,
        }


def run_native(
    cmd: list[str], *, env: dict | None = None, timeout: int = 1800
) -> tuple[dict, dict]:
    with (
        tempfile.TemporaryFile(mode="w+t", encoding="utf8") as stdout,
        tempfile.TemporaryFile(mode="w+t", encoding="utf8") as stderr,
    ):
        start = time.perf_counter_ns()
        proc = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, env=env)
        with ProcessMonitor(proc.pid) as monitor:
            try:
                code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                raise RuntimeError(f"Нативная команда превысила лимит времени {timeout} с")
        elapsed = time.perf_counter_ns() - start
        stdout.seek(0)
        stderr.seek(0)
        if code:
            raise RuntimeError(f"Нативная команда завершилась с кодом {code}: {stderr.read()[-1800:]}")
        try:
            result = json.load(stdout)
        except (ValueError, TypeError) as exc:
            raise RuntimeError("Нативный процесс не вернул результат JSON") from exc
        resources = monitor.report()
        resources["cpuCorePercentOfWallTime"] = (
            100 * resources["sampledCpuSeconds"] / (elapsed / 1e9)
        )
        return {"elapsedMs": elapsed / 1e6, **resources}, result


def isolated_env(home: Path) -> dict:
    env = os.environ.copy()
    home.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        env["LOCALAPPDATA"] = str(home)
    elif sys.platform == "darwin":
        env["HOME"] = str(home)
    else:
        env["XDG_CACHE_HOME"] = str(home)
    return env


def signed_manifest(signer: Path, folder: Path, manifest: dict) -> tuple[Path, str]:
    unsigned = folder / "unsigned.json"
    signed = folder / "signed.json"
    unsigned.write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf8")
    env = os.environ.copy()
    env["LAUNCHER_CERT_TEST_SEED"] = SEED
    result = subprocess.run(
        [str(signer), str(unsigned), str(signed)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    key = result.stdout.strip()
    if (
        result.returncode
        or len(key) != 64
        or not all(c in "0123456789abcdefABCDEF" for c in key)
    ):
        raise RuntimeError(
            "Реальный подписывающий модуль тестовой сертификации отклонил манифест: "
            + result.stderr[-1000:]
        )
    return signed, key


def manifest_base(files: list[dict], version: str = "0.35.11") -> dict:
    return {
        "schemaVersion": "1.0",
        "projectId": "certification",
        "profileId": "benchmark",
        "channel": "stable",
        "version": version,
        "createdAt": "2026-10-20T00:00:00Z",
        "minecraft": {"version": "1.21.1", "loader": "vanilla"},
        "runtime": {"java": {"majorVersion": 21, "distribution": "temurin"}},
        "files": files,
    }


def file_entry(path: str, size: int, digest: str, url: str) -> dict:
    return {
        "path": path,
        "size": size,
        "sha256": digest,
        "url": url,
        "mirrors": [],
        "required": True,
        "executable": False,
        "ownership": "managed",
    }


def verify_10k(
    runtime: Path,
    signer: Path,
    work: Path,
    *,
    count: int = 10_000,
    repetitions: int = 3,
) -> dict:
    if count < 1 or count > 100_000 or repetitions < 1:
        raise ValueError("count and repetitions: требуется «positive»")
    root = work / "files"
    (root / "libraries/benchmark").mkdir(parents=True, exist_ok=True)
    entries = []
    for n in range(count):
        relative = f"libraries/benchmark/{n:05d}.jar"
        path = root / relative
        # По 4 КиБ детерминированных тестовых данных, выглядящих несжимаемыми, на
        # файл.
        block = hashlib.shake_256(f"launcher-bench-{n}".encode()).digest(4096)
        path.write_bytes(block)
        entries.append(
            file_entry(
                relative,
                len(block),
                hashlib.sha256(block).hexdigest(),
                "https://example.invalid/benchmark",
            )
        )
    manifest, key = signed_manifest(signer, work, manifest_base(entries))
    rows = []
    for index in range(repetitions):
        observed, data = run_native(
            [
                str(runtime),
                "verify",
                "--manifest",
                str(manifest),
                "--root",
                str(root),
                "--pinned-public-key",
                key,
            ],
            timeout=1800,
        )
        statuses = data.get("files", [])
        if (
            data.get("status") != "ready"
            or len(statuses) != count
            or any(x.get("status") != "ok" for x in statuses)
        ):
            raise RuntimeError(
                "Нативный проверяющий модуль подтвердил не все файлы измерения производительности"
            )
        rows.append({"run": index + 1, **observed})
    return {
        "fileCount": count,
        "bytesVerifiedPerRun": count * 4096,
        "repetitions": repetitions,
        "elapsedMs": describe([r["elapsedMs"] for r in rows]),
        "runs": rows,
        "engine": "runtime verify; SHA-256 and signed manifest",
    }


class RepeatingRangeServer:
    """Настоящая передача HTTP Range/200 через localhost; ограниченная память и проверенные полученные байты."""

    def __init__(self, block: bytes, size: int):
        if not block or size < 1:
            raise ValueError("Некорректное значение: «HTTP benchmark payload»")
        self.block, self.size = block, size
        self.transferred = 0
        self.requests: list[dict] = []
        self.lock = Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_GET(self):
                if urlsplit(self.path).path != "/benchmark.bin":
                    self.send_error(404)
                    return
                start = 0
                rng = self.headers.get("Range", "")
                if rng:
                    if not rng.startswith("bytes=") or not rng.endswith("-"):
                        self.send_error(416)
                        return
                    try:
                        start = int(rng[6:-1])
                    except ValueError:
                        self.send_error(416)
                        return
                    if start >= outer.size or start < 0:
                        self.send_response(416)
                        self.send_header("Content-Range", f"bytes */{outer.size}")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                code = 206 if start else 200
                self.send_response(code)
                self.send_header("Content-Length", str(outer.size - start))
                self.send_header("ETag", '"launcher-bench-fixture"')
                self.send_header("Accept-Ranges", "bytes")
                if code == 206:
                    self.send_header(
                        "Content-Range", f"bytes {start}-{outer.size - 1}/{outer.size}"
                    )
                self.end_headers()
                sent = 0
                try:
                    offset = start
                    while offset < outer.size:
                        length = min(
                            outer.size - offset,
                            len(outer.block) - offset % len(outer.block),
                        )
                        chunk = outer.block[
                            offset % len(outer.block) : offset % len(outer.block)
                            + length
                        ]
                        self.wfile.write(chunk)
                        sent += len(chunk)
                        offset += length
                    self.wfile.flush()
                except (ConnectionError, BrokenPipeError, OSError):
                    pass
                finally:
                    with outer.lock:
                        outer.transferred += sent
                        outer.requests.append(
                            {"range": rng or None, "status": code, "sentBytes": sent}
                        )

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}/benchmark.bin"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def repeating_hash(block: bytes, size: int) -> str:
    digest = hashlib.sha256()
    for offset in range(0, size, len(block)):
        digest.update(block[: min(len(block), size - offset)])
    return digest.hexdigest()


def benchmark_download(
    runtime: Path, signer: Path, work: Path, size_mib: int, repetitions: int = 3
) -> dict:
    if size_mib < 1 or repetitions < 1:
        raise ValueError("Некорректное значение: «download size or repetitions»")
    size = size_mib * MIB
    # Одна установленная копия может сосуществовать с нативным кэшем с адресацией
    # по содержимому. Отклоняйте опасную нагрузку на диск вместо заполнения
    # промышленного тома.
    available = shutil.disk_usage(work).free
    if available < int(size * 2.5) + 128 * MIB:
        raise RuntimeError(
            f"Недостаточно свободного места для теста объёмом {size_mib} МиБ (необходимо не менее 2,5 размера тестовых данных)"
        )
    block = hashlib.shake_256(b"launcher-03511-incompressible-fixture").digest(MIB)
    digest = repeating_hash(block, size)
    rows = []
    with RepeatingRangeServer(block, size) as server:
        manifest, key = signed_manifest(
            signer,
            work,
            manifest_base(
                [
                    file_entry(
                        "libraries/benchmark/payload.bin", size, digest, server.url
                    )
                ]
            ),
        )
        for index in range(repetitions):
            # Новый корень и пустой кэш гарантируют полную сетевую загрузку, а не только чтение
            # из кэша ОС/приложения.
            root = work / f"game-{index}"
            env = isolated_env(work / f"cache-{index}")
            wire_before = server.transferred
            observed, data = run_native(
                [
                    str(runtime),
                    "sync-local",
                    "--manifest",
                    str(manifest),
                    "--root",
                    str(root),
                    "--pinned-public-key",
                    key,
                ],
                env=env,
                timeout=3600,
            )
            wire = server.transferred - wire_before
            output = root / "libraries/benchmark/payload.bin"
            if (
                data.get("status") != "ready"
                or not output.is_file()
                or output.stat().st_size != size
            ):
                raise RuntimeError("Нативная загрузка не опубликовала ожидаемый файл")
            # Независимый дайджест, без опоры только на нативный флаг ready.
            if hash_file(output) != digest:
                raise RuntimeError("Независимая проверка SHA-256 загруженного файла выявила несовпадение")
            if wire < size or wire > size * 1.05:
                raise RuntimeError(
                    f"Неожиданный объём переданных по сети данных: {wire} вместо {size}"
                )
            rows.append(
                {
                    "run": index + 1,
                    **observed,
                    "wireBytes": wire,
                    "throughputMiBPerSec": size_mib / (observed["elapsedMs"] / 1000),
                }
            )
            # Настоящее тёплое обновление точно установленного выпуска должно обходиться без
            # HTTP-загрузок.
            warm_before = server.transferred
            warm, warm_data = run_native(
                [
                    str(runtime),
                    "sync-local",
                    "--manifest",
                    str(manifest),
                    "--root",
                    str(root),
                    "--pinned-public-key",
                    key,
                ],
                env=env,
                timeout=1800,
            )
            if warm_data.get("status") != "ready" or server.transferred != warm_before:
                raise RuntimeError(
                    "Повторное нативное обновление передало данные по сети либо завершилось ошибкой"
                )
            rows[-1]["warmUpdate"] = {**warm, "wireBytes": 0}
            # Запуски с 10 ГиБ выполняйте последовательно с ограничением использования
            # диска.
            shutil.rmtree(root)
            shutil.rmtree(work / f"cache-{index}")
    return {
        "sizeMiB": size_mib,
        "payloadSha256": digest,
        "coldElapsedMs": describe([r["elapsedMs"] for r in rows]),
        "warmUpdateElapsedMs": describe([r["warmUpdate"]["elapsedMs"] for r in rows]),
        "throughputMiBPerSec": describe([r["throughputMiBPerSec"] for r in rows]),
        "runs": rows,
        "source": "actual loopback HTTP Range server, no external CDN",
    }


def benchmark_startup(
    desktop: Path, work: Path, repetitions: int = 3, timeout: int = 90
) -> dict:
    rows = []
    for index in range(repetitions + 1):
        marker = work / f"ui-ready-{index}.json"
        env = isolated_env(work / "desktop-home")
        env["LAUNCHER_BENCH_READY_FILE"] = str(marker)
        start_wall = time.time_ns()
        start_mono = time.perf_counter_ns()
        with (
            tempfile.TemporaryFile(mode="w+t", encoding="utf8") as stdout,
            tempfile.TemporaryFile(mode="w+t", encoding="utf8") as stderr,
        ):
            proc = subprocess.Popen(
                [str(desktop)], env=env, stdout=stdout, stderr=stderr
            )
            try:
                with ProcessMonitor(proc.pid) as monitor:
                    deadline = time.monotonic() + timeout
                    while time.monotonic() < deadline:
                        if marker.is_file():
                            break
                        if proc.poll() is not None:
                            stderr.seek(0)
                            raise RuntimeError(
                                f"Desktop завершился до готовности интерфейса: {stderr.read()[-800:]}"
                            )
                        time.sleep(0.015)
                    else:
                        raise RuntimeError("Desktop не показал маркер готовности интерфейса")
                value = json.loads(marker.read_text(encoding="utf8"))
                end_mono = time.perf_counter_ns()
                elapsed_ms = (value["wallClockUnixNs"] - start_wall) / 1e6
                if not 0 < elapsed_ms <= (end_mono - start_mono) / 1e6 + 250:
                    raise RuntimeError(
                        "Недопустимая отметка времени готовности интерфейса или скачок системных часов"
                    )
                resources = monitor.report()
                resources["cpuCorePercentOfWallTime"] = (
                    100
                    * resources["sampledCpuSeconds"]
                    / ((end_mono - start_mono) / 1e9)
                )
                rows.append(
                    {
                        "run": index + 1,
                        "kind": "firstProcessStart"
                        if index == 0
                        else "subsequentProcessStart",
                        "elapsedMs": elapsed_ms,
                        **resources,
                    }
                )
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
    return {
        "startupDefinition": "process creation to React first double requestAnimationFrame, native marker",
        "note": "Холодный запуск — это первый запуск процесса, а НЕ очистка файлового кеша ОС или запуск компьютера после выключения; последующие запуски используют кеши ОС",
        "firstStart": rows[0],
        "subsequentStartMs": describe([r["elapsedMs"] for r in rows[1:]]),
        "runs": rows,
    }


def benchmark_api(
    endpoint: str,
    *,
    repetitions: int = 3,
    requests_per_run: int = 100,
    workers: int = 8,
    backend_pid: int | None = None,
) -> dict:
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Требуется: «absolute HTTP(S) endpoint without credentials/query»")
    if (
        parsed.hostname not in ("127.0.0.1", "localhost", "::1")
        and os.getenv("LAUNCHER_BENCH_ALLOW_REMOTE") != "YES"
    ):
        raise ValueError(
            "Для удалённых адресов необходимо задать LAUNCHER_BENCH_ALLOW_REMOTE=YES; используйте только на подконтрольных системах"
        )
    if (
        workers < 1
        or workers > 64
        or requests_per_run < workers
        or requests_per_run > 10000
    ):
        raise ValueError(
            "Число рабочих процессов должно быть от 1 до 64, а запросов за запуск — от числа процессов до 10000"
        )
    token = os.getenv("LAUNCHER_BENCH_AUTH_TOKEN")
    headers = {"Accept": "application/json", "User-Agent": "Launcher-Benchmark/0.35.11"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def sample():
        t0 = time.perf_counter_ns()
        try:
            with urlopen(
                Request(endpoint, headers=headers, method="GET"), timeout=15
            ) as response:
                content = response.read(2 * MIB + 1)
                if len(content) > 2 * MIB:
                    raise ValueError("Ответ API превышает ограничение размера измерений")
                code = response.status
            return {"elapsedMs": (time.perf_counter_ns() - t0) / 1e6, "status": code}
        except Exception as exc:
            return {
                "elapsedMs": (time.perf_counter_ns() - t0) / 1e6,
                "status": None,
                "errorType": type(exc).__name__,
            }

    rows = []
    for n in range(repetitions):
        monitor = ProcessMonitor(backend_pid) if backend_pid is not None else None
        if monitor:
            monitor.__enter__()
        try:
            started = time.perf_counter_ns()
            with ThreadPoolExecutor(max_workers=workers) as executor:
                observations = list(
                    executor.map(lambda _: sample(), range(requests_per_run))
                )
            wall_sec = (time.perf_counter_ns() - started) / 1e9
        finally:
            if monitor:
                monitor.__exit__(None, None, None)
        success = [
            r["elapsedMs"]
            for r in observations
            if r["status"] is not None and 200 <= r["status"] < 300
        ]
        if len(success) != len(observations):
            raise RuntimeError(
                f"HTTP-запуск {n + 1}: неуспешных запросов {len(observations) - len(success)} из {len(observations)}"
            )
        row = {
            "run": n + 1,
            "latencyMs": describe(success),
            "requestsPerSecond": len(success) / wall_sec,
            "requests": len(success),
        }
        if monitor:
            row["backendResources"] = monitor.report()
            row["backendResources"]["cpuCorePercentOfWallTime"] = (
                100 * row["backendResources"]["sampledCpuSeconds"] / wall_sec
            )
        rows.append(row)
    return {
        "urlRedacted": f"{parsed.scheme}://{parsed.hostname}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}{parsed.path}",
        "method": "GET",
        "concurrency": workers,
        "runs": rows,
        "p95Ms": describe([r["latencyMs"]["p95"] for r in rows]),
        "p99Ms": describe([r["latencyMs"]["p99"] for r in rows]),
        "note": "Измеряется указанный адрес API, а не все страницы Admin, сценарии авторизации или задержка БД рабочей среды",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, help="Скомпилированный исполняемый файл Runtime")
    parser.add_argument(
        "--signer", type=Path, help="Скомпилированный пример Runtime cert_sign_fixture"
    )
    parser.add_argument(
        "--desktop", type=Path, help="Скомпилированный исполняемый файл Tauri Desktop"
    )
    parser.add_argument(
        "--api-url", help="URL API только для чтения; настоящий Backend должен работать"
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--verify-files", type=int, default=10000)
    parser.add_argument("--download-mib", type=int, nargs="*", default=[1024, 10240])
    parser.add_argument(
        "--confirm-large",
        action="store_true",
        help="Явно разрешить реальные сетевые/дисковые записи объёмом 1 и 10 ГиБ",
    )
    parser.add_argument(
        "--api-pid", type=int, help="PID локального процесса Backend для измерения CPU/RAM"
    )
    parser.add_argument("--api-requests", type=int, default=100)
    parser.add_argument("--api-workers", type=int, default=8)
    args = parser.parse_args()
    if args.api_pid is not None and (not args.api_url or args.api_pid <= 0):
        parser.error("Для --api-pid требуются --api-url и положительный локальный PID")
    if args.repetitions < 3:
        parser.error("Для отчётов по измерениям требуется не менее трёх повторений")
    if not (args.runtime or args.desktop or args.api_url):
        parser.error("Укажите хотя бы один реальный измеряемый исполняемый файл или endpoint")
    if args.runtime and not args.signer:
        parser.error("Для --runtime требуется --signer")
    if args.runtime and any(n < 1 or n > 10240 for n in args.download_mib):
        parser.error("download sizes: требуется «in 1..10240 MiB»")
    if (
        args.download_mib
        and args.runtime
        and any(n >= 1024 for n in args.download_mib)
        and not args.confirm_large
    ):
        parser.error("Для реальных загрузок объёмом 1/10 ГиБ требуется --confirm-large")
    measurements = {}
    report = {
        "schemaVersion": "1.0",
        "status": "incomplete",
        "environment": metadata(),
        "executables": {},
        "measurements": measurements,
    }
    if args.runtime:
        report["executables"]["runtime"] = binary(args.runtime, "runtime")
        report["executables"]["signer"] = binary(args.signer, "certification signer")
    if args.desktop:
        report["executables"]["desktop"] = binary(args.desktop, "desktop")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="launcher-bench-03511-") as d:
            work = Path(d)
            if args.runtime:
                folder = work / "file-verification"
                folder.mkdir()
                measurements["verify"] = verify_10k(
                    args.runtime.resolve(),
                    args.signer.resolve(),
                    folder,
                    count=args.verify_files,
                    repetitions=args.repetitions,
                )
                for size_mib in args.download_mib:
                    folder = work / f"download-{size_mib}"
                    folder.mkdir()
                    measurements[f"download-{size_mib}MiB"] = benchmark_download(
                        args.runtime.resolve(),
                        args.signer.resolve(),
                        folder,
                        size_mib,
                        repetitions=args.repetitions,
                    )
            if args.desktop:
                folder = work / "desktop"
                folder.mkdir()
                measurements["startup"] = benchmark_startup(
                    args.desktop.resolve(), folder, repetitions=args.repetitions
                )
            if args.api_url:
                measurements["api"] = benchmark_api(
                    args.api_url,
                    repetitions=args.repetitions,
                    requests_per_run=args.api_requests,
                    workers=args.api_workers,
                    backend_pid=args.api_pid,
                )
        report["status"] = "measured"
        return_code = 0
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)[:1500]}
        return_code = 1
    args.output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf8"
    )
    print(
        json.dumps(
            {
                "status": report["status"],
                "output": str(args.output),
                "measurements": list(measurements),
                "error": report.get("error"),
            },
            ensure_ascii=False,
        )
    )
    return return_code


if __name__ == "__main__":
    sys.exit(main())
