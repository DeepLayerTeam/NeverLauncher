#if os(macOS)
import Foundation
import Darwin
import CryptoKit
import Dispatch

// libproc перечисляет непосредственных потомков; обходите их рекурсивно, чтобы обнаружить любой
// дополнительный процесс нативного расширения, включая сменивший группу процессов.
@_silgen_name("proc_listchildpids")
private func listChildPIDs(_ ppid: pid_t, _ buffer: UnsafeMutableRawPointer?, _ bytes: Int32) -> Int32

// Этот исполняемый файл ОБЯЗАТЕЛЬНО должен быть подписан Developer ID с единственным app-sandbox=true. Не
// запускайте его без проверки подписи и набора entitlement родительским процессом. Расширение —
// самостоятельный нативный Mach-O, копируемый в СОБСТВЕННЫЙ контейнер App Sandbox помощника. Общие
// разрешения на файлы с ограниченным доступом и сетевые entitlement не предоставляются.

@_silgen_name("sandbox_check")
private func sandboxCheck(_ pid: pid_t, _ operation: UnsafePointer<CChar>, _ filterType: UInt32, _ path: UnsafePointer<CChar>) -> Int32

private struct Request: Decodable {
    let size: Int
    let sha256: String
    let args: [String]
    let environment: [String]
    let memoryBytes: Int64
    let cpuPercent: Int
    let timeoutSeconds: Int
    let maxProcesses: Int
}

private enum SandboxError: Error {
    case invalid(String)
    var message: String { if case let .invalid(s) = self { return s }; return "helper-error" }
}
private func fail(_ why: String) -> Never {
    let bytes = Array(("error " + why + "\n").utf8)
    _ = bytes.withUnsafeBytes { write(5, $0.baseAddress, $0.count) }
    fputs("Launcher macOS sandbox: \(why)\n", stderr)
    exit(126)
}
private func exactRead(_ fd: Int32, _ length: Int) throws -> Data {
    if length < 0 || length > 64 << 20 { throw SandboxError.invalid("executable-size-outside-bound") }
    var data = Data()
    var chunk = [UInt8](repeating: 0, count: 32768)
    while data.count < length {
        let count = min(chunk.count, length - data.count)
        let n = chunk.withUnsafeMutableBytes { read(fd, $0.baseAddress, count) }
        if n < 0 && errno == EINTR { continue }
        if n <= 0 { throw SandboxError.invalid("truncated-executable") }
        data.append(contentsOf: chunk[0..<n])
    }
    return data
}
private func readHeader(_ fd: Int32) throws -> Request {
    var line = [UInt8]()
    while line.count <= 32768 {
        var byte: UInt8 = 0
        let n = read(fd, &byte, 1)
        if n < 0 && errno == EINTR { continue }
        if n != 1 { throw SandboxError.invalid("truncated-header") }
        if byte == 10 { return try JSONDecoder().decode(Request.self, from: Data(line)) }
        line.append(byte)
    }
    throw SandboxError.invalid("header-exceeds-32k")
}
private func ensureSandbox() throws {
    // Проверьте запись, которую App Sandbox должна отклонить, даже если каталог обычно доступен интерактивному
    // пользователю.
    let denial = "/Users/Shared".withCString { sandboxCheck(getpid(), "file-write-data", 1, $0) }
    if denial == 0 { throw SandboxError.invalid("kernel-app-sandbox-not-enforced") }
}
private func stage(_ image: Data) throws -> (String, String) {
    let home = FileManager.default.homeDirectoryForCurrentUser
    guard home.path.contains("/Library/Containers/") && home.path.hasSuffix("/Data") else {
        throw SandboxError.invalid("app-sandbox-home-container-required")
    }
    let base = home.appendingPathComponent("Library/Application Support/LauncherIsolated", isDirectory: true)
    try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let run = base.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: run, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let scratch = run.appendingPathComponent("scratch", isDirectory: true)
    try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let path = run.appendingPathComponent("extension")
    let handle = open(path.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o700)
    if handle < 0 { throw SandboxError.invalid("private-executable-create-denied") }
    defer { close(handle) }
    try image.withUnsafeBytes { raw in
        guard let base = raw.baseAddress else { throw SandboxError.invalid("empty-executable") }
        var offset = 0
        while offset < image.count {
            let n = write(handle, base.advanced(by: offset), image.count - offset)
            if n < 0 && errno == EINTR { continue }
            if n <= 0 { throw SandboxError.invalid("executable-write-failed") }
            offset += n
        }
    }
    if fchmod(handle, 0o500) != 0 { throw SandboxError.invalid("executable-permission-failed") }
    return (path.path, scratch.path)
}
private func limit(_ resource: Int32, _ maximum: UInt64) throws {
    let value = rlim_t(maximum)
    var bounds = rlimit(rlim_cur: value, rlim_max: value)
    if setrlimit(resource, &bounds) != 0 { throw SandboxError.invalid("resource-limit-rejected") }
}
private func spawn(_ path: String, _ scratch: String, _ request: Request) throws -> pid_t {
    if request.args.count > 128 || request.args.contains(where: { $0.contains("\0") || $0.utf8.count > 16384 }) {
        throw SandboxError.invalid("invalid-arguments")
    }
    if request.memoryBytes < 64 << 20 || request.cpuPercent < 1 || request.cpuPercent > 100 || request.timeoutSeconds < 1 || request.maxProcesses != 1 {
        throw SandboxError.invalid("invalid-limits")
    }
    // Лимиты ресурсов наследуются потомками. На macOS совокупное потребление нельзя атомарно ограничить без
    // привилегированного супервизора; поддерживается только один процесс, а создание потомка считается
    // фатальным нарушением.
    try limit(RLIMIT_AS, UInt64(request.memoryBytes))
    let cpu = max(1, (request.timeoutSeconds * request.cpuPercent + 99) / 100)
    try limit(RLIMIT_CPU, UInt64(cpu))
    var env = request.environment.filter {
        $0.hasPrefix("LAUNCHER_") && !$0.hasPrefix("LAUNCHER_EXTENSION_HOST_FD=") && !$0.contains("\0")
    }
    env.append("LAUNCHER_EXTENSION_HOST_FD=4")
    env.append("HOME=\(scratch)")
    env.append("TMPDIR=\(scratch)")
    env.append("PATH=/usr/bin:/bin")
    let argv: [String] = [path] + request.args
    var args: [UnsafeMutablePointer<CChar>?] = argv.map { strdup($0) } + [nil]
    var vars: [UnsafeMutablePointer<CChar>?] = env.map { strdup($0) } + [nil]
    defer { for s in args { free(s) }; for s in vars { free(s) } }
    if chdir(scratch) != 0 { throw SandboxError.invalid("scratch-working-directory-required") }
    // Никогда не раскрывайте недоверенному потомку дескриптор конфигурации или подтверждения готовности. FD4 —
    // единственная намеренно наследуемая точка IPC.
    _ = fcntl(3, F_SETFD, FD_CLOEXEC)
    _ = fcntl(5, F_SETFD, FD_CLOEXEC)
    _ = fcntl(6, F_SETFD, FD_CLOEXEC)
    // Go ExtraFiles передаёт сокет брокера как FD4. Статическая App Sandbox, применяемая ядром, наследуется
    // через posix_spawn, включая потомков.
    if fcntl(4, F_SETFD, 0) != 0 { throw SandboxError.invalid("host-ipc-fd-unavailable") }
    var child: pid_t = 0
    let result = args.withUnsafeMutableBufferPointer { a in vars.withUnsafeMutableBufferPointer { v in
        posix_spawn(&child, path, nil, nil, a.baseAddress!, v.baseAddress!)
    }}
    if result != 0 || child < 1 { throw SandboxError.invalid("sandboxed-spawn-failed-\(result)") }
    return child
}

private func children(of parent: pid_t) -> [pid_t]? {
    let capacity = 4096
    var pids = [pid_t](repeating: 0, count: capacity)
    // libproc proc_listchildpids возвращает число PID, а НЕ байтов (в отличие от proc_listpids). Полный буфер
    // считайте переполнением и отказывайте.
    let count = pids.withUnsafeMutableBytes { raw -> Int32 in
        listChildPIDs(parent, raw.baseAddress, Int32(raw.count))
    }
    if count < 0 || Int(count) >= capacity { return nil }
    return Array(pids.prefix(Int(count))).filter { $0 > 0 }
}

// FD6 удерживается супервизором Go. Потеря родителя фатальна, даже если его группа процессов уже исчезла.
// О готовности не сообщают до подтверждения наследования дочерним процессом политики App Sandbox ядра.
private func parentAlive() -> Bool {
    var fd = pollfd(fd: 6, events: Int16(POLLHUP | POLLERR | POLLNVAL), revents: 0)
    let status = poll(&fd, 1, 0)
    return status == 0
}
private func enforceChildBoundary(_ child: pid_t) -> Bool {
    guard parentAlive(), let direct = children(of: getpid()), direct.count == 1, direct[0] == child,
          let grandChildren = children(of: child), grandChildren.isEmpty else { return false }
    return true
}
private func run() throws {
    try ensureSandbox()
    let header = try readHeader(3)
    let data = try exactRead(3, header.size)
    let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    if digest != header.sha256 { throw SandboxError.invalid("executable-sha256-mismatch") }
    let (path, scratch) = try stage(data)
    defer { _ = try? FileManager.default.removeItem(at: URL(fileURLWithPath: (path as NSString).deletingLastPathComponent)) }
    let pid = try spawn(path, scratch, header)
    // Подписи помощника недостаточно: проверьте, что сам ДОЧЕРНИЙ процесс унаследовал политику App Sandbox с
    // запретом по умолчанию.
    let childDenied = "/Users/Shared".withCString { sandboxCheck(pid, "file-write-data", 1, $0) }
    guard childDenied != 0 && enforceChildBoundary(pid) else {
        _ = kill(pid, SIGKILL)
        throw SandboxError.invalid("child-sandbox-or-process-boundary-unverified")
    }
    let signal = Array("ready \(pid)\n".utf8)
    guard signal.withUnsafeBytes({ write(5, $0.baseAddress, $0.count) }) == signal.count else {
        _ = kill(pid, SIGKILL)
        throw SandboxError.invalid("ready-channel-failed")
    }
    var status: Int32 = 0
    var violated = false
    while true {
        // WNOHANG позволяет непрерывно применять ограничения, а не бесконечно ожидать скомпрометированное
        // расширение. Учитывайте отделившегося потомка: одной проверки группы процессов на macOS недостаточно.
        let waited = waitpid(pid, &status, WNOHANG)
        if waited == pid { break }
        if waited < 0 { if errno == EINTR { continue }; violated = true; break }
        if !enforceChildBoundary(pid) {
            violated = true
            if let descendants = children(of: pid) {
                for descendant in descendants { _ = kill(descendant, SIGKILL) }
            }
            _ = kill(pid, SIGKILL)
            while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
            break
        }
        usleep(20_000) // 20 мс — не замена ограничению числа процессов на уровне ядра.
    }
    _ = try? FileManager.default.removeItem(at: URL(fileURLWithPath: (path as NSString).deletingLastPathComponent))
    if violated { exit(126) }
    if (status & 0x7f) == 0 { exit((status >> 8) & 0xff) }
    exit(128)
}
do { try run() } catch let e as SandboxError { fail(e.message) } catch { fail("sandbox-initialization-failed") }
#else
fatalError("Вспомогательная утилита изоляции Launcher может запускаться только на macOS")
#endif
