/// Centralized security-sensitive function specs for C/POSIX/Windows and common libraries.
///
/// # Design
///
/// Every function that matters to the analysis has a **spec** — a structured
/// description of its security-relevant behaviour.  Callers that need only a
/// function name iterate the spec table and take the key:
///
/// ```rust
/// use web_sitter::security_patterns as sp;
///
/// let is_prop = sp::get_propagator("sprintf").is_some();
/// let src_names: Vec<&str> = sp::STDLIB_TAINT_SOURCES.iter().map(|(n, _)| *n).collect();
/// ```
///
/// # Rule-matcher contract
///
/// The rule matcher obtains sources and sinks from YAML rules (and
/// `TaintConfig::builtin()`).  `security_patterns` is the single source of
/// truth for stdlib propagators and any other component that must know about
/// stdlib behaviour.

// =============================================================================
// Spec types
// =============================================================================

/// Describes how a function introduces taint into the program.
pub struct SourceSpec {
    /// Argument indices that are written with tainted data (output buffers).
    pub tainted_params: &'static [i32],
    /// Whether the return value is tainted.
    pub tainted_return: bool,
}

/// Describes which arguments of a function must not receive tainted data.
pub struct SinkSpec {
    /// Argument indices that are security-sensitive.
    pub sink_args: &'static [i32],
}

/// Describes how a function propagates taint from source arguments to a
/// destination argument.
pub struct PropagatorSpec {
    /// Index of the destination (output) argument.
    /// `-1` means the return value is the destination (no arg is written).
    pub dst: i32,
    /// Source argument indices.
    /// `-1` means "all remaining arguments after `dst`" (for variadic format
    /// functions such as `sprintf`; only meaningful when `dst >= 0`).
    pub src: &'static [i32],
}

/// Describes a heap allocation function.
pub struct AllocSpec {
    /// Which argument carries the allocation size.
    /// `-1` means the size is implicit (e.g. `strdup` — derived from arg 0's length).
    pub size_arg: i32,
}

// =============================================================================
// C/POSIX taint sources
// =============================================================================

/// Stdlib/POSIX/Windows functions that introduce attacker-controlled data.
pub const STDLIB_TAINT_SOURCES: &[(&str, SourceSpec)] = &[
    // ── Standard I/O ─────────────────────────────────────────────────────────
    (
        "gets",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: true,
        },
    ),
    (
        "fgets",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: true,
        },
    ),
    (
        "getchar",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getc",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "fgetc",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "ungetc",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getline",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "getdelim",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    // ── Formatted input ──────────────────────────────────────────────────────
    (
        "scanf",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "fscanf",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "sscanf",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "vscanf",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "vfscanf",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "vsscanf",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "wscanf",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "fwscanf",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "swscanf",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    // ── File I/O ─────────────────────────────────────────────────────────────
    (
        "fread",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    // ── POSIX I/O ────────────────────────────────────────────────────────────
    (
        "read",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "pread",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "readv",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "preadv",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    // ── Network I/O ──────────────────────────────────────────────────────────
    (
        "recv",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "recvfrom",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "recvmsg",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "recvmmsg",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    // ── DNS / host lookups ────────────────────────────────────────────────────
    (
        "gethostbyname",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "gethostbyaddr",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getnameinfo",
        SourceSpec {
            tainted_params: &[2, 4],
            tainted_return: false,
        },
    ),
    (
        "getsockname",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    // ── Environment / system ─────────────────────────────────────────────────
    (
        "getenv",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "secure_getenv",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getlogin",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getlogin_r",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "getcwd",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: true,
        },
    ),
    (
        "getwd",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: true,
        },
    ),
    (
        "get_current_dir_name",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "gethostname",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "getdomainname",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "getopt",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getopt_long",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getopt_long_only",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── String tokenisation ───────────────────────────────────────────────────
    (
        "strtok",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "strtok_r",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "strsep",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── User interaction ─────────────────────────────────────────────────────
    (
        "getpass",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "readline",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── C++ I/O streams ──────────────────────────────────────────────────────
    (
        "cin",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "wcin",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "std::cin",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "std::wcin",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "std::getline",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "istream",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "iostream",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "basic_istream",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "istreambuf_iterator",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "std::basic_istream",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "std::istream",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── CRT / POSIX extended ─────────────────────────────────────────────────
    (
        "getenv_s",
        SourceSpec {
            tainted_params: &[3],
            tainted_return: false,
        },
    ),
    (
        "gets_s",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: true,
        },
    ),
    (
        "getenv_r",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    // ── Windows — file I/O ───────────────────────────────────────────────────
    (
        "ReadFile",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "ReadFileEx",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "NtReadFile",
        SourceSpec {
            tainted_params: &[5],
            tainted_return: false,
        },
    ),
    (
        "ZwReadFile",
        SourceSpec {
            tainted_params: &[5],
            tainted_return: false,
        },
    ),
    // ── Windows — network (Winsock) ──────────────────────────────────────────
    (
        "WSARecv",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "WSARecvFrom",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "WSARecvMsg",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "WSAReadMsg",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "AcceptEx",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    (
        "WSAAccept",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── Windows — UI / user input ────────────────────────────────────────────
    (
        "GetWindowTextA",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "GetWindowTextW",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "GetWindowText",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "GetDlgItemTextA",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    (
        "GetDlgItemTextW",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    (
        "GetDlgItemText",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    (
        "GetClipboardData",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── Windows — environment ────────────────────────────────────────────────
    (
        "GetEnvironmentVariableA",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "GetEnvironmentVariableW",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "ExpandEnvironmentStringsA",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "ExpandEnvironmentStringsW",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    // ── Windows — command line ───────────────────────────────────────────────
    (
        "GetCommandLineA",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "GetCommandLineW",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "GetCommandLine",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── Windows — user/machine information ──────────────────────────────────
    (
        "GetUserNameA",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "GetUserNameW",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "GetUserNameExA",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "GetUserNameExW",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "GetComputerNameA",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "GetComputerNameW",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "GetComputerNameExA",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "GetComputerNameExW",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "GetAdaptersInfo",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "GetAdaptersAddresses",
        SourceSpec {
            tainted_params: &[3],
            tainted_return: false,
        },
    ),
    // ── Windows — registry read ──────────────────────────────────────────────
    (
        "RegQueryValueExA",
        SourceSpec {
            tainted_params: &[4],
            tainted_return: false,
        },
    ),
    (
        "RegQueryValueExW",
        SourceSpec {
            tainted_params: &[4],
            tainted_return: false,
        },
    ),
    (
        "RegGetValueA",
        SourceSpec {
            tainted_params: &[6],
            tainted_return: false,
        },
    ),
    (
        "RegGetValueW",
        SourceSpec {
            tainted_params: &[6],
            tainted_return: false,
        },
    ),
    (
        "SHRegOpenUSKeyA",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "SHRegOpenUSKeyW",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── Windows — I/O completion ports ──────────────────────────────────────
    (
        "GetQueuedCompletionStatus",
        SourceSpec {
            tainted_params: &[3],
            tainted_return: false,
        },
    ),
    (
        "GetQueuedCompletionStatusEx",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    // ── Windows — HTTP Server API ────────────────────────────────────────────
    (
        "HttpReceiveHttpRequest",
        SourceSpec {
            tainted_params: &[3],
            tainted_return: false,
        },
    ),
    (
        "HttpReceiveHttpRequestFragment",
        SourceSpec {
            tainted_params: &[3],
            tainted_return: false,
        },
    ),
    // ── Windows — memory mapping ─────────────────────────────────────────────
    (
        "MapViewOfFile",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "MapViewOfFileEx",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── Windows — device I/O ─────────────────────────────────────────────────
    (
        "DeviceIoControl",
        SourceSpec {
            tainted_params: &[4],
            tainted_return: false,
        },
    ),
    // ── Windows — path/module information ───────────────────────────────────
    (
        "GetTempPathA",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "GetTempPathW",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "GetTempFileNameA",
        SourceSpec {
            tainted_params: &[3],
            tainted_return: false,
        },
    ),
    (
        "GetTempFileNameW",
        SourceSpec {
            tainted_params: &[3],
            tainted_return: false,
        },
    ),
    (
        "GetModuleFileNameA",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "GetModuleFileNameW",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "GetModuleFileNameExA",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    (
        "GetModuleFileNameExW",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    (
        "GetFullPathNameA",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    (
        "GetFullPathNameW",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    (
        "GetCurrentDirectoryA",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "GetCurrentDirectoryW",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    // ── Windows — token / security ───────────────────────────────────────────
    (
        "GetTokenInformation",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    (
        "LsaGetLogonSessionData",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    // ── Windows — cryptography (decrypted data is attacker-influenced) ───────
    (
        "CryptDecrypt",
        SourceSpec {
            tainted_params: &[4],
            tainted_return: false,
        },
    ),
    (
        "CryptDecryptMessage",
        SourceSpec {
            tainted_params: &[4],
            tainted_return: false,
        },
    ),
    // ── Windows — LDAP ──────────────────────────────────────────────────────
    (
        "ldap_initA",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "ldap_initW",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "ldap_search_ext_sA",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "ldap_search_ext_sW",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── C++ streams ─────────────────────────────────────────────────────────
    (
        "getline",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: true,
        },
    ),
    // istream::read / get / getline — param 0 is the istream object (this), param 1+ is buffer
    (
        "read",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "get",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: true,
        },
    ),
    // ── C++ Qt ──────────────────────────────────────────────────────────────
    (
        "QLineEdit::text",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "QInputDialog::getText",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "QProcess::readAllStandardOutput",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "QProcess::readLine",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: true,
        },
    ),
    // ── C++ Boost ───────────────────────────────────────────────────────────
    (
        "boost::property_tree::ptree::get",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── C++17 std::filesystem ───────────────────────────────────────────────
    (
        "std::filesystem::directory_iterator",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "std::filesystem::recursive_directory_iterator",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "std::filesystem::read_symlink",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── C++ getenv (qualified form) ─────────────────────────────────────────
    (
        "std::getenv",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── C++ istreambuf_iterator ─────────────────────────────────────────────
    (
        "std::istreambuf_iterator",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── C++17 from_chars — result depends on input string ───────────────────
    (
        "std::from_chars",
        SourceSpec {
            tainted_params: &[],
            tainted_return: false,
        },
    ),
    (
        "from_chars",
        SourceSpec {
            tainted_params: &[],
            tainted_return: false,
        },
    ),
    // ── C++ istream additional read operations ────────────────────────────────
    (
        "readsome",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "putback",
        SourceSpec {
            tainted_params: &[],
            tainted_return: false,
        },
    ),
    // ── POSIX — memory-mapped I/O ────────────────────────────────────────────
    (
        "mmap",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "mmap2",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── POSIX — socket connection accept ────────────────────────────────────
    (
        "accept",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: true,
        },
    ),
    (
        "accept4",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: true,
        },
    ),
    (
        "getpeername",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "getsockname",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "getsockopt",
        SourceSpec {
            tainted_params: &[4],
            tainted_return: false,
        },
    ),
    // ── POSIX — address string conversion ────────────────────────────────────
    (
        "inet_ntoa",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "inet_ntop",
        SourceSpec {
            tainted_params: &[3],
            tainted_return: true,
        },
    ),
    (
        "inet_addr",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── POSIX — name/address resolution ──────────────────────────────────────
    (
        "getaddrinfo",
        SourceSpec {
            tainted_params: &[3],
            tainted_return: false,
        },
    ),
    (
        "freeaddrinfo",
        SourceSpec {
            tainted_params: &[],
            tainted_return: false,
        },
    ),
    // ── POSIX — password / group database ────────────────────────────────────
    (
        "getpwnam",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getpwuid",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getpwnam_r",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    (
        "getpwuid_r",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    (
        "getpwent",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getgrnam",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getgrgid",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "getgrnam_r",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    (
        "getgrgid_r",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    (
        "getgrent",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── POSIX — system configuration strings ─────────────────────────────────
    (
        "confstr",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    (
        "sysconf",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "pathconf",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "uname",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    (
        "cuserid",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: true,
        },
    ),
    // ── POSIX — temp file name generation ────────────────────────────────────
    (
        "tmpnam",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: true,
        },
    ),
    (
        "tmpnam_r",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: true,
        },
    ),
    (
        "tempnam",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "mktemp",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: true,
        },
    ),
    // ── POSIX — misc. info sources ────────────────────────────────────────────
    (
        "getrusage",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "times",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: false,
        },
    ),
    // ── POSIX — NIS/NIS+ (external directory data) ───────────────────────────
    (
        "yp_match",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    (
        "nis_list",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── C++ — numeric string conversions (tainted string → tainted number) ────
    // stoi/stod family: value is derived from the tainted input string
    (
        "stoi",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "stol",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "stoll",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "stoul",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "stoull",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "stof",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "stod",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "stold",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "std::stoi",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "std::stol",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "std::stoll",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "std::stoul",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "std::stoull",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "std::stof",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "std::stod",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "std::stold",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── C++ — std::future gets a value from an async computation ─────────────
    (
        "std::future::get",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "future::get",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "shared_future::get",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    // ── Boost.Asio — async I/O result buffer ─────────────────────────────────
    (
        "boost::asio::read",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "boost::asio::read_until",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    (
        "boost::asio::async_read",
        SourceSpec {
            tainted_params: &[1],
            tainted_return: false,
        },
    ),
    // ── HTTP / REST (common framework patterns) ───────────────────────────────
    // libcurl: response body written to callback/buffer
    (
        "curl_easy_getinfo",
        SourceSpec {
            tainted_params: &[2],
            tainted_return: false,
        },
    ),
    // ── Qt additional sources ─────────────────────────────────────────────────
    (
        "QFile::readAll",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "QFile::readLine",
        SourceSpec {
            tainted_params: &[0],
            tainted_return: true,
        },
    ),
    (
        "QTextStream::readAll",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "QTextStream::readLine",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "QNetworkReply::readAll",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
    (
        "QHttpMultiPart::readAll",
        SourceSpec {
            tainted_params: &[],
            tainted_return: true,
        },
    ),
];

// =============================================================================
// C/POSIX taint sinks
// =============================================================================

/// Stdlib/POSIX/Windows functions that can be exploited with tainted arguments.
pub const STDLIB_TAINT_SINKS: &[(&str, SinkSpec)] = &[
    // ── Command / process execution ──────────────────────────────────────────
    ("system", SinkSpec { sink_args: &[0] }),
    ("popen", SinkSpec { sink_args: &[0] }),
    ("exec", SinkSpec { sink_args: &[0] }),
    ("execl", SinkSpec { sink_args: &[0] }),
    ("execle", SinkSpec { sink_args: &[0] }),
    ("execlp", SinkSpec { sink_args: &[0] }),
    ("execv", SinkSpec { sink_args: &[0] }),
    (
        "execve",
        SinkSpec {
            sink_args: &[0, 1, 2],
        },
    ),
    ("execvp", SinkSpec { sink_args: &[0] }),
    ("execvpe", SinkSpec { sink_args: &[0] }),
    ("fexecve", SinkSpec { sink_args: &[0] }),
    ("posix_spawn", SinkSpec { sink_args: &[2] }),
    ("posix_spawnp", SinkSpec { sink_args: &[2] }),
    // Microsoft spawn family
    ("_spawnl", SinkSpec { sink_args: &[1] }),
    ("_spawnlp", SinkSpec { sink_args: &[1] }),
    ("_spawnv", SinkSpec { sink_args: &[1] }),
    ("_spawnvp", SinkSpec { sink_args: &[1] }),
    ("_spawnle", SinkSpec { sink_args: &[1] }),
    ("_spawnlpe", SinkSpec { sink_args: &[1] }),
    ("_spawnve", SinkSpec { sink_args: &[1] }),
    ("_spawnvpe", SinkSpec { sink_args: &[1] }),
    ("_wspawnl", SinkSpec { sink_args: &[1] }),
    ("_wspawnlp", SinkSpec { sink_args: &[1] }),
    ("_wspawnv", SinkSpec { sink_args: &[1] }),
    ("_wspawnvp", SinkSpec { sink_args: &[1] }),
    // ── File-path operations (path traversal / CWE-22) ───────────────────────
    ("open", SinkSpec { sink_args: &[0] }),
    ("openat", SinkSpec { sink_args: &[1] }),
    ("creat", SinkSpec { sink_args: &[0] }),
    ("mkstemp", SinkSpec { sink_args: &[0] }),
    ("mkostemp", SinkSpec { sink_args: &[0] }),
    ("mkdtemp", SinkSpec { sink_args: &[0] }),
    ("unlink", SinkSpec { sink_args: &[0] }),
    ("unlinkat", SinkSpec { sink_args: &[1] }),
    ("remove", SinkSpec { sink_args: &[0] }),
    ("rename", SinkSpec { sink_args: &[0, 1] }),
    ("renameat", SinkSpec { sink_args: &[1, 3] }),
    ("mkdir", SinkSpec { sink_args: &[0] }),
    ("mkdirat", SinkSpec { sink_args: &[1] }),
    ("rmdir", SinkSpec { sink_args: &[0] }),
    ("symlink", SinkSpec { sink_args: &[0, 1] }),
    ("symlinkat", SinkSpec { sink_args: &[0, 2] }),
    ("link", SinkSpec { sink_args: &[0, 1] }),
    ("linkat", SinkSpec { sink_args: &[1, 3] }),
    ("chdir", SinkSpec { sink_args: &[0] }),
    ("fchdir", SinkSpec { sink_args: &[0] }),
    ("access", SinkSpec { sink_args: &[0] }),
    ("faccessat", SinkSpec { sink_args: &[1] }),
    ("chmod", SinkSpec { sink_args: &[0] }),
    ("fchmod", SinkSpec { sink_args: &[0] }),
    ("fchmodat", SinkSpec { sink_args: &[1] }),
    ("chown", SinkSpec { sink_args: &[0] }),
    ("lchown", SinkSpec { sink_args: &[0] }),
    ("fchown", SinkSpec { sink_args: &[0] }),
    ("fchownat", SinkSpec { sink_args: &[1] }),
    ("truncate", SinkSpec { sink_args: &[0] }),
    ("readlink", SinkSpec { sink_args: &[0] }),
    ("readlinkat", SinkSpec { sink_args: &[1] }),
    ("_wfopen", SinkSpec { sink_args: &[0] }),
    ("mkfifo", SinkSpec { sink_args: &[0] }),
    ("mknod", SinkSpec { sink_args: &[0] }),
    // ── Buffer / memory operations (buffer overflow) ─────────────────────────
    ("memcpy", SinkSpec { sink_args: &[2] }),
    ("memmove", SinkSpec { sink_args: &[2] }),
    ("wmemcpy", SinkSpec { sink_args: &[2] }),
    ("wmemmove", SinkSpec { sink_args: &[2] }),
    ("mempcpy", SinkSpec { sink_args: &[2] }),
    ("bcopy", SinkSpec { sink_args: &[0] }), // bcopy(src,dst,n): tainted src
    // ── String operations (buffer overflow) ──────────────────────────────────
    ("strcpy", SinkSpec { sink_args: &[1] }),
    ("strncpy", SinkSpec { sink_args: &[1] }),
    ("strcat", SinkSpec { sink_args: &[1] }),
    ("strncat", SinkSpec { sink_args: &[1] }),
    ("strdup", SinkSpec { sink_args: &[0] }),
    ("strndup", SinkSpec { sink_args: &[0] }),
    ("stpcpy", SinkSpec { sink_args: &[1] }),
    ("stpncpy", SinkSpec { sink_args: &[1] }),
    // ── Wide-character string operations ─────────────────────────────────────
    ("wcscpy", SinkSpec { sink_args: &[1] }),
    ("wcsncpy", SinkSpec { sink_args: &[1] }),
    ("wcscat", SinkSpec { sink_args: &[1] }),
    ("wcsncat", SinkSpec { sink_args: &[1] }),
    ("wcsdup", SinkSpec { sink_args: &[0] }),
    ("wcstombs", SinkSpec { sink_args: &[1] }),
    ("wcsnrtombs", SinkSpec { sink_args: &[1] }),
    // ── Formatted output (format string vulnerability) ────────────────────────
    ("printf", SinkSpec { sink_args: &[0] }),
    ("fprintf", SinkSpec { sink_args: &[1] }),
    ("sprintf", SinkSpec { sink_args: &[1] }),
    ("snprintf", SinkSpec { sink_args: &[2] }),
    ("vprintf", SinkSpec { sink_args: &[0] }),
    ("vfprintf", SinkSpec { sink_args: &[1] }),
    ("vsprintf", SinkSpec { sink_args: &[1] }),
    ("vsnprintf", SinkSpec { sink_args: &[2] }),
    ("wprintf", SinkSpec { sink_args: &[0] }),
    ("fwprintf", SinkSpec { sink_args: &[1] }),
    ("swprintf", SinkSpec { sink_args: &[2] }),
    ("vwprintf", SinkSpec { sink_args: &[0] }),
    ("vfwprintf", SinkSpec { sink_args: &[1] }),
    ("vswprintf", SinkSpec { sink_args: &[2] }),
    ("dprintf", SinkSpec { sink_args: &[1] }),
    ("vdprintf", SinkSpec { sink_args: &[1] }),
    ("asprintf", SinkSpec { sink_args: &[1] }),
    ("vasprintf", SinkSpec { sink_args: &[1] }),
    ("_snprintf", SinkSpec { sink_args: &[2] }),
    ("_snwprintf", SinkSpec { sink_args: &[2] }),
    // ── Logging (format string) ───────────────────────────────────────────────
    ("syslog", SinkSpec { sink_args: &[1] }),
    ("vsyslog", SinkSpec { sink_args: &[1] }),
    ("err", SinkSpec { sink_args: &[1] }),
    ("errx", SinkSpec { sink_args: &[1] }),
    ("warn", SinkSpec { sink_args: &[0] }),
    ("warnx", SinkSpec { sink_args: &[0] }),
    ("verr", SinkSpec { sink_args: &[1] }),
    ("verrx", SinkSpec { sink_args: &[1] }),
    ("vwarn", SinkSpec { sink_args: &[0] }),
    ("vwarnx", SinkSpec { sink_args: &[0] }),
    // ── Memory allocation (integer overflow in size → CWE-190/131) ───────────
    ("malloc", SinkSpec { sink_args: &[0] }),
    ("calloc", SinkSpec { sink_args: &[0, 1] }),
    ("realloc", SinkSpec { sink_args: &[1] }),
    ("reallocarray", SinkSpec { sink_args: &[1, 2] }),
    ("alloca", SinkSpec { sink_args: &[0] }),
    ("aligned_alloc", SinkSpec { sink_args: &[1] }),
    ("valloc", SinkSpec { sink_args: &[0] }),
    ("memalign", SinkSpec { sink_args: &[1] }),
    // ── Network ──────────────────────────────────────────────────────────────
    ("send", SinkSpec { sink_args: &[1] }),
    ("sendto", SinkSpec { sink_args: &[1] }),
    ("sendmsg", SinkSpec { sink_args: &[1] }),
    ("sendmmsg", SinkSpec { sink_args: &[1] }),
    ("sendfile", SinkSpec { sink_args: &[3] }),
    ("connect", SinkSpec { sink_args: &[1] }),
    ("setsockopt", SinkSpec { sink_args: &[3] }),
    ("bind", SinkSpec { sink_args: &[1] }),
    // ── File I/O ─────────────────────────────────────────────────────────────
    ("fwrite", SinkSpec { sink_args: &[0] }),
    ("fputs", SinkSpec { sink_args: &[0] }),
    ("puts", SinkSpec { sink_args: &[0] }),
    ("fputws", SinkSpec { sink_args: &[0] }),
    ("fputwc", SinkSpec { sink_args: &[0] }),
    ("write", SinkSpec { sink_args: &[1] }),
    ("writev", SinkSpec { sink_args: &[1] }),
    ("pwrite", SinkSpec { sink_args: &[1] }),
    ("pwritev", SinkSpec { sink_args: &[1] }),
    // ── IPC / shared memory ───────────────────────────────────────────────────
    ("shm_open", SinkSpec { sink_args: &[0] }),
    ("sem_open", SinkSpec { sink_args: &[0] }),
    ("mq_open", SinkSpec { sink_args: &[0] }),
    ("ioctl", SinkSpec { sink_args: &[2] }),
    // ── SQL / database ────────────────────────────────────────────────────────
    ("mysql_query", SinkSpec { sink_args: &[1] }),
    ("mysql_real_query", SinkSpec { sink_args: &[1] }),
    ("mysql_prepare", SinkSpec { sink_args: &[1] }),
    ("mysql_stmt_prepare", SinkSpec { sink_args: &[1] }),
    ("sqlite3_exec", SinkSpec { sink_args: &[1] }),
    ("sqlite3_prepare", SinkSpec { sink_args: &[1] }),
    ("sqlite3_prepare_v2", SinkSpec { sink_args: &[1] }),
    ("sqlite3_prepare_v3", SinkSpec { sink_args: &[1] }),
    ("PQexec", SinkSpec { sink_args: &[1] }),
    ("PQexecParams", SinkSpec { sink_args: &[1] }),
    ("PQprepare", SinkSpec { sink_args: &[1] }),
    ("PQexecPrepared", SinkSpec { sink_args: &[0] }),
    ("OCIStmtExecute", SinkSpec { sink_args: &[1] }),
    ("OCIStmtPrepare", SinkSpec { sink_args: &[2] }),
    ("odbc_exec", SinkSpec { sink_args: &[1] }),
    ("odbc_execute", SinkSpec { sink_args: &[0] }),
    // ── Library / code loading ────────────────────────────────────────────────
    ("dlopen", SinkSpec { sink_args: &[0] }),
    ("LoadLibraryA", SinkSpec { sink_args: &[0] }),
    ("LoadLibraryW", SinkSpec { sink_args: &[0] }),
    ("LoadLibraryExA", SinkSpec { sink_args: &[0] }),
    ("LoadLibraryExW", SinkSpec { sink_args: &[0] }),
    ("LoadLibraryEx", SinkSpec { sink_args: &[0] }),
    // ── Windows — process creation / command injection ────────────────────────
    ("WinExec", SinkSpec { sink_args: &[0] }),
    ("ShellExecuteA", SinkSpec { sink_args: &[2] }),
    ("ShellExecuteW", SinkSpec { sink_args: &[2] }),
    ("ShellExecuteExA", SinkSpec { sink_args: &[0] }),
    ("ShellExecuteExW", SinkSpec { sink_args: &[0] }),
    ("CreateProcessA", SinkSpec { sink_args: &[1] }),
    ("CreateProcessW", SinkSpec { sink_args: &[1] }),
    ("CreateProcessAsUserA", SinkSpec { sink_args: &[2] }),
    ("CreateProcessAsUserW", SinkSpec { sink_args: &[2] }),
    // ── Windows — file operations ─────────────────────────────────────────────
    ("WriteFile", SinkSpec { sink_args: &[1] }),
    ("WriteFileEx", SinkSpec { sink_args: &[1] }),
    ("NtWriteFile", SinkSpec { sink_args: &[5] }),
    ("ZwWriteFile", SinkSpec { sink_args: &[5] }),
    ("CreateFileA", SinkSpec { sink_args: &[0] }),
    ("CreateFileW", SinkSpec { sink_args: &[0] }),
    ("CreateFile", SinkSpec { sink_args: &[0] }),
    ("DeleteFileA", SinkSpec { sink_args: &[0] }),
    ("DeleteFileW", SinkSpec { sink_args: &[0] }),
    ("CreateDirectoryA", SinkSpec { sink_args: &[0] }),
    ("CreateDirectoryW", SinkSpec { sink_args: &[0] }),
    ("RemoveDirectoryA", SinkSpec { sink_args: &[0] }),
    ("RemoveDirectoryW", SinkSpec { sink_args: &[0] }),
    ("MoveFileA", SinkSpec { sink_args: &[0, 1] }),
    ("MoveFileW", SinkSpec { sink_args: &[0, 1] }),
    ("MoveFileExA", SinkSpec { sink_args: &[0, 1] }),
    ("MoveFileExW", SinkSpec { sink_args: &[0, 1] }),
    ("CopyFileA", SinkSpec { sink_args: &[0, 1] }),
    ("CopyFileW", SinkSpec { sink_args: &[0, 1] }),
    // ── Windows — registry write ──────────────────────────────────────────────
    ("RegSetValueExA", SinkSpec { sink_args: &[4] }),
    ("RegSetValueExW", SinkSpec { sink_args: &[4] }),
    ("RegCreateKeyExA", SinkSpec { sink_args: &[1] }),
    ("RegCreateKeyExW", SinkSpec { sink_args: &[1] }),
    ("RegCreateKeyA", SinkSpec { sink_args: &[1] }),
    ("RegCreateKeyW", SinkSpec { sink_args: &[1] }),
    ("RegOpenKeyExA", SinkSpec { sink_args: &[1] }),
    ("RegOpenKeyExW", SinkSpec { sink_args: &[1] }),
    // ── Windows — network send ────────────────────────────────────────────────
    ("WSASend", SinkSpec { sink_args: &[1] }),
    ("WSASendTo", SinkSpec { sink_args: &[1] }),
    ("WSASendMsg", SinkSpec { sink_args: &[1] }),
    // ── Windows — string operations ───────────────────────────────────────────
    ("lstrcpyA", SinkSpec { sink_args: &[1] }),
    ("lstrcpyW", SinkSpec { sink_args: &[1] }),
    ("lstrcatA", SinkSpec { sink_args: &[1] }),
    ("lstrcatW", SinkSpec { sink_args: &[1] }),
    ("lstrcpynA", SinkSpec { sink_args: &[1] }),
    ("lstrcpynW", SinkSpec { sink_args: &[1] }),
    // ── Windows — memory operations ───────────────────────────────────────────
    ("CopyMemory", SinkSpec { sink_args: &[1] }),
    ("MoveMemory", SinkSpec { sink_args: &[1] }),
    ("RtlCopyMemory", SinkSpec { sink_args: &[1] }),
    ("RtlMoveMemory", SinkSpec { sink_args: &[1] }),
    // ── Windows — virtual memory ──────────────────────────────────────────────
    ("VirtualAlloc", SinkSpec { sink_args: &[1] }),
    ("VirtualAllocEx", SinkSpec { sink_args: &[2] }),
    ("VirtualProtect", SinkSpec { sink_args: &[1] }),
    // ── Windows — thread / process injection ─────────────────────────────────
    ("CreateThread", SinkSpec { sink_args: &[2] }),
    ("CreateRemoteThread", SinkSpec { sink_args: &[3] }),
    ("CreateRemoteThreadEx", SinkSpec { sink_args: &[3] }),
    ("QueueUserAPC", SinkSpec { sink_args: &[0] }),
    // ── Windows — UI ─────────────────────────────────────────────────────────
    ("SetWindowTextA", SinkSpec { sink_args: &[1] }),
    ("SetWindowTextW", SinkSpec { sink_args: &[1] }),
    ("SetDlgItemTextA", SinkSpec { sink_args: &[2] }),
    ("SetDlgItemTextW", SinkSpec { sink_args: &[2] }),
    ("SetEnvironmentVariableA", SinkSpec { sink_args: &[1] }),
    ("SetEnvironmentVariableW", SinkSpec { sink_args: &[1] }),
    ("putenv", SinkSpec { sink_args: &[0] }),
    // ── Windows — formatted output ────────────────────────────────────────────
    ("wsprintfA", SinkSpec { sink_args: &[1] }),
    ("wsprintfW", SinkSpec { sink_args: &[1] }),
    ("wvsprintfA", SinkSpec { sink_args: &[1] }),
    ("wvsprintfW", SinkSpec { sink_args: &[1] }),
    // ── Windows — wide/multibyte conversion (overflow if size tainted) ────────
    ("MultiByteToWideChar", SinkSpec { sink_args: &[2] }),
    ("WideCharToMultiByte", SinkSpec { sink_args: &[2] }),
    // ── Windows — named pipes / IPC ───────────────────────────────────────────
    ("CreateNamedPipeA", SinkSpec { sink_args: &[0] }),
    ("CreateNamedPipeW", SinkSpec { sink_args: &[0] }),
    ("ConnectNamedPipe", SinkSpec { sink_args: &[0] }),
    // ── Windows — cryptography ────────────────────────────────────────────────
    ("CryptEncrypt", SinkSpec { sink_args: &[4] }),
    ("CryptHashData", SinkSpec { sink_args: &[2] }),
    ("CryptDeriveKey", SinkSpec { sink_args: &[1] }),
    ("CryptStringToBinaryA", SinkSpec { sink_args: &[0] }),
    // ── C++ ──────────────────────────────────────────────────────────────────
    ("std::system", SinkSpec { sink_args: &[0] }),
    ("std::ofstream::open", SinkSpec { sink_args: &[0] }),
    ("std::ifstream::open", SinkSpec { sink_args: &[0] }),
    ("std::fstream::open", SinkSpec { sink_args: &[0] }),
    // ── C++17 std::filesystem (CWE-22 path traversal) ────────────────────────
    ("std::filesystem::remove", SinkSpec { sink_args: &[0] }),
    ("std::filesystem::remove_all", SinkSpec { sink_args: &[0] }),
    ("std::filesystem::copy", SinkSpec { sink_args: &[0, 1] }),
    (
        "std::filesystem::copy_file",
        SinkSpec { sink_args: &[0, 1] },
    ),
    ("std::filesystem::rename", SinkSpec { sink_args: &[0, 1] }),
    (
        "std::filesystem::create_directory",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "std::filesystem::create_directories",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "std::filesystem::create_symlink",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "std::filesystem::create_hard_link",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "std::filesystem::equivalent",
        SinkSpec { sink_args: &[0, 1] },
    ),
    ("std::filesystem::resize_file", SinkSpec { sink_args: &[0] }),
    // ── C++ Boost process execution (CWE-78) ──────────────────────────────────
    ("boost::process::system", SinkSpec { sink_args: &[0] }),
    ("boost::process::child", SinkSpec { sink_args: &[0] }),
    // ── Qt process execution (CWE-78) ────────────────────────────────────────
    ("QProcess::start", SinkSpec { sink_args: &[0] }),
    ("QProcess::startDetached", SinkSpec { sink_args: &[0] }),
    // ── C++20 format strings (CWE-134) ───────────────────────────────────────
    ("std::format", SinkSpec { sink_args: &[0] }),
    ("fmt::format", SinkSpec { sink_args: &[0] }),
    ("fmt::vformat", SinkSpec { sink_args: &[0] }),
    // ── spdlog logging with user-controlled format (CWE-134) ─────────────────
    ("spdlog::info", SinkSpec { sink_args: &[0] }),
    ("spdlog::warn", SinkSpec { sink_args: &[0] }),
    ("spdlog::error", SinkSpec { sink_args: &[0] }),
    ("spdlog::critical", SinkSpec { sink_args: &[0] }),
    ("spdlog::debug", SinkSpec { sink_args: &[0] }),
    // ── C++20 std::vformat / format_to / format_to_n (CWE-134) ──────────────
    ("std::vformat", SinkSpec { sink_args: &[0] }),
    ("vformat", SinkSpec { sink_args: &[0] }),
    ("std::format_to", SinkSpec { sink_args: &[1] }),
    ("format_to", SinkSpec { sink_args: &[1] }),
    ("std::format_to_n", SinkSpec { sink_args: &[1] }),
    ("format_to_n", SinkSpec { sink_args: &[1] }),
    // ── C++23 std::print / std::println (CWE-134) ───────────────────────────
    ("std::print", SinkSpec { sink_args: &[0] }),
    ("std::println", SinkSpec { sink_args: &[0] }),
    // ── C++ info-leak via error streams (CWE-209) ────────────────────────────
    ("std::cerr", SinkSpec { sink_args: &[0] }),
    ("std::clog", SinkSpec { sink_args: &[0] }),
    ("cerr", SinkSpec { sink_args: &[0] }),
    ("clog", SinkSpec { sink_args: &[0] }),
    // ── File open with tainted path (CWE-22 path traversal) ──────────────────
    ("fopen", SinkSpec { sink_args: &[0] }),
    ("freopen", SinkSpec { sink_args: &[0, 1] }),
    ("_wfopen_s", SinkSpec { sink_args: &[0] }),
    ("opendir", SinkSpec { sink_args: &[0] }),
    ("fdopendir", SinkSpec { sink_args: &[0] }),
    ("nftw", SinkSpec { sink_args: &[0] }),
    ("ftw", SinkSpec { sink_args: &[0] }),
    // ── stat family — path traversal / TOCTOU (CWE-22, CWE-367) ─────────────
    ("stat", SinkSpec { sink_args: &[0] }),
    ("lstat", SinkSpec { sink_args: &[0] }),
    ("fstatat", SinkSpec { sink_args: &[1] }),
    ("statx", SinkSpec { sink_args: &[1] }),
    ("_stat", SinkSpec { sink_args: &[0] }),
    ("_stat64", SinkSpec { sink_args: &[0] }),
    // ── POSIX — misc. file / process sinks ───────────────────────────────────
    ("setenv", SinkSpec { sink_args: &[0, 1] }),
    ("execveat", SinkSpec { sink_args: &[1] }),
    ("fanotify_mark", SinkSpec { sink_args: &[4] }),
    ("inotify_add_watch", SinkSpec { sink_args: &[1] }),
    // ── Network — address / DNS injection ────────────────────────────────────
    ("getaddrinfo", SinkSpec { sink_args: &[0, 1] }),
    ("inet_aton", SinkSpec { sink_args: &[0] }),
    ("inet_addr", SinkSpec { sink_args: &[0] }),
    ("gethostbyname2", SinkSpec { sink_args: &[0] }),
    // ── C++ streams — file construction with tainted path ────────────────────
    ("ofstream", SinkSpec { sink_args: &[0] }),
    ("ifstream", SinkSpec { sink_args: &[0] }),
    ("fstream", SinkSpec { sink_args: &[0] }),
    ("std::ofstream", SinkSpec { sink_args: &[0] }),
    ("std::ifstream", SinkSpec { sink_args: &[0] }),
    ("std::fstream", SinkSpec { sink_args: &[0] }),
    ("wofstream", SinkSpec { sink_args: &[0] }),
    ("wifstream", SinkSpec { sink_args: &[0] }),
    ("wfstream", SinkSpec { sink_args: &[0] }),
    // ── C++17 std::filesystem — query sinks (CWE-22 oracle / info-disclosure)
    ("std::filesystem::exists", SinkSpec { sink_args: &[0] }),
    (
        "std::filesystem::is_regular_file",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "std::filesystem::is_directory",
        SinkSpec { sink_args: &[0] },
    ),
    ("std::filesystem::is_symlink", SinkSpec { sink_args: &[0] }),
    (
        "std::filesystem::is_block_file",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "std::filesystem::is_character_file",
        SinkSpec { sink_args: &[0] },
    ),
    ("std::filesystem::is_fifo", SinkSpec { sink_args: &[0] }),
    ("std::filesystem::is_socket", SinkSpec { sink_args: &[0] }),
    ("std::filesystem::is_other", SinkSpec { sink_args: &[0] }),
    ("std::filesystem::is_empty", SinkSpec { sink_args: &[0] }),
    ("std::filesystem::file_size", SinkSpec { sink_args: &[0] }),
    (
        "std::filesystem::hard_link_count",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "std::filesystem::last_write_time",
        SinkSpec { sink_args: &[0] },
    ),
    ("std::filesystem::status", SinkSpec { sink_args: &[0] }),
    (
        "std::filesystem::symlink_status",
        SinkSpec { sink_args: &[0] },
    ),
    ("std::filesystem::absolute", SinkSpec { sink_args: &[0] }),
    ("std::filesystem::canonical", SinkSpec { sink_args: &[0] }),
    (
        "std::filesystem::weakly_canonical",
        SinkSpec { sink_args: &[0] },
    ),
    ("std::filesystem::relative", SinkSpec { sink_args: &[0, 1] }),
    (
        "std::filesystem::proximate",
        SinkSpec { sink_args: &[0, 1] },
    ),
    ("std::filesystem::permissions", SinkSpec { sink_args: &[0] }),
    ("std::filesystem::space", SinkSpec { sink_args: &[0] }),
    (
        "std::filesystem::current_path",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "std::filesystem::temp_directory_path",
        SinkSpec { sink_args: &[0] },
    ),
    ("std::filesystem::path", SinkSpec { sink_args: &[0] }),
    (
        "std::filesystem::copy_symlink",
        SinkSpec { sink_args: &[0, 1] },
    ),
    // ── XML injection (libxml2) ───────────────────────────────────────────────
    ("xmlXPathEval", SinkSpec { sink_args: &[0] }),
    ("xmlXPathEvalExpression", SinkSpec { sink_args: &[0] }),
    ("xmlXPathEvalPredicate", SinkSpec { sink_args: &[1] }),
    ("xmlParseMemory", SinkSpec { sink_args: &[0] }),
    ("xmlReadMemory", SinkSpec { sink_args: &[0] }),
    ("xmlReadFile", SinkSpec { sink_args: &[0] }),
    ("xmlParseFile", SinkSpec { sink_args: &[0] }),
    ("xmlDocGetRootElement", SinkSpec { sink_args: &[0] }),
    ("xmlNewDocNode", SinkSpec { sink_args: &[2] }),
    ("xmlNewChild", SinkSpec { sink_args: &[2, 3] }),
    ("xmlSetProp", SinkSpec { sink_args: &[1, 2] }),
    // ── curl — URL / option injection (CWE-88, SSRF) ─────────────────────────
    ("curl_easy_setopt", SinkSpec { sink_args: &[2] }),
    ("curl_easy_perform", SinkSpec { sink_args: &[0] }),
    ("curl_multi_setopt", SinkSpec { sink_args: &[2] }),
    // ── LDAP — query / entry injection ───────────────────────────────────────
    ("ldap_add_ext", SinkSpec { sink_args: &[1] }),
    ("ldap_add_ext_s", SinkSpec { sink_args: &[1] }),
    ("ldap_modify_ext", SinkSpec { sink_args: &[1] }),
    ("ldap_modify_ext_s", SinkSpec { sink_args: &[1] }),
    ("ldap_search_ext", SinkSpec { sink_args: &[1, 2] }),
    ("ldap_search_ext_s", SinkSpec { sink_args: &[1, 2] }),
    ("ldap_delete_ext", SinkSpec { sink_args: &[1] }),
    ("ldap_delete_ext_s", SinkSpec { sink_args: &[1] }),
    ("ldap_sasl_bind", SinkSpec { sink_args: &[1] }),
    ("ldap_sasl_bind_s", SinkSpec { sink_args: &[1] }),
    ("ldap_bind_s", SinkSpec { sink_args: &[0] }),
    ("ldap_compare_ext_s", SinkSpec { sink_args: &[1, 2] }),
    // ── Regex — ReDoS via user-supplied pattern (CWE-1333) ───────────────────
    ("std::regex", SinkSpec { sink_args: &[0] }),
    ("std::wregex", SinkSpec { sink_args: &[0] }),
    ("std::regex_match", SinkSpec { sink_args: &[2] }),
    ("std::regex_search", SinkSpec { sink_args: &[2] }),
    ("std::regex_replace", SinkSpec { sink_args: &[2] }),
    ("boost::regex", SinkSpec { sink_args: &[0] }),
    ("boost::wregex", SinkSpec { sink_args: &[0] }),
    ("regcomp", SinkSpec { sink_args: &[1] }), // POSIX regex
    // ── Python embedding — code injection ────────────────────────────────────
    ("PyRun_SimpleString", SinkSpec { sink_args: &[0] }),
    ("PyRun_SimpleFile", SinkSpec { sink_args: &[0] }),
    ("PyRun_String", SinkSpec { sink_args: &[0] }),
    ("PyEval_EvalCode", SinkSpec { sink_args: &[0] }),
    ("PyImport_ImportModule", SinkSpec { sink_args: &[0] }),
    // ── Lua embedding — code injection ───────────────────────────────────────
    ("luaL_dostring", SinkSpec { sink_args: &[1] }),
    ("luaL_loadstring", SinkSpec { sink_args: &[1] }),
    ("luaL_loadbuffer", SinkSpec { sink_args: &[1] }),
    ("lua_dostring", SinkSpec { sink_args: &[1] }),
    ("luaL_dofile", SinkSpec { sink_args: &[1] }),
    // ── JavaScript embedding ─────────────────────────────────────────────────
    ("duk_eval_string", SinkSpec { sink_args: &[1] }),
    ("duk_compile_string", SinkSpec { sink_args: &[2] }),
    ("JS_EvaluateScript", SinkSpec { sink_args: &[2] }),
    ("v8::Script::Compile", SinkSpec { sink_args: &[0] }),
    // ── Boost.Asio — network write ────────────────────────────────────────────
    ("boost::asio::write", SinkSpec { sink_args: &[1] }),
    ("boost::asio::async_write", SinkSpec { sink_args: &[1] }),
    ("boost::asio::write_at", SinkSpec { sink_args: &[2] }),
    // ── C++ info-leak via stdout ──────────────────────────────────────────────
    ("std::cout", SinkSpec { sink_args: &[0] }),
    ("std::wcout", SinkSpec { sink_args: &[0] }),
    // ── Memory mapping (write path, CWE-787) ─────────────────────────────────
    ("msync", SinkSpec { sink_args: &[0] }),
    ("munmap", SinkSpec { sink_args: &[0] }),
    // ── Database — additional ORM / driver patterns ───────────────────────────
    ("pqxx::work::exec", SinkSpec { sink_args: &[0] }),
    ("pqxx::connection::prepare", SinkSpec { sink_args: &[0, 1] }),
    ("soci::session::prepare", SinkSpec { sink_args: &[0] }),
    (
        "mongo::DBClientConnection::query",
        SinkSpec { sink_args: &[0, 1] },
    ),
    // ── Crypto — key/IV injection (CWE-320, weak crypto inputs) ─────────────
    ("EVP_DigestInit_ex", SinkSpec { sink_args: &[1] }),
    ("EVP_EncryptInit_ex", SinkSpec { sink_args: &[1] }),
    ("EVP_DecryptInit_ex", SinkSpec { sink_args: &[1] }),
    ("EVP_CipherInit_ex", SinkSpec { sink_args: &[1] }),
    ("SSL_CTX_use_PrivateKey_file", SinkSpec { sink_args: &[1] }),
    ("SSL_CTX_use_certificate_file", SinkSpec { sink_args: &[1] }),
    (
        "SSL_CTX_load_verify_locations",
        SinkSpec { sink_args: &[1] },
    ),
    // ── Windows — additional COM / script execution ───────────────────────────
    ("CoCreateInstance", SinkSpec { sink_args: &[0] }),
    ("IDispatch::Invoke", SinkSpec { sink_args: &[0] }),
];

// =============================================================================
// Taint propagators
// =============================================================================

/// Functions that propagate taint from source arguments to a destination.
///
/// `PropagatorSpec::dst`:
///   - `-1` = return value is the tainted destination.
///   - `0..` = argument index that receives tainted data.
///
/// `PropagatorSpec::src`:
///   - `-1` = "all remaining arguments after `dst`" (variadic format args).
///     Only meaningful when `dst >= 0`.
///   - `0..` = specific source argument index.
pub const TAINT_PROPAGATORS: &[(&str, PropagatorSpec)] = &[
    // ── Formatted output: format + variadic args → output buffer ─────────────
    (
        "sprintf",
        PropagatorSpec {
            dst: 0,
            src: &[1, -1],
        },
    ),
    (
        "snprintf",
        PropagatorSpec {
            dst: 0,
            src: &[2, -1],
        },
    ),
    (
        "swprintf",
        PropagatorSpec {
            dst: 0,
            src: &[2, -1],
        },
    ),
    (
        "fprintf",
        PropagatorSpec {
            dst: 1,
            src: &[1, -1],
        },
    ), // dst is stream arg 1
    (
        "asprintf",
        PropagatorSpec {
            dst: 0,
            src: &[1, -1],
        },
    ), // arg0 = char**
    ("vasprintf", PropagatorSpec { dst: 0, src: &[1] }),
    // ── Formatted output: format → stdout/stream (return value is char count) ─
    // printf/fprintf/etc. don't write to a buffer arg; return value propagation
    // is handled via the STDLIB_TAINT_SOURCES / abstract_interp lhs path.
    // ── Memory copy: src(arg1) → dst(arg0) ───────────────────────────────────
    ("memcpy", PropagatorSpec { dst: 0, src: &[1] }),
    ("memmove", PropagatorSpec { dst: 0, src: &[1] }),
    ("mempcpy", PropagatorSpec { dst: 0, src: &[1] }),
    ("bcopy", PropagatorSpec { dst: 1, src: &[0] }), // bcopy(src,dst,n)
    ("wmemcpy", PropagatorSpec { dst: 0, src: &[1] }),
    ("wmemmove", PropagatorSpec { dst: 0, src: &[1] }),
    // ── Memory search: haystack → return value ────────────────────────────────
    ("memchr", PropagatorSpec { dst: -1, src: &[0] }),
    ("wmemchr", PropagatorSpec { dst: -1, src: &[0] }),
    // ── String copy: src(arg1) → dst(arg0) ───────────────────────────────────
    ("strcpy", PropagatorSpec { dst: 0, src: &[1] }),
    ("strncpy", PropagatorSpec { dst: 0, src: &[1] }),
    ("strcat", PropagatorSpec { dst: 0, src: &[1] }),
    ("strncat", PropagatorSpec { dst: 0, src: &[1] }),
    ("stpcpy", PropagatorSpec { dst: 0, src: &[1] }),
    ("stpncpy", PropagatorSpec { dst: 0, src: &[1] }),
    // ── String copy → return value ────────────────────────────────────────────
    ("strdup", PropagatorSpec { dst: -1, src: &[0] }),
    ("strndup", PropagatorSpec { dst: -1, src: &[0] }),
    ("wcsdup", PropagatorSpec { dst: -1, src: &[0] }),
    // ── String search → return value (pointer into haystack) ─────────────────
    ("strchr", PropagatorSpec { dst: -1, src: &[0] }),
    ("strrchr", PropagatorSpec { dst: -1, src: &[0] }),
    ("strstr", PropagatorSpec { dst: -1, src: &[0] }),
    ("strpbrk", PropagatorSpec { dst: -1, src: &[0] }),
    ("wcschr", PropagatorSpec { dst: -1, src: &[0] }),
    ("wcsstr", PropagatorSpec { dst: -1, src: &[0] }),
    // ── String tokenisation → return value ───────────────────────────────────
    ("strtok", PropagatorSpec { dst: -1, src: &[0] }),
    ("strtok_r", PropagatorSpec { dst: -1, src: &[0] }),
    ("strsep", PropagatorSpec { dst: -1, src: &[0] }),
    // ── String length: input → tainted length (for CWE-190/131) ──────────────
    ("strlen", PropagatorSpec { dst: -1, src: &[0] }),
    ("wcslen", PropagatorSpec { dst: -1, src: &[0] }),
    ("strnlen", PropagatorSpec { dst: -1, src: &[0] }),
    // ── Wide-character string copy ────────────────────────────────────────────
    ("wcscpy", PropagatorSpec { dst: 0, src: &[1] }),
    ("wcsncpy", PropagatorSpec { dst: 0, src: &[1] }),
    ("wcscat", PropagatorSpec { dst: 0, src: &[1] }),
    ("wcsncat", PropagatorSpec { dst: 0, src: &[1] }),
    // ── String-to-number conversions: tainted string → tainted number ─────────
    ("strtol", PropagatorSpec { dst: -1, src: &[0] }),
    ("strtoul", PropagatorSpec { dst: -1, src: &[0] }),
    ("strtoll", PropagatorSpec { dst: -1, src: &[0] }),
    ("strtoull", PropagatorSpec { dst: -1, src: &[0] }),
    ("strtof", PropagatorSpec { dst: -1, src: &[0] }),
    ("strtod", PropagatorSpec { dst: -1, src: &[0] }),
    ("strtold", PropagatorSpec { dst: -1, src: &[0] }),
    ("strtoimax", PropagatorSpec { dst: -1, src: &[0] }),
    ("strtoumax", PropagatorSpec { dst: -1, src: &[0] }),
    ("atoi", PropagatorSpec { dst: -1, src: &[0] }),
    ("atol", PropagatorSpec { dst: -1, src: &[0] }),
    ("atoll", PropagatorSpec { dst: -1, src: &[0] }),
    ("atof", PropagatorSpec { dst: -1, src: &[0] }),
    // ── va_list propagation ───────────────────────────────────────────────────
    ("va_start", PropagatorSpec { dst: 0, src: &[1] }),
    ("va_copy", PropagatorSpec { dst: 0, src: &[1] }),
    ("va_arg", PropagatorSpec { dst: -1, src: &[0] }),
    // ── SQL prepared statement: sql string → stmt handle ─────────────────────
    ("sqlite3_prepare", PropagatorSpec { dst: 3, src: &[1] }),
    ("sqlite3_prepare_v2", PropagatorSpec { dst: 3, src: &[1] }),
    ("sqlite3_prepare_v3", PropagatorSpec { dst: 3, src: &[1] }),
    // ── GLib string helpers ───────────────────────────────────────────────────
    ("g_strlcpy", PropagatorSpec { dst: 0, src: &[1] }),
    ("g_strlcat", PropagatorSpec { dst: 0, src: &[1] }),
    ("g_strdup", PropagatorSpec { dst: -1, src: &[0] }),
    ("g_strndup", PropagatorSpec { dst: -1, src: &[0] }),
    (
        "g_strdup_printf",
        PropagatorSpec {
            dst: -1,
            src: &[0, -1],
        },
    ),
    // ── Windows — string copy ─────────────────────────────────────────────────
    ("lstrcpyA", PropagatorSpec { dst: 0, src: &[1] }),
    ("lstrcpyW", PropagatorSpec { dst: 0, src: &[1] }),
    ("lstrcatA", PropagatorSpec { dst: 0, src: &[1] }),
    ("lstrcatW", PropagatorSpec { dst: 0, src: &[1] }),
    ("lstrcpynA", PropagatorSpec { dst: 0, src: &[1] }),
    ("lstrcpynW", PropagatorSpec { dst: 0, src: &[1] }),
    // ── Windows — memory copy ─────────────────────────────────────────────────
    ("CopyMemory", PropagatorSpec { dst: 0, src: &[1] }),
    ("MoveMemory", PropagatorSpec { dst: 0, src: &[1] }),
    ("RtlCopyMemory", PropagatorSpec { dst: 0, src: &[1] }),
    ("RtlMoveMemory", PropagatorSpec { dst: 0, src: &[1] }),
    // ── Windows — file read ───────────────────────────────────────────────────
    ("ReadFile", PropagatorSpec { dst: 1, src: &[0] }),
    ("ReadFileEx", PropagatorSpec { dst: 1, src: &[0] }),
    ("NtReadFile", PropagatorSpec { dst: 5, src: &[0] }),
    ("ZwReadFile", PropagatorSpec { dst: 5, src: &[0] }),
    // ── Windows — network receive ─────────────────────────────────────────────
    ("WSARecv", PropagatorSpec { dst: 1, src: &[0] }),
    ("WSARecvFrom", PropagatorSpec { dst: 1, src: &[0] }),
    ("WSARecvMsg", PropagatorSpec { dst: 1, src: &[0] }),
    // ── Windows — UI text retrieval ───────────────────────────────────────────
    ("GetWindowTextA", PropagatorSpec { dst: 1, src: &[0] }),
    ("GetWindowTextW", PropagatorSpec { dst: 1, src: &[0] }),
    ("GetWindowText", PropagatorSpec { dst: 1, src: &[0] }),
    ("GetDlgItemTextA", PropagatorSpec { dst: 2, src: &[0] }),
    ("GetDlgItemTextW", PropagatorSpec { dst: 2, src: &[0] }),
    // ── Windows — environment ─────────────────────────────────────────────────
    (
        "GetEnvironmentVariableA",
        PropagatorSpec { dst: 1, src: &[0] },
    ),
    (
        "GetEnvironmentVariableW",
        PropagatorSpec { dst: 1, src: &[0] },
    ),
    (
        "ExpandEnvironmentStringsA",
        PropagatorSpec { dst: 1, src: &[0] },
    ),
    (
        "ExpandEnvironmentStringsW",
        PropagatorSpec { dst: 1, src: &[0] },
    ),
    // ── Windows — user/machine names ──────────────────────────────────────────
    ("GetUserNameA", PropagatorSpec { dst: 0, src: &[] }),
    ("GetUserNameW", PropagatorSpec { dst: 0, src: &[] }),
    ("GetUserNameExA", PropagatorSpec { dst: 1, src: &[0] }),
    ("GetUserNameExW", PropagatorSpec { dst: 1, src: &[0] }),
    ("GetComputerNameA", PropagatorSpec { dst: 0, src: &[] }),
    ("GetComputerNameW", PropagatorSpec { dst: 0, src: &[] }),
    ("GetComputerNameExA", PropagatorSpec { dst: 1, src: &[0] }),
    ("GetComputerNameExW", PropagatorSpec { dst: 1, src: &[0] }),
    // ── Windows — registry ───────────────────────────────────────────────────
    ("RegQueryValueExA", PropagatorSpec { dst: 4, src: &[0] }),
    ("RegQueryValueExW", PropagatorSpec { dst: 4, src: &[0] }),
    ("RegGetValueA", PropagatorSpec { dst: 6, src: &[0] }),
    ("RegGetValueW", PropagatorSpec { dst: 6, src: &[0] }),
    // ── Windows — path ───────────────────────────────────────────────────────
    ("GetTempPathA", PropagatorSpec { dst: 1, src: &[] }),
    ("GetTempPathW", PropagatorSpec { dst: 1, src: &[] }),
    ("GetTempFileNameA", PropagatorSpec { dst: 3, src: &[0] }),
    ("GetTempFileNameW", PropagatorSpec { dst: 3, src: &[0] }),
    ("GetModuleFileNameA", PropagatorSpec { dst: 1, src: &[0] }),
    ("GetModuleFileNameW", PropagatorSpec { dst: 1, src: &[0] }),
    (
        "GetModuleFileNameExA",
        PropagatorSpec {
            dst: 2,
            src: &[0, 1],
        },
    ),
    (
        "GetModuleFileNameExW",
        PropagatorSpec {
            dst: 2,
            src: &[0, 1],
        },
    ),
    ("GetFullPathNameA", PropagatorSpec { dst: 2, src: &[0] }),
    ("GetFullPathNameW", PropagatorSpec { dst: 2, src: &[0] }),
    ("GetCurrentDirectoryA", PropagatorSpec { dst: 1, src: &[] }),
    ("GetCurrentDirectoryW", PropagatorSpec { dst: 1, src: &[] }),
    // ── Windows — cryptography ────────────────────────────────────────────────
    ("CryptDecrypt", PropagatorSpec { dst: 4, src: &[1] }),
    ("CryptDecryptMessage", PropagatorSpec { dst: 4, src: &[0] }),
    // ── Windows — wide/multibyte conversion ──────────────────────────────────
    ("MultiByteToWideChar", PropagatorSpec { dst: 4, src: &[2] }),
    ("WideCharToMultiByte", PropagatorSpec { dst: 4, src: &[2] }),
    // ── Windows — formatted output ────────────────────────────────────────────
    (
        "wsprintfA",
        PropagatorSpec {
            dst: 0,
            src: &[1, -1],
        },
    ),
    (
        "wsprintfW",
        PropagatorSpec {
            dst: 0,
            src: &[1, -1],
        },
    ),
    // ── C++ std::string / std::wstring ────────────────────────────────────────
    (
        "append",
        PropagatorSpec {
            dst: -1,
            src: &[0, 1],
        },
    ), // this.append(src) → return
    (
        "assign",
        PropagatorSpec {
            dst: -1,
            src: &[0, 1],
        },
    ),
    (
        "insert",
        PropagatorSpec {
            dst: -1,
            src: &[0, 2],
        },
    ),
    (
        "replace",
        PropagatorSpec {
            dst: -1,
            src: &[0, 3],
        },
    ),
    ("substr", PropagatorSpec { dst: -1, src: &[0] }),
    ("c_str", PropagatorSpec { dst: -1, src: &[0] }),
    ("data", PropagatorSpec { dst: -1, src: &[0] }),
    ("to_string", PropagatorSpec { dst: -1, src: &[0] }),
    // ── C++ std::move / std::forward (ownership transfer) ────────────────────
    ("std::move", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::forward", PropagatorSpec { dst: -1, src: &[0] }),
    ("move", PropagatorSpec { dst: -1, src: &[0] }),
    ("forward", PropagatorSpec { dst: -1, src: &[0] }),
    // ── C++ std::string_view / std::span ─────────────────────────────────────
    ("string_view", PropagatorSpec { dst: -1, src: &[0] }),
    // ── C++ std algorithms ────────────────────────────────────────────────────
    ("std::copy", PropagatorSpec { dst: 2, src: &[0] }),
    ("std::transform", PropagatorSpec { dst: 3, src: &[0] }),
    // ── C++ container accessors ───────────────────────────────────────────────
    ("at", PropagatorSpec { dst: -1, src: &[0] }),
    // ── C++ smart pointer dereference ─────────────────────────────────────────
    ("get", PropagatorSpec { dst: -1, src: &[0] }),
    ("lock", PropagatorSpec { dst: -1, src: &[0] }),
    // ── C++ Boost ─────────────────────────────────────────────────────────────
    ("boost::lexical_cast", PropagatorSpec { dst: -1, src: &[0] }),
    (
        "boost::algorithm::join",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "boost::algorithm::replace_all",
        PropagatorSpec {
            dst: 0,
            src: &[1, 2],
        },
    ),
    // ── C++ exception ─────────────────────────────────────────────────────────
    ("what", PropagatorSpec { dst: -1, src: &[0] }),
    // ── C++ std::string operators ─────────────────────────────────────────────
    (
        "operator+",
        PropagatorSpec {
            dst: -1,
            src: &[0, 1],
        },
    ),
    (
        "operator+=",
        PropagatorSpec {
            dst: -1,
            src: &[0, 1],
        },
    ),
    // ── C++ ostringstream chain: << returns *this ─────────────────────────────
    (
        "operator<<",
        PropagatorSpec {
            dst: -1,
            src: &[0, 1],
        },
    ),
    // ── C++ ostringstream::str() → return ────────────────────────────────────
    ("str", PropagatorSpec { dst: -1, src: &[0] }),
    // ── C++ container accessors ───────────────────────────────────────────────
    ("front", PropagatorSpec { dst: -1, src: &[0] }),
    ("back", PropagatorSpec { dst: -1, src: &[0] }),
    ("top", PropagatorSpec { dst: -1, src: &[0] }),
    ("operator[]", PropagatorSpec { dst: -1, src: &[0] }),
    ("push_back", PropagatorSpec { dst: 0, src: &[1] }),
    ("emplace_back", PropagatorSpec { dst: 0, src: &[1] }),
    ("push", PropagatorSpec { dst: 0, src: &[1] }),
    // ── C++ std::optional / std::expected ────────────────────────────────────
    ("value", PropagatorSpec { dst: -1, src: &[0] }),
    ("value_or", PropagatorSpec { dst: -1, src: &[0] }),
    // ── C++ std::variant / std::tuple helpers ────────────────────────────────
    ("std::get", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::tie", PropagatorSpec { dst: -1, src: &[0] }),
    (
        "std::make_pair",
        PropagatorSpec {
            dst: -1,
            src: &[0, 1],
        },
    ),
    ("std::make_tuple", PropagatorSpec { dst: -1, src: &[0] }),
    (
        "make_pair",
        PropagatorSpec {
            dst: -1,
            src: &[0, 1],
        },
    ),
    ("make_tuple", PropagatorSpec { dst: -1, src: &[0] }),
    // ── C++ std::span / std::string_view narrowing ────────────────────────────
    ("subspan", PropagatorSpec { dst: -1, src: &[0] }),
    ("first", PropagatorSpec { dst: -1, src: &[0] }),
    ("last", PropagatorSpec { dst: -1, src: &[0] }),
    // ── C++ std::any_cast / std::bit_cast ────────────────────────────────────
    ("std::any_cast", PropagatorSpec { dst: -1, src: &[0] }),
    ("any_cast", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::bit_cast", PropagatorSpec { dst: -1, src: &[0] }),
    ("bit_cast", PropagatorSpec { dst: -1, src: &[0] }),
    // ── C++ std::ranges ───────────────────────────────────────────────────────
    ("std::ranges::copy", PropagatorSpec { dst: 2, src: &[0] }),
    (
        "std::ranges::transform",
        PropagatorSpec { dst: 3, src: &[0] },
    ),
    ("std::ranges::fill", PropagatorSpec { dst: 0, src: &[1] }),
    ("std::ranges::copy_if", PropagatorSpec { dst: 2, src: &[0] }),
    ("std::copy_if", PropagatorSpec { dst: 2, src: &[0] }),
    // ── C++20 std::format propagation (format string + args → return) ─────────
    // Note: std::format is ALSO a sink for CWE-134; it's both a propagator and sink.
    (
        "std::format",
        PropagatorSpec {
            dst: -1,
            src: &[0, -1],
        },
    ),
    (
        "format",
        PropagatorSpec {
            dst: -1,
            src: &[0, -1],
        },
    ),
    // ── C++ container lookup: find/rfind/count return iterator or position ───
    // The returned iterator/pos carries taint from the container being searched.
    ("find", PropagatorSpec { dst: -1, src: &[0] }),
    ("rfind", PropagatorSpec { dst: -1, src: &[0] }),
    ("count", PropagatorSpec { dst: -1, src: &[0] }),
    // ── C++ container mutation: erase / emplace family ────────────────────────
    ("erase", PropagatorSpec { dst: 0, src: &[0] }),
    ("emplace", PropagatorSpec { dst: 0, src: &[1] }),
    ("emplace_front", PropagatorSpec { dst: 0, src: &[1] }),
    ("emplace_hint", PropagatorSpec { dst: 0, src: &[2] }),
    // ── C++ ordered container lookup iterators ────────────────────────────────
    ("lower_bound", PropagatorSpec { dst: -1, src: &[0] }),
    ("upper_bound", PropagatorSpec { dst: -1, src: &[0] }),
    ("equal_range", PropagatorSpec { dst: -1, src: &[0] }),
    // ── std::deque / std::list front mutations ────────────────────────────────
    ("push_front", PropagatorSpec { dst: 0, src: &[1] }),
    ("pop_front", PropagatorSpec { dst: 0, src: &[0] }),
    ("pop_back", PropagatorSpec { dst: 0, src: &[0] }),
    // ── std::list / std::forward_list structural operations ───────────────────
    ("splice", PropagatorSpec { dst: 0, src: &[2] }),
    ("merge", PropagatorSpec { dst: 0, src: &[1] }),
    // ── std::span / std::array iterators ─────────────────────────────────────
    ("begin", PropagatorSpec { dst: -1, src: &[0] }),
    ("end", PropagatorSpec { dst: -1, src: &[0] }),
    ("cbegin", PropagatorSpec { dst: -1, src: &[0] }),
    ("cend", PropagatorSpec { dst: -1, src: &[0] }),
    ("rbegin", PropagatorSpec { dst: -1, src: &[0] }),
    ("rend", PropagatorSpec { dst: -1, src: &[0] }),
    // ── C++20/23 ranges::to and std::to_array ─────────────────────────────────
    ("to_array", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::ranges::to", PropagatorSpec { dst: -1, src: &[0] }),
    // ── std::function invocation propagates captured taint ───────────────────
    ("operator()", PropagatorSpec { dst: -1, src: &[0] }),
    // ── Exception re-throw propagation ───────────────────────────────────────
    ("rethrow_exception", PropagatorSpec { dst: -1, src: &[0] }),
    (
        "std::rethrow_exception",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    // ── std::string / std::wstring qualified method forms ────────────────────
    ("std::to_string", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::to_wstring", PropagatorSpec { dst: -1, src: &[0] }),
    // std::string_view construction from a string (takes a reference)
    ("std::string_view", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::wstring_view", PropagatorSpec { dst: -1, src: &[0] }),
    // ── std::string search → tainted offset/position ─────────────────────────
    // Returned position is derived from the tainted string content; can be
    // used as an array index (CWE-125/787) or loop bound (CWE-190).
    ("find_first_of", PropagatorSpec { dst: -1, src: &[0] }),
    ("find_last_of", PropagatorSpec { dst: -1, src: &[0] }),
    ("find_first_not_of", PropagatorSpec { dst: -1, src: &[0] }),
    ("find_last_not_of", PropagatorSpec { dst: -1, src: &[0] }),
    // ── std::string copy to raw buffer ────────────────────────────────────────
    // string::copy(dest, count, pos) → param 0 (dest) tainted by param 0 (this).
    // The engine uses dst=0 / src=0 convention: receiver is implicit arg 0.
    ("copy", PropagatorSpec { dst: 0, src: &[0] }),
    // ── std::string_view narrowing operations ─────────────────────────────────
    ("remove_prefix", PropagatorSpec { dst: -1, src: &[0] }),
    ("remove_suffix", PropagatorSpec { dst: -1, src: &[0] }),
    // ── std::string → number conversion (tainted string → tainted integer) ────
    // These are also listed in STDLIB_TAINT_SOURCES; having them here ensures
    // taint propagates through the call when the result is assigned.
    ("stoi", PropagatorSpec { dst: -1, src: &[0] }),
    ("stol", PropagatorSpec { dst: -1, src: &[0] }),
    ("stoll", PropagatorSpec { dst: -1, src: &[0] }),
    ("stoul", PropagatorSpec { dst: -1, src: &[0] }),
    ("stoull", PropagatorSpec { dst: -1, src: &[0] }),
    ("stof", PropagatorSpec { dst: -1, src: &[0] }),
    ("stod", PropagatorSpec { dst: -1, src: &[0] }),
    ("stold", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::stoi", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::stol", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::stoll", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::stoul", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::stoull", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::stof", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::stod", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::stold", PropagatorSpec { dst: -1, src: &[0] }),
    // ── Container — node handle / extract (C++17) ────────────────────────────
    // extract() removes an element from the container and returns a node handle;
    // the tainted value travels with the handle.
    ("extract", PropagatorSpec { dst: -1, src: &[0] }),
    // ── Container — upsert / try_emplace (map / unordered_map) ──────────────
    (
        "insert_or_assign",
        PropagatorSpec {
            dst: 0,
            src: &[1, 2],
        },
    ),
    ("try_emplace", PropagatorSpec { dst: 0, src: &[1] }),
    // ── Smart pointer release ─────────────────────────────────────────────────
    // unique_ptr::release() returns the raw pointer (which is tainted if
    // the unique_ptr was constructed from tainted data).
    ("release", PropagatorSpec { dst: -1, src: &[0] }),
    // ── C++17 std::optional / std::expected monadic chains (C++23) ───────────
    ("and_then", PropagatorSpec { dst: -1, src: &[0] }),
    ("or_else", PropagatorSpec { dst: -1, src: &[0] }),
    // ── std::variant access ───────────────────────────────────────────────────
    ("std::get_if", PropagatorSpec { dst: -1, src: &[0] }),
    ("get_if", PropagatorSpec { dst: -1, src: &[0] }),
    // ── std::future / std::promise ────────────────────────────────────────────
    // future::get() blocks and returns the stored value; if the promise was
    // fulfilled with tainted data, the returned value carries that taint.
    ("get_future", PropagatorSpec { dst: -1, src: &[0] }),
    // ── std::algorithm copy family — output range carries input taint ─────────
    ("std::copy_n", PropagatorSpec { dst: 2, src: &[0] }),
    ("std::move_backward", PropagatorSpec { dst: 2, src: &[0] }),
    ("std::reverse_copy", PropagatorSpec { dst: 2, src: &[0] }),
    ("std::rotate_copy", PropagatorSpec { dst: 3, src: &[0] }),
    ("std::remove_copy", PropagatorSpec { dst: 2, src: &[0] }),
    ("std::remove_copy_if", PropagatorSpec { dst: 2, src: &[0] }),
    ("std::unique_copy", PropagatorSpec { dst: 2, src: &[0] }),
    ("std::replace_copy", PropagatorSpec { dst: 2, src: &[0] }),
    ("std::replace_copy_if", PropagatorSpec { dst: 2, src: &[0] }),
    (
        "std::partial_sort_copy",
        PropagatorSpec { dst: 2, src: &[0] },
    ),
    ("std::sample", PropagatorSpec { dst: 2, src: &[0] }),
    // ── std::algorithm set operations — both input ranges propagate ───────────
    (
        "std::merge",
        PropagatorSpec {
            dst: 4,
            src: &[0, 2],
        },
    ),
    (
        "std::set_union",
        PropagatorSpec {
            dst: 4,
            src: &[0, 2],
        },
    ),
    (
        "std::set_intersection",
        PropagatorSpec {
            dst: 4,
            src: &[0, 2],
        },
    ),
    (
        "std::set_difference",
        PropagatorSpec {
            dst: 4,
            src: &[0, 2],
        },
    ),
    (
        "std::set_symmetric_difference",
        PropagatorSpec {
            dst: 4,
            src: &[0, 2],
        },
    ),
    (
        "std::inplace_merge",
        PropagatorSpec {
            dst: 0,
            src: &[0, 1],
        },
    ),
    // ── std::algorithm partition copy ─────────────────────────────────────────
    ("std::partition_copy", PropagatorSpec { dst: 2, src: &[0] }),
    // ── std::numeric — aggregate propagators ──────────────────────────────────
    ("std::accumulate", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::reduce", PropagatorSpec { dst: -1, src: &[0] }),
    (
        "std::transform_reduce",
        PropagatorSpec {
            dst: -1,
            src: &[0, 2],
        },
    ),
    ("std::partial_sum", PropagatorSpec { dst: 2, src: &[0] }),
    (
        "std::adjacent_difference",
        PropagatorSpec { dst: 2, src: &[0] },
    ),
    ("std::inclusive_scan", PropagatorSpec { dst: 2, src: &[0] }),
    ("std::exclusive_scan", PropagatorSpec { dst: 2, src: &[0] }),
    (
        "std::transform_inclusive_scan",
        PropagatorSpec { dst: 2, src: &[0] },
    ),
    (
        "std::transform_exclusive_scan",
        PropagatorSpec { dst: 2, src: &[0] },
    ),
    (
        "std::inner_product",
        PropagatorSpec {
            dst: -1,
            src: &[0, 2],
        },
    ),
    // ── std::ranges algorithm forms (C++20) ───────────────────────────────────
    ("std::ranges::copy_n", PropagatorSpec { dst: 2, src: &[0] }),
    (
        "std::ranges::move_backward",
        PropagatorSpec { dst: 2, src: &[0] },
    ),
    (
        "std::ranges::reverse_copy",
        PropagatorSpec { dst: 2, src: &[0] },
    ),
    (
        "std::ranges::rotate_copy",
        PropagatorSpec { dst: 3, src: &[0] },
    ),
    (
        "std::ranges::remove_copy",
        PropagatorSpec { dst: 2, src: &[0] },
    ),
    (
        "std::ranges::remove_copy_if",
        PropagatorSpec { dst: 2, src: &[0] },
    ),
    (
        "std::ranges::unique_copy",
        PropagatorSpec { dst: 2, src: &[0] },
    ),
    (
        "std::ranges::replace_copy",
        PropagatorSpec { dst: 2, src: &[0] },
    ),
    (
        "std::ranges::replace_copy_if",
        PropagatorSpec { dst: 2, src: &[0] },
    ),
    (
        "std::ranges::partial_sort_copy",
        PropagatorSpec { dst: 2, src: &[0] },
    ),
    ("std::ranges::sample", PropagatorSpec { dst: 2, src: &[0] }),
    (
        "std::ranges::merge",
        PropagatorSpec {
            dst: 4,
            src: &[0, 2],
        },
    ),
    (
        "std::ranges::set_union",
        PropagatorSpec {
            dst: 4,
            src: &[0, 2],
        },
    ),
    (
        "std::ranges::set_intersection",
        PropagatorSpec {
            dst: 4,
            src: &[0, 2],
        },
    ),
    (
        "std::ranges::set_difference",
        PropagatorSpec {
            dst: 4,
            src: &[0, 2],
        },
    ),
    (
        "std::ranges::set_symmetric_difference",
        PropagatorSpec {
            dst: 4,
            src: &[0, 2],
        },
    ),
    (
        "std::ranges::inplace_merge",
        PropagatorSpec {
            dst: 0,
            src: &[0, 1],
        },
    ),
    (
        "std::ranges::partition_copy",
        PropagatorSpec { dst: 2, src: &[0] },
    ),
    // ── std::views / range adaptors (C++20/23) — lazy propagators ────────────
    // Range adaptors are lazy; the underlying range carries taint.
    ("std::views::filter", PropagatorSpec { dst: -1, src: &[0] }),
    (
        "std::views::transform",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    ("std::views::take", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::views::drop", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::views::reverse", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::views::join", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::views::split", PropagatorSpec { dst: -1, src: &[0] }),
    (
        "std::views::take_while",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "std::views::drop_while",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "std::views::elements",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    ("std::views::values", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::views::keys", PropagatorSpec { dst: -1, src: &[0] }),
    (
        "std::views::enumerate",
        PropagatorSpec { dst: -1, src: &[0] },
    ), // C++23
    ("std::views::zip", PropagatorSpec { dst: -1, src: &[0] }), // C++23
    ("std::views::chunk", PropagatorSpec { dst: -1, src: &[0] }), // C++23
    ("std::views::stride", PropagatorSpec { dst: -1, src: &[0] }), // C++23
    ("std::views::slide", PropagatorSpec { dst: -1, src: &[0] }), // C++23
    (
        "std::views::chunk_by",
        PropagatorSpec { dst: -1, src: &[0] },
    ), // C++23
    (
        "std::views::as_rvalue",
        PropagatorSpec { dst: -1, src: &[0] },
    ), // C++23
    (
        "std::views::as_const",
        PropagatorSpec { dst: -1, src: &[0] },
    ), // C++23
    (
        "std::views::concat",
        PropagatorSpec {
            dst: -1,
            src: &[0, 1],
        },
    ), // C++26
    // ── std::span operations ──────────────────────────────────────────────────
    ("as_bytes", PropagatorSpec { dst: -1, src: &[0] }),
    ("as_writable_bytes", PropagatorSpec { dst: -1, src: &[0] }),
    // ── std::string_view / std::span iteration helpers ────────────────────────
    ("std::as_bytes", PropagatorSpec { dst: -1, src: &[0] }),
    (
        "std::as_writable_bytes",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    // ── std::mdspan (C++23) accessors ─────────────────────────────────────────
    ("std::mdspan", PropagatorSpec { dst: -1, src: &[0] }),
    ("mdspan", PropagatorSpec { dst: -1, src: &[0] }),
    // ── Boost string algorithms ───────────────────────────────────────────────
    (
        "boost::algorithm::to_lower_copy",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "boost::algorithm::to_upper_copy",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "boost::algorithm::trim_copy",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "boost::algorithm::trim_left_copy",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "boost::algorithm::trim_right_copy",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "boost::algorithm::erase_all_copy",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "boost::algorithm::split",
        PropagatorSpec { dst: 0, src: &[1] },
    ),
    (
        "boost::algorithm::find",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "boost::algorithm::contains",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "boost::algorithm::starts_with",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "boost::algorithm::ends_with",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "boost::algorithm::replace_all_copy",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    // ── fmt library (format string propagation) ───────────────────────────────
    (
        "fmt::format",
        PropagatorSpec {
            dst: -1,
            src: &[0, -1],
        },
    ),
    ("fmt::format_to", PropagatorSpec { dst: 1, src: &[0] }),
    ("fmt::format_to_n", PropagatorSpec { dst: 1, src: &[0] }),
    ("fmt::vformat", PropagatorSpec { dst: -1, src: &[0] }),
    // ── std::from_chars (binary → value propagation) ─────────────────────────
    ("std::from_chars", PropagatorSpec { dst: 2, src: &[0] }),
    ("from_chars", PropagatorSpec { dst: 2, src: &[0] }),
    // ── std::to_chars (value → text propagation) ─────────────────────────────
    ("std::to_chars", PropagatorSpec { dst: 0, src: &[2] }),
    ("to_chars", PropagatorSpec { dst: 0, src: &[2] }),
    // ── std::byte / std::bit_* helpers (C++20) ────────────────────────────────
    ("std::to_integer", PropagatorSpec { dst: -1, src: &[0] }),
    ("to_integer", PropagatorSpec { dst: -1, src: &[0] }),
    // ── Filesystem path composition ───────────────────────────────────────────
    (
        "std::filesystem::path::string",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "std::filesystem::path::wstring",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "std::filesystem::path::u8string",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "std::filesystem::path::generic_string",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "std::filesystem::path::filename",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "std::filesystem::path::stem",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "std::filesystem::path::extension",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "std::filesystem::path::parent_path",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "std::filesystem::path::root_name",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "std::filesystem::path::root_path",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "std::filesystem::path::relative_path",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    ("filename", PropagatorSpec { dst: -1, src: &[0] }),
    ("stem", PropagatorSpec { dst: -1, src: &[0] }),
    ("extension", PropagatorSpec { dst: -1, src: &[0] }),
    ("parent_path", PropagatorSpec { dst: -1, src: &[0] }),
    ("root_name", PropagatorSpec { dst: -1, src: &[0] }),
    ("root_path", PropagatorSpec { dst: -1, src: &[0] }),
    ("relative_path", PropagatorSpec { dst: -1, src: &[0] }),
    // ── std::regex_match / search result ─────────────────────────────────────
    ("std::smatch", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::wsmatch", PropagatorSpec { dst: -1, src: &[0] }),
    // ── C++ cast operators: taint passes through all cast forms ──────────────
    // Named cast: dynamic_cast<T>(expr), static_cast<T>(expr), etc.
    // call_name extracts the function-like prefix, e.g. "dynamic_cast".
    ("dynamic_cast", PropagatorSpec { dst: -1, src: &[0] }),
    ("static_cast", PropagatorSpec { dst: -1, src: &[0] }),
    ("reinterpret_cast", PropagatorSpec { dst: -1, src: &[0] }),
    ("const_cast", PropagatorSpec { dst: -1, src: &[0] }),
    // std::launder (C++17): returns pointer to same object — taint passes through
    ("std::launder", PropagatorSpec { dst: -1, src: &[0] }),
    ("launder", PropagatorSpec { dst: -1, src: &[0] }),
    // ── C++ polymorphism helpers ──────────────────────────────────────────────
    // std::addressof: returns address of object — object taint propagates
    ("std::addressof", PropagatorSpec { dst: -1, src: &[0] }),
    ("addressof", PropagatorSpec { dst: -1, src: &[0] }),
    // ── Object lifetime / RAII helpers ────────────────────────────────────────
    // std::exchange: returns old value of obj — taint from old value propagates
    ("std::exchange", PropagatorSpec { dst: -1, src: &[0] }),
    ("exchange", PropagatorSpec { dst: -1, src: &[0] }),
    // std::swap: exchanges two values — both become tainted if either was tainted
    ("std::swap", PropagatorSpec { dst: 0, src: &[1] }),
    ("swap", PropagatorSpec { dst: 0, src: &[1] }),
];

// =============================================================================
// Heap allocators
// =============================================================================

/// Functions that return a heap-allocated pointer (NULL on failure).
pub const HEAP_ALLOCATORS: &[(&str, AllocSpec)] = &[
    // Standard C
    ("malloc", AllocSpec { size_arg: 0 }),
    ("calloc", AllocSpec { size_arg: 0 }),
    ("realloc", AllocSpec { size_arg: 1 }),
    ("reallocarray", AllocSpec { size_arg: 1 }),
    ("aligned_alloc", AllocSpec { size_arg: 1 }),
    ("valloc", AllocSpec { size_arg: 0 }),
    ("memalign", AllocSpec { size_arg: 1 }),
    ("posix_memalign", AllocSpec { size_arg: 2 }),
    ("alloca", AllocSpec { size_arg: 0 }),
    // String duplication (size implicit from string length)
    ("strdup", AllocSpec { size_arg: -1 }),
    ("strndup", AllocSpec { size_arg: 1 }),
    ("wcsdup", AllocSpec { size_arg: -1 }),
    // GLib
    ("g_malloc", AllocSpec { size_arg: 0 }),
    ("g_malloc0", AllocSpec { size_arg: 0 }),
    ("g_try_malloc", AllocSpec { size_arg: 0 }),
    ("g_try_malloc0", AllocSpec { size_arg: 0 }),
    ("g_realloc", AllocSpec { size_arg: 1 }),
    ("g_strdup", AllocSpec { size_arg: -1 }),
    ("g_strndup", AllocSpec { size_arg: 1 }),
    ("g_new", AllocSpec { size_arg: 1 }),
    ("g_new0", AllocSpec { size_arg: 1 }),
    // Linux kernel
    ("kmalloc", AllocSpec { size_arg: 0 }),
    ("kzalloc", AllocSpec { size_arg: 0 }),
    ("vmalloc", AllocSpec { size_arg: 0 }),
    ("kvmalloc", AllocSpec { size_arg: 0 }),
    ("kzalloc_node", AllocSpec { size_arg: 0 }),
    ("vmalloc_node", AllocSpec { size_arg: 0 }),
    ("kstrdup", AllocSpec { size_arg: -1 }),
    // Windows
    ("HeapAlloc", AllocSpec { size_arg: 2 }),
    ("GlobalAlloc", AllocSpec { size_arg: 1 }),
    ("LocalAlloc", AllocSpec { size_arg: 1 }),
    ("VirtualAlloc", AllocSpec { size_arg: 1 }),
    ("VirtualAllocEx", AllocSpec { size_arg: 2 }),
    // Misc / custom allocators
    ("talloc", AllocSpec { size_arg: 1 }),
    ("talloc_zero", AllocSpec { size_arg: 1 }),
    ("zmalloc", AllocSpec { size_arg: 0 }),
    ("zrealloc", AllocSpec { size_arg: 1 }),
    ("xmalloc", AllocSpec { size_arg: 0 }),
    ("xcalloc", AllocSpec { size_arg: 0 }),
    ("xrealloc", AllocSpec { size_arg: 1 }),
    ("xstrdup", AllocSpec { size_arg: -1 }),
    // ── C++ allocators ────────────────────────────────────────────────────────
    ("std::make_unique", AllocSpec { size_arg: -1 }),
    ("std::make_shared", AllocSpec { size_arg: -1 }),
    ("std::make_unique_for_overwrite", AllocSpec { size_arg: 0 }), // C++20
    ("std::make_shared_for_overwrite", AllocSpec { size_arg: -1 }), // C++20
    ("operator new", AllocSpec { size_arg: 0 }),
    ("operator new[]", AllocSpec { size_arg: 0 }),
    ("new", AllocSpec { size_arg: -1 }),
    ("boost::pool::malloc", AllocSpec { size_arg: 0 }),
    // C++ allocator-aware containers (size implicit from element count)
    ("std::vector::resize", AllocSpec { size_arg: 0 }),
    ("std::vector::reserve", AllocSpec { size_arg: 0 }),
    ("std::string::resize", AllocSpec { size_arg: 0 }),
    ("std::string::reserve", AllocSpec { size_arg: 0 }),
    ("std::deque::resize", AllocSpec { size_arg: 0 }),
    // OpenSSL
    ("OPENSSL_malloc", AllocSpec { size_arg: 0 }),
    ("OPENSSL_realloc", AllocSpec { size_arg: 1 }),
    ("BN_new", AllocSpec { size_arg: -1 }),
    ("BIO_new", AllocSpec { size_arg: -1 }),
    ("EVP_MD_CTX_new", AllocSpec { size_arg: -1 }),
    ("EVP_CIPHER_CTX_new", AllocSpec { size_arg: -1 }),
    ("EVP_PKEY_new", AllocSpec { size_arg: -1 }),
    // jemalloc
    ("je_malloc", AllocSpec { size_arg: 0 }),
    ("je_calloc", AllocSpec { size_arg: 0 }),
    ("je_realloc", AllocSpec { size_arg: 1 }),
    ("mallocx", AllocSpec { size_arg: 0 }),
    ("rallocx", AllocSpec { size_arg: 1 }),
    // tcmalloc
    ("tc_malloc", AllocSpec { size_arg: 0 }),
    ("tc_calloc", AllocSpec { size_arg: 0 }),
    ("tc_realloc", AllocSpec { size_arg: 1 }),
];

// =============================================================================
// Simple enumeration lists
// =============================================================================

/// Memory deallocation functions (CWE-415 double-free, CWE-416 use-after-free).
pub const FREE_FUNCTIONS: &[&str] = &[
    // C standard
    "free",
    "cfree",
    // Linux kernel
    "kfree",
    "vfree",
    "kvfree",
    "kfree_rcu",
    // GLib
    "g_free",
    "g_slist_free",
    "g_slist_free_full",
    "g_list_free",
    "g_list_free_full",
    "g_hash_table_destroy",
    "g_ptr_array_free",
    "g_byte_array_free",
    "g_string_free",
    // Apple Core Foundation
    "CFRelease",
    "cfrelease",
    // APR
    "apr_pool_destroy",
    "apr_brigade_destroy",
    // Windows
    "GlobalFree",
    "LocalFree",
    "HeapFree",
    "VirtualFree",
    "CoTaskMemFree",
    "RtlFreeHeap",
    "SysFreeString",
    "freelibrary",
    "FreeLibrary",
    // BSD / misc
    "xfree",
    "efree",
    "OPENSSL_free",
    "BN_free",
    "EVP_CIPHER_CTX_free",
    "BIO_free",
    "BIO_free_all",
    "X509_free",
    "SSL_CTX_free",
    "SSL_free",
    // C++ (operator delete)
    "operator delete",
    "operator delete[]",
];

/// Deallocation + assertion calls; used for UAF / double-free bracketing.
pub const DEALLOC_OR_ASSERT_CALLS: &[&str] = &[
    "free",
    "cfree",
    "kfree",
    "xfree",
    "g_free",
    "apr_pool_destroy",
    "operator delete",
    "operator delete[]",
    "assert",
    "g_assert",
    "g_return_if_fail",
    "g_return_val_if_fail",
    "ASSERT",
    "VERIFY",
    "CHECK_PTR",
    "_ASSERTE",
    "Q_ASSERT",
    "NSAssert",
];

/// Functions that validate, encode, or neutralise tainted data.
pub const SANITIZER_FUNCTIONS: &[&str] = &[
    // Path canonicalization
    "realpath",
    "canonicalize_file_name",
    "canonicalize_path",
    "apr_filepath_merge",
    "g_canonicalize_filename",
    "std::filesystem::canonical",
    "std::filesystem::lexically_normal",
    "std::filesystem::weakly_canonical",
    // Integer bounds checking
    "strtol",
    "strtoul",
    "strtoll",
    "strtoull",
    "atoi",
    "atol",
    "atoll",
    "strtof",
    "strtod",
    "strtold",
    // HTML encoding
    "escape_html",
    "htmlspecialchars",
    "htmlentities",
    "html_escape",
    "html_entity_encode",
    "HtmlEncode",
    "AntiXSS::HtmlEncode",
    // SQL escaping
    "mysql_real_escape_string",
    "mysql_real_escape_string_quote",
    "sqlite3_mprintf",
    "PQescapeStringConn",
    "PQescapeLiteral",
    "PQescapeIdentifier",
    // Shell escaping
    "escape_shell",
    "shlex_quote",
    "shell_escape",
    "escapeshellarg",
    "escapeshellcmd",
    "str_replace",
    "addslashes",
    // LDAP escaping
    "ldap_escape",
    // C++ character classification (used for whitelist validation)
    "isalpha",
    "isdigit",
    "isprint",
    "isalnum",
    "isspace",
    "isupper",
    "islower",
    "ispunct",
    "iscntrl",
    "isxdigit",
    "isgraph",
    "std::isalpha",
    "std::isdigit",
    "std::isprint",
    "std::isalnum",
    "std::isspace",
    "std::isupper",
    "std::islower",
    // C++ regex validation
    "std::regex_match",
    "std::regex_search",
    // URL encoding
    "url_encode",
    "urlencode",
    "percent_encode",
    "uri_escape",
    "curl_easy_escape",
    // Base64 (transforms but reduces attack surface for binary injection)
    "base64_encode",
    "b64_encode",
    "EVP_EncodeBlock",
];

/// Functions that never return (process terminators / long-jumps).
pub const NORETURN_FUNCTIONS: &[&str] = &[
    // C standard
    "exit",
    "_exit",
    "_Exit",
    "abort",
    "quick_exit",
    "at_quick_exit",
    // Long jumps
    "longjmp",
    "siglongjmp",
    "_longjmp",
    // BSD error family (exits with formatted message)
    "err",
    "errx",
    "verr",
    "verrx",
    // POSIX thread exit
    "pthread_exit",
    "thrd_exit",
    // C++ exceptions (do not return when uncaught)
    "std::terminate",
    "std::unexpected",
    "std::abort",
    // GLib
    "g_error",
    "g_critical",
    // Compiler builtins
    "__builtin_unreachable",
    "__assume",
    // Windows
    "ExitProcess",
    "ExitThread",
    "TerminateProcess",
    "FatalExit",
    // Linux kernel
    "panic",
    "BUG",
    "BUG_ON",
    // C++ throw wrappers
    "throw_runtime_error",
    "throw_invalid_argument",
];

/// File/resource open functions that return handles (NULL or -1 on failure).
pub const RESOURCE_OPENERS: &[&str] = &[
    // C standard
    "fopen",
    "freopen",
    "fdopen",
    "popen",
    "tmpfile",
    "tmpfile64",
    // POSIX
    "open",
    "openat",
    "open64",
    "openat64",
    "creat",
    "creat64",
    "socket",
    "socketpair",
    "accept",
    "accept4",
    "shm_open",
    "sem_open",
    "mq_open",
    "opendir",
    "fdopendir",
    // Linux epoll / io_uring
    "epoll_create",
    "epoll_create1",
    "inotify_init",
    "inotify_init1",
    "eventfd",
    "timerfd_create",
    "signalfd",
    "userfaultfd",
    // Windows
    "CreateFile",
    "CreateFileA",
    "CreateFileW",
    "CreateNamedPipe",
    "CreateNamedPipeA",
    "CreateNamedPipeW",
    "OpenFileMapping",
    "CreateFileMapping",
    "RegOpenKeyEx",
    "RegOpenKeyExA",
    "RegOpenKeyExW",
];

/// File/resource close functions.
pub const RESOURCE_CLOSERS: &[&str] = &[
    // C standard
    "fclose",
    "pclose",
    // POSIX
    "close",
    "closedir",
    "munmap",
    "shm_unlink",
    "sem_close",
    "mq_close",
    // Winsock
    "closesocket",
    "_close",
    // Windows
    "CloseHandle",
    "RegCloseKey",
    "FindClose",
    "DestroyWindow",
    "ReleaseDC",
    // Linux
    "epoll_close",
    // OpenSSL
    "BIO_free",
    "BIO_free_all",
    "SSL_free",
    "SSL_CTX_free",
];

/// Privilege-altering syscalls.
pub const PRIVILEGE_FUNCTIONS: &[&str] = &[
    // User/group ID
    "setuid",
    "setgid",
    "seteuid",
    "setegid",
    "setreuid",
    "setregid",
    "setresuid",
    "setresgid",
    "setgroups",
    "initgroups",
    // Filesystem isolation
    "chroot",
    "pivot_root",
    // Capabilities (Linux)
    "cap_set_proc",
    "capset",
    "prctl",
    // Namespace/jail (BSD)
    "jail",
    "jail_set",
    // Privilege drop helpers
    "setpriv",
    "drop_privileges",
];

/// POSIX thread/synchronisation functions (commonly return error codes).
pub const PTHREAD_FUNCTIONS: &[&str] = &[
    // Thread lifecycle
    "pthread_create",
    "pthread_join",
    "pthread_detach",
    "pthread_cancel",
    "pthread_exit",
    "pthread_self",
    "pthread_equal",
    // Mutex
    "pthread_mutex_init",
    "pthread_mutex_lock",
    "pthread_mutex_trylock",
    "pthread_mutex_timedlock",
    "pthread_mutex_unlock",
    "pthread_mutex_destroy",
    // Condition variables
    "pthread_cond_init",
    "pthread_cond_wait",
    "pthread_cond_timedwait",
    "pthread_cond_signal",
    "pthread_cond_broadcast",
    "pthread_cond_destroy",
    // RW locks
    "pthread_rwlock_init",
    "pthread_rwlock_rdlock",
    "pthread_rwlock_wrlock",
    "pthread_rwlock_tryrdlock",
    "pthread_rwlock_trywrlock",
    "pthread_rwlock_timedrdlock",
    "pthread_rwlock_timedwrlock",
    "pthread_rwlock_unlock",
    "pthread_rwlock_destroy",
    // Barriers
    "pthread_barrier_init",
    "pthread_barrier_wait",
    "pthread_barrier_destroy",
    // Spin locks
    "pthread_spin_init",
    "pthread_spin_lock",
    "pthread_spin_trylock",
    "pthread_spin_unlock",
    "pthread_spin_destroy",
    // Thread-local / once
    "pthread_once",
    "pthread_key_create",
    "pthread_key_delete",
    "pthread_getspecific",
    "pthread_setspecific",
    // C11 threads
    "thrd_create",
    "thrd_join",
    "thrd_detach",
    "thrd_exit",
    "mtx_init",
    "mtx_lock",
    "mtx_timedlock",
    "mtx_trylock",
    "mtx_unlock",
    "mtx_destroy",
    "cnd_init",
    "cnd_wait",
    "cnd_timedwait",
    "cnd_signal",
    "cnd_broadcast",
    "cnd_destroy",
];

/// Integer/float conversion functions (tainted string → tainted numeric value).
pub const STRING_TO_INT_FUNCTIONS: &[&str] = &[
    // C string-to-int
    "atoi",
    "atol",
    "atoll",
    "atof",
    "strtol",
    "strtoul",
    "strtoll",
    "strtoull",
    "strtof",
    "strtod",
    "strtold",
    "strtoimax",
    "strtoumax",
    // Wide-char variants
    "wcstol",
    "wcstoul",
    "wcstoll",
    "wcstoull",
    "wcstof",
    "wcstod",
    "wcstold",
    // C++ std::sto* family
    "stoi",
    "stol",
    "stoll",
    "stoul",
    "stoull",
    "stof",
    "stod",
    "stold",
    "std::stoi",
    "std::stol",
    "std::stoll",
    "std::stoul",
    "std::stoull",
    "std::stof",
    "std::stod",
    "std::stold",
    // C++17 std::from_chars (binary parsing)
    "std::from_chars",
    "from_chars",
    // POSIX
    "sscanf",
    // Windows
    "_atoi64",
    "_atoi128",
    "_wtoi",
    "_wtol",
    "_wtoll",
    "_wtof",
];

/// Misc known-stdlib functions used for symbol anonymization.
/// These don't fit cleanly into sources/sinks/propagators but should never
/// be anonymized in the CPG.
pub const MISC_STDLIB: &[&str] = &[
    // Network byte-order conversion
    "htons",
    "ntohs",
    "htonl",
    "ntohl",
    "htobe16",
    "htobe32",
    "htobe64",
    "be16toh",
    "be32toh",
    "be64toh",
    "inet_addr",
    "inet_aton",
    "inet_ntoa",
    "inet_ntop",
    "inet_pton",
    // Standard math / utility
    "abs",
    "labs",
    "llabs",
    "imaxabs",
    "fabs",
    "fabsf",
    "fabsl",
    "sqrt",
    "sqrtf",
    "sqrtl",
    "pow",
    "powf",
    "powl",
    "floor",
    "floorf",
    "floorl",
    "ceil",
    "ceilf",
    "ceill",
    "round",
    "roundf",
    "roundl",
    "fmod",
    "fmodf",
    "fmodl",
    "min",
    "max",
    "std::min",
    "std::max",
    "std::clamp",
    // String utilities (non-taint-relevant)
    "strlen",
    "wcslen",
    "strnlen",
    "strcmp",
    "strncmp",
    "strcasecmp",
    "strncasecmp",
    "wcscmp",
    "wcsncmp",
    "strspn",
    "strcspn",
    "memcmp",
    "bcmp",
    "wmemcmp",
    // I/O control / positioning
    "fflush",
    "fseek",
    "fseeko",
    "ftell",
    "ftello",
    "rewind",
    "feof",
    "ferror",
    "clearerr",
    "fclose",
    "pclose",
    "close",
    "closesocket",
    "fgetpos",
    "fsetpos",
    // File metadata
    "stat",
    "fstat",
    "lstat",
    "fstatat",
    "statx",
    "access",
    "faccessat",
    // Resource limits / timing
    "getrlimit",
    "setrlimit",
    "getrusage",
    "clock",
    "time",
    "gettimeofday",
    "clock_gettime",
    "clock_getres",
    "clock_settime",
    "nanosleep",
    "usleep",
    "sleep",
    // Semaphore / sync (not in PTHREAD_FUNCTIONS)
    "sem_init",
    "sem_wait",
    "sem_trywait",
    "sem_timedwait",
    "sem_post",
    "sem_getvalue",
    "sem_destroy",
    "sem_open",
    "sem_close",
    "sem_unlink",
    // Process
    "fork",
    "vfork",
    "clone",
    "wait",
    "waitpid",
    "waitid",
    "wait3",
    "wait4",
    "getpid",
    "getppid",
    "getpgid",
    "getsid",
    "setsid",
    "setpgid",
    // Signals
    "signal",
    "sigaction",
    "sigprocmask",
    "sigpending",
    "sigsuspend",
    "sigwait",
    "sigwaitinfo",
    "raise",
    "kill",
    "killpg",
    "tkill",
    // Memory
    "mlock",
    "munlock",
    "mlockall",
    "munlockall",
    "mprotect",
    "madvise",
    "mincore",
    "brk",
    "sbrk",
    // Misc
    "qsort",
    "qsort_r",
    "bsearch",
    "rand",
    "rand_r",
    "srand",
    "random",
    "srandom",
    "drand48",
    "lrand48",
    "mrand48",
    "getpagesize",
    "sysconf",
    "pathconf",
    "dup",
    "dup2",
    "dup3",
    "pipe",
    "pipe2",
    "isatty",
    "ttyname",
    "ttyname_r",
    "strerror",
    "strerror_r",
    "perror",
    // C++ standard
    "std::terminate",
    "std::unexpected",
    "std::move",
    "std::forward",
    "std::swap",
    "std::begin",
    "std::end",
    "std::size",
    "std::addressof",
    "std::ignore",
];

// =============================================================================
// Named function sets (previously builtin_sets.yaml)
// Referenced in rules as: text: { in: "$builtin.set_name" }
// =============================================================================

/// Standard C/POSIX I/O functions that introduce tainted data.
pub const BUILTIN_SET_C_IO_SOURCES: &[&str] = &[
    // Low-level POSIX
    "read",
    "pread",
    "readv",
    "preadv",
    // Network
    "recv",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    // C stdio
    "fread",
    "fgets",
    "gets",
    "getchar",
    "getc",
    "fgetc",
    "scanf",
    "fscanf",
    "sscanf",
    "vscanf",
    "vfscanf",
    "vsscanf",
    // Environment
    "getenv",
    "secure_getenv",
    "getenv_s",
    // CLI / program arguments
    "argv",
    "getopt",
    "getopt_long",
    "getopt_long_only",
    // Line reading
    "getline",
    "getdelim",
    // Mapping
    "mmap",
    // Additional
    "accept",
    "accept4",
    "getpwnam",
    "getpwuid",
    "cuserid",
    "getlogin",
];

/// File system operations that may use attacker-controlled paths (CWE-22).
pub const BUILTIN_SET_FILE_OPS: &[&str] = &[
    // Open
    "fopen",
    "freopen",
    "open",
    "openat",
    "open64",
    "openat64",
    "creat",
    // Delete / rename
    "unlink",
    "unlinkat",
    "remove",
    "rename",
    "renameat",
    // Directory
    "mkdir",
    "mkdirat",
    "rmdir",
    "opendir",
    // Traversal
    "chdir",
    "fchdir",
    // Permissions
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "lchown",
    "fchown",
    "fchownat",
    // Hard / soft links
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "readlink",
    "readlinkat",
    // Temp
    "mkstemp",
    "mkostemp",
    "mkdtemp",
    // Truncate
    "truncate",
    // C++ filesystem
    "std::filesystem::copy",
    "std::filesystem::copy_file",
    "std::filesystem::remove",
    "std::filesystem::remove_all",
    "std::filesystem::rename",
    "std::filesystem::create_directory",
    "std::filesystem::create_symlink",
];

/// Process/command execution functions.
pub const BUILTIN_SET_EXEC_OPS: &[&str] = &[
    // C standard
    "system",
    "popen",
    // POSIX exec family
    "execl",
    "execle",
    "execlp",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "fexecve",
    "execveat",
    // POSIX spawn
    "posix_spawn",
    "posix_spawnp",
    // Windows
    "ShellExecute",
    "ShellExecuteA",
    "ShellExecuteW",
    "ShellExecuteEx",
    "ShellExecuteExA",
    "ShellExecuteExW",
    "CreateProcess",
    "CreateProcessA",
    "CreateProcessW",
    "CreateProcessAsUserA",
    "CreateProcessAsUserW",
    "WinExec",
    // C++ Boost.Process
    "boost::process::system",
    "boost::process::child",
    // Qt
    "QProcess::start",
    "QProcess::startDetached",
    // Dynamic library loading (attacker-controlled path → code execution)
    "dlopen",
    "dlmopen",
];

/// Heap allocation functions.
pub const BUILTIN_SET_ALLOC_OPS: &[&str] = &[
    // C standard
    "malloc",
    "calloc",
    "realloc",
    "reallocarray",
    "alloca",
    "aligned_alloc",
    "valloc",
    "memalign",
    "posix_memalign",
    // String duplication
    "strdup",
    "strndup",
    "wcsdup",
    // GLib
    "g_malloc",
    "g_malloc0",
    "g_realloc",
    "g_strdup",
    "g_strndup",
    "g_new",
    "g_new0",
    // Linux kernel
    "kmalloc",
    "kzalloc",
    "vmalloc",
    // Windows
    "HeapAlloc",
    "GlobalAlloc",
    "LocalAlloc",
    "VirtualAlloc",
    // C++ operators
    "operator new",
    "operator new[]",
    // C++ smart pointers (allocation+construction)
    "std::make_unique",
    "std::make_shared",
];

/// String/memory copy functions.
pub const BUILTIN_SET_STRING_COPY_OPS: &[&str] = &[
    // String copy
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "stpcpy",
    "stpncpy",
    // Wide-char copy
    "wcscpy",
    "wcsncpy",
    "wcscat",
    "wcsncat",
    // Formatted print (to buffer)
    "sprintf",
    "snprintf",
    "vsprintf",
    "vsnprintf",
    "swprintf",
    "vswprintf",
    "asprintf",
    "vasprintf",
    // Memory copy
    "memcpy",
    "memmove",
    "mempcpy",
    "bcopy",
    "wmemcpy",
    "wmemmove",
    // Memory set
    "memset",
    "bzero",
    "explicit_bzero",
    // Windows
    "lstrcpy",
    "lstrcpyA",
    "lstrcpyW",
    "lstrcat",
    "lstrcatA",
    "lstrcatW",
];

/// Path canonicalization / sanitizer functions.
pub const BUILTIN_SET_PATH_SANITIZERS: &[&str] = &[
    // C POSIX canonicalization
    "realpath",
    "canonicalize_path",
    "canonicalize_file_name",
    // Framework-specific
    "apr_filepath_merge",
    "g_canonicalize_filename",
    // Decomposition (not full validation, but reduces surface)
    "basename",
    "dirname",
    // User-defined validation patterns (conventional names)
    "validate_path",
    "sanitize_path",
    "normalize_path",
    "check_path",
    "is_safe_path",
    "is_valid_path",
    "restrict_path",
    // Search / membership (used to whitelist components)
    "strstr",
    "strchr",
    "strrchr",
    // C++17 filesystem
    "std::filesystem::canonical",
    "std::filesystem::lexically_normal",
    "std::filesystem::weakly_canonical",
];

/// Shell command sanitizer functions.
pub const BUILTIN_SET_COMMAND_SANITIZERS: &[&str] = &[
    // Shell quoting
    "escape_shell",
    "shlex_quote",
    "shell_escape",
    "escapeshellcmd",
    "escapeshellarg",
    "g_shell_quote",
    "apr_escape_shell_cmd",
    // User-defined (conventional names)
    "sanitize_command",
    "validate_command",
    "whitelist_command",
    "is_safe_command",
    "is_allowed_command",
    // Search-based validation
    "strchr",
    "strstr",
    "strpbrk",
    "regex_match",
    // URL encoding (for shell via URL)
    "urlencode",
    "url_encode",
    "curl_easy_escape",
];

/// Valid guard_type_preset names (previously keys of guard_type_presets in
/// default_sanitizers.yaml). Used by the rule loader for schema validation.
pub const GUARD_TYPE_PRESET_NAMES: &[&str] = &["injection_guards", "bounds_guards"];

/// Prefixes that conventionally indicate a sanitizer/validation function by naming convention.
pub const SANITIZER_PREFIXES: &[&str] = &[
    "validate_",
    "sanitize_",
    "escape_",
    "encode_",
    "check_",
    "verify_",
    "is_valid_",
    "is_safe_",
    "clean_",
    "filter_",
];

/// Canonical field names used to check a type discriminant before a type-unsafe cast.
pub const BUILTIN_SET_DISCRIMINANT_FIELDS: &[&str] =
    &["type", "kind", "tag", "discriminant", "variant", "class"];

/// Build the complete map of builtin named sets for use in the rule loader.
/// Keys are the set names (e.g. "exec_ops"); values are the member function lists.
pub fn builtin_sets() -> std::collections::BTreeMap<String, Vec<String>> {
    let mut m = std::collections::BTreeMap::new();
    let insert =
        |m: &mut std::collections::BTreeMap<String, Vec<String>>, name: &str, items: &[&str]| {
            m.insert(
                name.to_string(),
                items.iter().map(|s| s.to_string()).collect(),
            );
        };
    // Sources already in STDLIB_TAINT_SOURCES — expose a named subset for rules.
    insert(&mut m, "c_io_sources", BUILTIN_SET_C_IO_SOURCES);
    insert(&mut m, "argv_sources", &["argv"]);
    insert(&mut m, "file_ops", BUILTIN_SET_FILE_OPS);
    insert(&mut m, "exec_ops", BUILTIN_SET_EXEC_OPS);
    insert(&mut m, "alloc_ops", BUILTIN_SET_ALLOC_OPS);
    insert(&mut m, "string_copy_ops", BUILTIN_SET_STRING_COPY_OPS);
    insert(&mut m, "path_sanitizers", BUILTIN_SET_PATH_SANITIZERS);
    insert(&mut m, "command_sanitizers", BUILTIN_SET_COMMAND_SANITIZERS);
    insert(
        &mut m,
        "bounds_sanitizers",
        &[
            "bounds_check",
            "strlen_check",
            "size_validation",
            "length_check",
            "range_check",
        ],
    );
    insert(&mut m, "string_dup_ops", BUILTIN_SET_STRING_DUP_OPS);
    insert(&mut m, "bounded_copy_ops", BUILTIN_SET_BOUNDED_COPY_OPS);
    insert(&mut m, "noreturn_functions", NORETURN_FUNCTIONS);
    insert(&mut m, "free_functions", FREE_FUNCTIONS);
    insert(&mut m, "dealloc_or_assert", DEALLOC_OR_ASSERT_CALLS);
    insert(&mut m, "privilege_functions", PRIVILEGE_FUNCTIONS);
    insert(&mut m, "resource_openers", RESOURCE_OPENERS);
    insert(&mut m, "resource_closers", RESOURCE_CLOSERS);
    insert(&mut m, "string_to_int", STRING_TO_INT_FUNCTIONS);
    insert(
        &mut m,
        "DISCRIMINANT_FIELDS",
        BUILTIN_SET_DISCRIMINANT_FIELDS,
    );
    m
}

// =============================================================================
// Query helpers — all comparisons are ASCII-case-insensitive.
// =============================================================================

#[inline]
fn ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[inline]
fn ci_list(list: &[&str], name: &str) -> bool {
    list.iter().any(|n| ci(n, name))
}

// ── O(1) lookup tables built once at first use ──────────────────────────────
// All keys are stored **lowercase** so callers just lowercase the name once.

use std::collections::HashMap;
use std::sync::LazyLock;

static PROPAGATOR_MAP: LazyLock<HashMap<&'static str, &'static PropagatorSpec>> =
    LazyLock::new(|| {
        TAINT_PROPAGATORS
            .iter()
            .map(|(name, spec)| (*name, spec))
            .collect()
    });

static SOURCE_MAP: LazyLock<HashMap<&'static str, &'static SourceSpec>> = LazyLock::new(|| {
    STDLIB_TAINT_SOURCES
        .iter()
        .map(|(name, spec)| (*name, spec))
        .collect()
});

static SINK_MAP: LazyLock<HashMap<&'static str, &'static SinkSpec>> = LazyLock::new(|| {
    STDLIB_TAINT_SINKS
        .iter()
        .map(|(name, spec)| (*name, spec))
        .collect()
});

static ALLOC_MAP: LazyLock<HashMap<&'static str, &'static AllocSpec>> = LazyLock::new(|| {
    HEAP_ALLOCATORS
        .iter()
        .map(|(name, spec)| (*name, spec))
        .collect()
});


/// Returns the [`PropagatorSpec`] for `name`, if it is a known propagator.
/// O(1) exact-match fast path; falls back to case-insensitive linear scan.
pub fn get_propagator(name: &str) -> Option<&'static PropagatorSpec> {
    PROPAGATOR_MAP.get(name).copied().or_else(|| {
        TAINT_PROPAGATORS
            .iter()
            .find(|(n, _)| ci(n, name))
            .map(|(_, s)| s)
    })
}

/// Returns the [`SourceSpec`] for `name`, if it is a known taint source.
pub fn get_source_spec(name: &str) -> Option<&'static SourceSpec> {
    SOURCE_MAP.get(name).copied().or_else(|| {
        STDLIB_TAINT_SOURCES
            .iter()
            .find(|(n, _)| ci(n, name))
            .map(|(_, s)| s)
    })
}

/// Returns the [`SinkSpec`] for `name`, if it is a known taint sink.
pub fn get_sink_spec(name: &str) -> Option<&'static SinkSpec> {
    SINK_MAP.get(name).copied().or_else(|| {
        STDLIB_TAINT_SINKS
            .iter()
            .find(|(n, _)| ci(n, name))
            .map(|(_, s)| s)
    })
}

/// Returns the [`AllocSpec`] for `name`, if it is a known heap allocator.
pub fn get_alloc_spec(name: &str) -> Option<&'static AllocSpec> {
    ALLOC_MAP.get(name).copied().or_else(|| {
        HEAP_ALLOCATORS
            .iter()
            .find(|(n, _)| ci(n, name))
            .map(|(_, s)| s)
    })
}

/// Returns `true` if `name` is a deallocation or assertion call.
pub fn is_dealloc_or_assert(name: &str) -> bool {
    ci_list(DEALLOC_OR_ASSERT_CALLS, name)
}

/// Returns `true` if `name` is a known standard-library function.
/// Used by the symbol anonymizer to avoid renaming well-known names.
/// String-duplication functions: return a freshly allocated copy of their
/// source argument.  Taint propagation: dst = -1 (return value), src = arg 0.
pub const BUILTIN_SET_STRING_DUP_OPS: &[&str] = &[
    "strdup",
    "strndup",
    "g_strdup",
    "g_strndup",
    "xstrdup",
    "kstrdup",
];

/// Memory/string copy functions that take an explicit size/count as their
/// *last* argument, making that argument the natural "guarded variable" for
/// bounds-check guard analysis.  Subset of BUILTIN_SET_STRING_COPY_OPS.
pub const BUILTIN_SET_BOUNDED_COPY_OPS: &[&str] = &[
    "memcpy", "memmove", "memset", "bcopy", "wmemcpy", "wmemmove", "strncpy", "strncat", "wcsncpy",
    "wcsncat",
];

/// Returns true if `name` is a string-duplication function
/// (see `BUILTIN_SET_STRING_DUP_OPS`).
#[inline]
pub fn is_string_dup_op(name: &str) -> bool {
    ci_list(BUILTIN_SET_STRING_DUP_OPS, name)
}

/// Returns true if `name` is a bounded-copy function (explicit size as last arg)
/// (see `BUILTIN_SET_BOUNDED_COPY_OPS`).
#[inline]
pub fn is_bounded_copy_op(name: &str) -> bool {
    ci_list(BUILTIN_SET_BOUNDED_COPY_OPS, name)
}

pub fn is_known_stdlib(name: &str) -> bool {
    get_source_spec(name).is_some()
        || get_sink_spec(name).is_some()
        || get_propagator(name).is_some()
        || get_alloc_spec(name).is_some()
        || ci_list(FREE_FUNCTIONS, name)
        || ci_list(SANITIZER_FUNCTIONS, name)
        || ci_list(NORETURN_FUNCTIONS, name)
        || ci_list(RESOURCE_OPENERS, name)
        || ci_list(RESOURCE_CLOSERS, name)
        || ci_list(PRIVILEGE_FUNCTIONS, name)
        || ci_list(PTHREAD_FUNCTIONS, name)
        || ci_list(STRING_TO_INT_FUNCTIONS, name)
        || ci_list(MISC_STDLIB, name)
}
