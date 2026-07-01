// cpp_security.cpp — C++ security vulnerability test patterns.
// Each vuln_ function contains a security issue; each safe_ function is the safe version.
// Used for rule matching integration tests.
// Not meant to be compiled; parsed by tree-sitter-cpp.

#include <cstddef>

// ── Stubs ─────────────────────────────────────────────────────────────────────

char* getenv(const char*);
int system(const char*);
void* malloc(int);
void free(void*);
int snprintf(char*, int, const char*, ...);
int printf(const char*, ...);
int strlen(const char*);
void* memcpy(void*, const void*, int);

namespace std {
    struct string {
        const char* buf;
        string() : buf("") {}
        explicit string(const char* s) : buf(s) {}
        string& operator+=(const char* s) { return *this; }
        string operator+(const char* s) const { return *this; }
        const char* c_str() const { return buf; }
        int size() const { return 0; }
    };
    struct ostringstream {
        ostringstream& operator<<(const char* s) { return *this; }
        ostringstream& operator<<(int n) { return *this; }
        string str() const { return {}; }
    };
    namespace filesystem {
        void remove(const char* p) {}
        void copy(const char* s, const char* d) {}
        void create_directory(const char* p) {}
        void rename(const char* from, const char* to) {}
        struct path {
            explicit path(const char* p) {}
            const char* c_str() const { return ""; }
        };
    }
    char* move(char* x) { return x; }
    string to_string(int n) { return {}; }
    void print(const char* fmt, ...) {}
    void println(const char* fmt, ...) {}
    string format(const char* fmt, ...) { return {}; }
    string vformat(const char* fmt, ...) { return {}; }
    void format_to(char* buf, const char* fmt, ...) {}
}

// ── CWE-78: Command Injection ─────────────────────────────────────────────────

// Vulnerable: user input directly into system()
void vuln_cmd_injection_direct() {
    char* cmd = getenv("USER_CMD");
    system(cmd);
}

// Safe: validate input before use
const char* ALLOWED_COMMANDS[] = {"ls", "pwd", "date", nullptr};
void safe_cmd_validated() {
    char* cmd = getenv("USER_CMD");
    for (int i = 0; ALLOWED_COMMANDS[i]; ++i) {
        if (cmd && cmd[0] && cmd[1] == 0) {
            // length check passes — would do real validation
            return;
        }
    }
    system("echo forbidden");  // only hardcoded command
}

// Vulnerable: std::string concatenation into system()
void vuln_cmd_string_concat() {
    char* user = getenv("INPUT");
    std::string cmd("ls ");
    cmd += user;
    system(cmd.c_str());
}

// Safe: hardcoded command
void safe_cmd_hardcoded() {
    system("ls /tmp");
}

// ── CWE-22: Path Traversal ────────────────────────────────────────────────────

// Vulnerable: unvalidated path to filesystem operations
void vuln_path_traversal_remove() {
    char* path = getenv("TARGET_FILE");
    std::filesystem::remove(path);
}

// Safe: use a fixed directory prefix
void safe_path_fixed_prefix() {
    std::filesystem::remove("/tmp/safe_dir/known_file.txt");
}

// Vulnerable: path traversal via filesystem::copy
void vuln_path_traversal_copy() {
    char* src = getenv("SRC_PATH");
    char* dst = getenv("DST_PATH");
    std::filesystem::copy(src, dst);
}

// Safe: validate destination stays within allowed dir
void safe_path_validated_copy() {
    std::filesystem::copy("/data/input.txt", "/tmp/output.txt");
}

// ── CWE-134: Format String ────────────────────────────────────────────────────

// Vulnerable: user-controlled format string to printf
void vuln_format_string_printf() {
    char* fmt = getenv("LOG_FORMAT");
    printf(fmt);
}

// Safe: use fixed format string
void safe_format_string_printf() {
    char* val = getenv("VALUE");
    printf("Value: %s\n", val);
}

// Vulnerable: user-controlled format to std::vformat (C++20)
void vuln_format_string_vformat() {
    char* fmt = getenv("FMT");
    std::string result = std::vformat(fmt);
    printf("%s", result.c_str());
}

// Safe: hardcoded format to vformat; user data in value position, not format string
void safe_format_string_vformat() {
    char* val = getenv("VALUE");
    std::string result = std::vformat("{}", val);  // user data in value, not format
    printf("%s", result.c_str());
}

// Vulnerable: std::print with user-controlled format (C++23)
void vuln_format_string_print() {
    char* fmt = getenv("LOG_FMT");
    std::print(fmt, 42);
}

// Safe: fixed format, user data as argument
void safe_format_string_print() {
    char* val = getenv("NAME");
    std::print("Hello, {}\n", val);
}

// ── CWE-476: Null Dereference after dynamic_cast ──────────────────────────────

struct Base { virtual ~Base() {} };
struct Derived : Base { int x; };

// Vulnerable: dynamic_cast result not checked before use
void vuln_dynamic_cast_null(Base* b) {
    Derived* d = dynamic_cast<Derived*>(b);
    (void)d->x;  // d could be null if b is not Derived
}

// Safe: check dynamic_cast result
void safe_dynamic_cast_checked(Base* b) {
    Derived* d = dynamic_cast<Derived*>(b);
    if (d != nullptr) {
        (void)d->x;
    }
}

// ── CWE-416: Use After Move ───────────────────────────────────────────────────

// Vulnerable: use after std::move
void vuln_use_after_move() {
    char* raw = getenv("DATA");
    char* moved = std::move(raw);
    (void)moved;
    system(raw);  // use after move — raw is in unspecified state
}

// Safe: don't use original after move
void safe_no_use_after_move() {
    char* raw = getenv("DATA");
    char* moved = std::move(raw);
    // only use 'moved', never 'raw' again
    (void)moved;
}

// ── CWE-362: Thread Data Race ─────────────────────────────────────────────────

struct shared_state {
    int counter;
    bool initialized;
    char* data;
};
shared_state g_state;

// Vulnerable: unsynchronized access to shared state
void vuln_data_race_write(char* new_data) {
    // No lock — races with concurrent readers
    g_state.data = new_data;
    g_state.initialized = true;
}

void vuln_data_race_read(char* out, int n) {
    if (g_state.initialized) {
        memcpy(out, g_state.data, n);  // data may not be initialized yet
    }
}

// ── CWE-209: Exception Information Leak ──────────────────────────────────────

// Vulnerable: leak exception details to stderr/output
void vuln_exception_info_leak() {
    try {
        int* p = nullptr;
        (void)*p;
    } catch (...) {
        printf("Internal error: exception at %s:%d", __FILE__, __LINE__);
    }
}

// Safe: generic error message only
void safe_exception_generic_message() {
    try {
        int* p = nullptr;
        (void)*p;
    } catch (...) {
        printf("An error occurred. Please try again.");
    }
}

// ── CWE-1333: Regex DoS ───────────────────────────────────────────────────────

// Stubs for regex
namespace std {
    struct regex {
        explicit regex(const char* pattern) {}
    };
    bool regex_match(const char* s, const regex& re) { return false; }
}

// Vulnerable: user-controlled regex pattern
bool vuln_regex_dos(const char* input) {
    char* pattern = getenv("REGEX_PATTERN");
    std::regex re(pattern);  // user-controlled pattern → ReDoS possible
    return std::regex_match(input, re);
}

// Safe: hardcoded pattern
bool safe_regex_hardcoded(const char* input) {
    std::regex re("^[a-zA-Z0-9_-]+$");  // fixed pattern
    return std::regex_match(input, re);
}

// ── CWE-476: Weak Pointer Unchecked Lock ────────────────────────────────────

template <typename T>
struct weak_ptr_stub {
    T* ptr;
    struct locked { T* p; T* operator->() { return p; } bool operator bool() { return p != nullptr; } };
    locked lock() { return {ptr}; }
};
template <typename T>
struct shared_ptr_stub { T* ptr; };

struct Resource { int id; void use() {} };

// Vulnerable: weak_ptr::lock() result not checked
void vuln_weak_ptr_unchecked(weak_ptr_stub<Resource> wp) {
    auto locked = wp.lock();
    locked->use();  // lock() may return null if resource was freed
}

// Safe: check lock() result
void safe_weak_ptr_checked(weak_ptr_stub<Resource> wp) {
    auto locked = wp.lock();
    if (locked.p) {
        locked->use();
    }
}

// ── CWE-78: Ostream Injection ─────────────────────────────────────────────────

// Vulnerable: user input injected into ostream that feeds a command
void vuln_ostream_injection() {
    char* user = getenv("PAYLOAD");
    std::ostringstream oss;
    oss << "command --arg " << user;
    system(oss.str().c_str());
}

// Safe: escape or validate user input before use
void safe_ostream_no_injection() {
    std::ostringstream oss;
    oss << "command --arg safe_value";
    system(oss.str().c_str());
}

// ── CWE-121: Stack Buffer Overflow ───────────────────────────────────────────

// Vulnerable: user-controlled length → stack overflow
void vuln_stack_overflow(const char* user_data, int user_len) {
    char local_buf[64];
    memcpy(local_buf, user_data, user_len);  // no size check
    (void)local_buf;
}

// Safe: check length before copy
void safe_stack_bounded(const char* user_data, int user_len) {
    char local_buf[64];
    if (user_len > 0 && user_len <= (int)sizeof(local_buf) - 1) {
        memcpy(local_buf, user_data, user_len);
        local_buf[user_len] = 0;
    }
    (void)local_buf;
}

// ── CWE-190: Integer Overflow ────────────────────────────────────────────────

// Vulnerable: multiplication overflow in size calculation
void* vuln_integer_overflow_alloc(int n) {
    int size = n * sizeof(int);  // can overflow if n is large
    return malloc(size);
}

// Safe: check before multiply
void* safe_integer_overflow_alloc(int n) {
    if (n <= 0 || n > 0x7FFFFFFF / (int)sizeof(int)) return nullptr;
    int size = n * sizeof(int);
    return malloc(size);
}

// ── CWE-401: Memory Leak ─────────────────────────────────────────────────────

// Vulnerable: allocated memory not freed on error path
void* vuln_memory_leak(int n, int flag) {
    void* buf = malloc(n);
    if (flag) {
        return nullptr;  // buf leaked
    }
    return buf;
}

// Safe: always free on error
void* safe_no_memory_leak(int n, int flag) {
    void* buf = malloc(n);
    if (flag) {
        free(buf);
        return nullptr;
    }
    return buf;
}

// ── CWE-415: Double Free ──────────────────────────────────────────────────────

// Vulnerable: double free via aliased pointer
void vuln_double_free(void* p) {
    void* alias = p;
    free(p);
    free(alias);  // double free
}

// Safe: null after free
void safe_null_after_free(void** pp) {
    free(*pp);
    *pp = nullptr;
}

// ── CWE-787: Out-of-Bounds Write ────────────────────────────────────────────

// Vulnerable: write past end of array
void vuln_oob_write(int* arr, int size, int idx, int val) {
    arr[idx] = val;  // no bounds check
}

// Safe: bounds check
void safe_oob_write(int* arr, int size, int idx, int val) {
    if (idx >= 0 && idx < size) {
        arr[idx] = val;
    }
}

// ── CWE-125: Out-of-Bounds Read ──────────────────────────────────────────────

// Vulnerable: read past end
int vuln_oob_read(int* arr, int size, int idx) {
    return arr[idx];  // no bounds check
}

// Safe: bounds check
int safe_oob_read(int* arr, int size, int idx) {
    if (idx >= 0 && idx < size) return arr[idx];
    return -1;
}

// ── CWE-798: Hardcoded Credentials ───────────────────────────────────────────

// Vulnerable: hardcoded password
bool vuln_hardcoded_password(const char* input) {
    const char* password = "s3cr3t_p@ssw0rd";
    return input == password;  // compare with hardcoded credential
}

// Safe: compare against stored hash / external credential
bool safe_no_hardcoded_password(const char* input, const char* stored_hash) {
    (void)input;
    (void)stored_hash;
    return false;  // real implementation would use crypto compare
}

// ── CWE-327: Weak Cryptography ───────────────────────────────────────────────

// Stubs
namespace crypto_stubs {
    void* MD5(const char*, int, void*) { return nullptr; }
    void* SHA256(const char*, int, void*) { return nullptr; }
}

// Vulnerable: use of MD5 for security-sensitive hashing
void* vuln_weak_crypto(const char* data, int len) {
    char hash[16];
    return crypto_stubs::MD5(data, len, hash);
}

// Safe: use SHA256
void* safe_strong_crypto(const char* data, int len) {
    char hash[32];
    return crypto_stubs::SHA256(data, len, hash);
}

// ── C++20: Coroutine security scenario ───────────────────────────────────────

struct CoTask {
    struct promise_type {
        CoTask get_return_object() { return {}; }
        struct SuspNever { bool await_ready(){return true;} void await_suspend(void*){} void await_resume(){} };
        SuspNever initial_suspend() { return {}; }
        SuspNever final_suspend() noexcept { return {}; }
        void return_void() {}
        void unhandled_exception() {}
    };
};

// Tainted data across co_await suspension point
CoTask vuln_coroutine_taint() {
    char* user_data = getenv("DATA");
    co_await CoTask::promise_type::SuspNever{};
    system(user_data);  // taint should survive co_await
    co_return;
}

// ── Lambda security patterns ──────────────────────────────────────────────────

// Vulnerable: lambda captures tainted var by ref and calls sink
void vuln_lambda_capture_taint() {
    char* user = getenv("CMD");
    auto exec = [&user]() {
        system(user);
    };
    exec();
}

// Safe: lambda does not call dangerous sink
void safe_lambda_no_sink() {
    char* user = getenv("DATA");
    auto process = [user]() {
        int len = strlen(user);
        (void)len;
    };
    process();
}

// ── Template security pattern ─────────────────────────────────────────────────

// Vulnerable: template passes tainted arg directly to sink
template <typename T>
void vuln_template_sink(T val) {
    system(val);
}

// Called with tainted data
void vuln_template_usage() {
    char* raw = getenv("CMD");
    vuln_template_sink(raw);
}

// ── Structured binding + taint ────────────────────────────────────────────────

struct UserEntry {
    const char* username;
    const char* command;
};

UserEntry get_user_entry() {
    UserEntry e;
    e.username = getenv("USERNAME");
    e.command = getenv("COMMAND");
    return e;
}

// Vulnerable: structured binding exposes tainted command to sink
void vuln_structured_binding_sink() {
    auto [user, cmd] = get_user_entry();
    system(cmd);  // cmd is tainted from getenv
}

// ── Member init list security ────────────────────────────────────────────────

struct CommandRunner {
    const char* cmd;
    CommandRunner(const char* c) : cmd(c) {}
    void run() { system(cmd); }
};

// Vulnerable: tainted data flows through constructor into field
void vuln_member_init_taint() {
    char* raw = getenv("RUN_CMD");
    CommandRunner runner(raw);  // taint: getenv → ctor param → cmd field
    runner.run();               // taint: cmd field → system()
}

// Safe: hardcoded command in constructor
void safe_member_init_no_taint() {
    CommandRunner runner("echo hello");
    runner.run();
}

// ── Alias analysis integration test ─────────────────────────────────────────

// Vulnerable: pointer alias — taint flows via alias to system()
void vuln_alias_pointer_to_system() {
    char* data = getenv("CMD");   // source: data is tainted
    char* alias_ptr = data;       // alias: alias_ptr == data
    system(alias_ptr);            // sink: tainted via alias
}

// ── CFG path-sensitive sanitizer test ───────────────────────────────────────

// Vulnerable: sanitizer is on one branch; sink is reachable via else-branch.
// A path-insensitive engine incorrectly kills taint at the sanitizer and misses
// the bug. Path-sensitive engine keeps taint because bypass path exists.
void vuln_branch_sanitizer(int use_sanitizer) {
    char* data = getenv("CMD");               // source
    if (use_sanitizer) {
        data = sanitize_command(data);        // sanitizer: only on this branch
    }
    system(data);                             // sink: reachable unsanitized via else
}

// Safe: sanitizer executes unconditionally before the sink on every path.
void safe_always_sanitized(void) {
    char* data = getenv("CMD");
    data = sanitize_command(data);            // sanitizer: always executed
    system(data);                             // sink: always sanitized before here
}
