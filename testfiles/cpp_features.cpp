// cpp_features.cpp — C++ grammar smoke-test source.
// Exercises all major C++ grammar constructs for CPG generation testing.
// Not meant to be compiled; parsed by tree-sitter-cpp.

#include <cstddef>

// ── Namespaces ────────────────────────────────────────────────────────────────

namespace outer {
    namespace inner {
        void nested_fn(int x) { (void)x; }
    }
    using namespace inner;
}

namespace outer::combined { // C++17 nested namespace
    void flat_nested(int x) { (void)x; }
}

// ── Templates ─────────────────────────────────────────────────────────────────

template <typename T>
T identity(T x) { return x; }

template <typename T, typename U>
auto add(T a, U b) -> decltype(a + b) { return a + b; }

template <typename... Args>
auto sum_all(Args... args) { return (args + ...); }

template <typename T>
T max_two(T a, T b) { return a > b ? a : b; }

// ── Concepts (C++20) ──────────────────────────────────────────────────────────

template <typename T>
concept Numeric = requires(T a, T b) {
    a + b;
    a - b;
    a * b;
    a / b;
};

template <Numeric T>
T numeric_square(T x) { return x * x; }

template <typename T>
requires (sizeof(T) >= 4)
T large_type_identity(T x) { return x; }

// ── Classes and inheritance ───────────────────────────────────────────────────

class Animal {
protected:
    int age;
    const char* name;
public:
    Animal(int a, const char* n) : age(a), name(n) {}
    virtual ~Animal() = default;
    virtual const char* sound() const { return ""; }
    virtual void speak() { (void)sound(); }
    int get_age() const { return age; }
    const char* get_name() const { return name; }
};

class Dog final : public Animal {
    const char* breed;
public:
    Dog(int a, const char* n, const char* b) : Animal(a, n), breed(b) {}
    const char* sound() const override { return "Woof"; }
    void fetch(const char* item) { (void)item; }
    const char* get_breed() const { return breed; }
};

class Cat : public Animal {
public:
    Cat(int a, const char* n) : Animal(a, n) {}
    const char* sound() const override { return "Meow"; }
};

// Multiple inheritance
struct Flyable { virtual void fly() = 0; };
struct Swimmable { virtual void swim() = 0; };
class Duck : public Animal, public Flyable, public Swimmable {
public:
    Duck() : Animal(1, "duck") {}
    void fly() override {}
    void swim() override {}
    const char* sound() const override { return "Quack"; }
};

// ── Operator overloads ────────────────────────────────────────────────────────

struct Vec2 {
    float x, y;
    Vec2(float x = 0, float y = 0) : x(x), y(y) {}
    Vec2 operator+(const Vec2& o) const { return {x + o.x, y + o.y}; }
    Vec2 operator-(const Vec2& o) const { return {x - o.x, y - o.y}; }
    Vec2& operator+=(const Vec2& o) { x += o.x; y += o.y; return *this; }
    float operator[](int i) const { return i == 0 ? x : y; }
    bool operator==(const Vec2& o) const { return x == o.x && y == o.y; }
    bool operator<(const Vec2& o) const { return x < o.x; }
    operator float() const { return x; }  // conversion operator
};

// Stream operators
struct ostream_like {
    ostream_like& operator<<(int) { return *this; }
    ostream_like& operator<<(const char*) { return *this; }
    ostream_like& operator<<(float) { return *this; }
};

// ── Lambda expressions ────────────────────────────────────────────────────────

int use_lambdas() {
    auto square = [](int x) { return x * x; };
    auto add = [](int a, int b) { return a + b; };

    int base = 10;
    auto add_base = [base](int x) { return x + base; };  // by-value capture

    int counter = 0;
    auto increment = [&counter]() { counter++; };  // by-ref capture

    increment();
    increment();
    int r = square(add_base(add(3, 4)));
    (void)counter;
    return r;
}

// Nested lambdas
void nested_lambdas(int x) {
    auto outer = [x]() {
        auto inner = [x]() {
            return x * 2;
        };
        return inner() + 1;
    };
    (void)outer();
}

// Generic lambda (C++14)
auto generic_lambda = [](auto a, auto b) { return a + b; };

// Lambda with trailing return type
auto typed_lambda = [](int x) -> float { return x * 1.5f; };

// ── Structured bindings (C++17) ───────────────────────────────────────────────

struct Pair { int first; int second; };

int use_structured_bindings() {
    Pair p{3, 7};
    auto [a, b] = p;
    return a + b;
}

// ── Range-based for ───────────────────────────────────────────────────────────

int sum_array(int arr[], int n) {
    int total = 0;
    for (int i = 0; i < n; ++i) {
        total += arr[i];
    }
    return total;
}

// ── Exception handling ────────────────────────────────────────────────────────

int safe_divide(int a, int b) {
    if (b == 0) throw "division by zero";
    return a / b;
}

int divide_or_default(int a, int b, int def) {
    try {
        return safe_divide(a, b);
    } catch (const char* e) {
        (void)e;
        return def;
    } catch (...) {
        return def;
    }
}

// Exception with multiple catch and rethrow
void process_with_exceptions(int x) {
    try {
        try {
            if (x < 0) throw x;
            if (x == 0) throw "zero";
        } catch (int e) {
            if (e < -10) throw;  // rethrow
        }
    } catch (...) {}
}

// ── Smart pointer patterns ────────────────────────────────────────────────────

template <typename T>
struct UniquePtr {
    T* ptr;
    UniquePtr() : ptr(nullptr) {}
    explicit UniquePtr(T* p) : ptr(p) {}
    ~UniquePtr() { delete ptr; }
    UniquePtr(UniquePtr&& o) noexcept : ptr(o.ptr) { o.ptr = nullptr; }
    UniquePtr& operator=(UniquePtr&& o) noexcept {
        if (this != &o) { delete ptr; ptr = o.ptr; o.ptr = nullptr; }
        return *this;
    }
    T* get() const { return ptr; }
    T* operator->() const { return ptr; }
    T& operator*() const { return *ptr; }
    UniquePtr(const UniquePtr&) = delete;
    UniquePtr& operator=(const UniquePtr&) = delete;
};

template <typename T>
struct SharedPtr {
    T* ptr;
    int* ref_count;
    SharedPtr() : ptr(nullptr), ref_count(nullptr) {}
    explicit SharedPtr(T* p) : ptr(p), ref_count(new int(1)) {}
    ~SharedPtr() {
        if (ref_count && --(*ref_count) == 0) {
            delete ptr;
            delete ref_count;
        }
    }
    T* get() const { return ptr; }
};

template <typename T>
struct WeakPtr {
    SharedPtr<T>* shared;
    WeakPtr() : shared(nullptr) {}
    SharedPtr<T> lock() const { return shared ? *shared : SharedPtr<T>(); }
};

// ── Templates with concepts and constraints ───────────────────────────────────

template <typename T>
class Stack {
    T items[256];
    int top_idx;
public:
    Stack() noexcept : top_idx(-1) {}
    ~Stack() = default;

    void push(T val) noexcept {
        if (top_idx < 255) items[++top_idx] = val;
    }
    T pop() {
        if (top_idx < 0) throw "empty stack";
        return items[top_idx--];
    }
    T& top() { return items[top_idx]; }
    bool empty() const noexcept { return top_idx < 0; }
    int size() const noexcept { return top_idx + 1; }

    // Template method within template class
    template <typename Fn>
    void for_each(Fn fn) {
        for (int i = 0; i <= top_idx; ++i) fn(items[i]);
    }
};

// ── Move semantics ────────────────────────────────────────────────────────────

namespace std {
    template <typename T>
    T&& move(T& v) { return static_cast<T&&>(v); }
    template <typename T>
    T&& forward(T& v) { return static_cast<T&&>(v); }
}

struct Buffer {
    char* data;
    int size;

    Buffer(int n) : data(new char[n]), size(n) {}
    ~Buffer() { delete[] data; }

    Buffer(Buffer&& o) noexcept : data(o.data), size(o.size) {
        o.data = nullptr;
        o.size = 0;
    }
    Buffer& operator=(Buffer&& o) noexcept {
        if (this != &o) {
            delete[] data;
            data = o.data;
            size = o.size;
            o.data = nullptr;
            o.size = 0;
        }
        return *this;
    }
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;
};

Buffer create_buffer(int n) {
    Buffer b(n);
    return std::move(b);
}

// ── Trailing return types and auto ────────────────────────────────────────────

auto compute_sum(int a, int b) -> int { return a + b; }

template <typename T>
auto make_pair_like(T a, T b) -> struct { T first; T second; } {
    return {a, b};
}

// ── noexcept ──────────────────────────────────────────────────────────────────

void guaranteed_safe() noexcept {}

template <typename T>
void swap_vals(T& a, T& b) noexcept(noexcept(T(std::move(a)))) {
    T tmp = std::move(a);
    a = std::move(b);
    b = std::move(tmp);
}

// ── friend declarations ───────────────────────────────────────────────────────

class Matrix {
    float data[4][4];
    friend Matrix transpose(const Matrix& m);
    friend class MatrixOps;
public:
    Matrix() {}
    float get(int r, int c) const { return data[r][c]; }
    void set(int r, int c, float v) { data[r][c] = v; }
};

Matrix transpose(const Matrix& m) {
    Matrix t;
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j)
            t.data[i][j] = m.data[j][i];
    return t;
}

class MatrixOps {
public:
    static float trace(const Matrix& m) {
        float t = 0;
        for (int i = 0; i < 4; ++i) t += m.data[i][i];
        return t;
    }
};

// ── using declarations / type aliases ────────────────────────────────────────

using IntStack = Stack<int>;
using CharBuffer = Buffer;

template <typename T>
using Ptr = UniquePtr<T>;

// ── static_assert ─────────────────────────────────────────────────────────────

static_assert(sizeof(int) >= 2, "int must be at least 2 bytes");
static_assert(sizeof(void*) >= 4, "need at least 32-bit pointers");

// ── decltype ──────────────────────────────────────────────────────────────────

int global_val = 42;
decltype(global_val) global_copy = global_val;

template <typename T>
decltype(auto) get_ref(T& val) { return val; }

// ── Access specifiers and visibility ─────────────────────────────────────────

class HiddenState {
    int secret;
protected:
    int semi_secret;
public:
    int visible;

    HiddenState(int s, int ss, int v)
        : secret(s), semi_secret(ss), visible(v) {}

    int reveal() const { return secret; }
};

// ── Constructor/destructor definitions (out-of-line) ─────────────────────────

class OutOfLine {
    int* data;
    int count;
public:
    OutOfLine(int n);
    ~OutOfLine();
    void fill(int val);
};

OutOfLine::OutOfLine(int n) : data(new int[n]), count(n) {}
OutOfLine::~OutOfLine() { delete[] data; }
void OutOfLine::fill(int val) {
    for (int i = 0; i < count; ++i) data[i] = val;
}

// ── new / delete patterns ─────────────────────────────────────────────────────

int* alloc_ints(int n) { return new int[n]; }
void free_ints(int* p) { delete[] p; }

struct Node {
    int val;
    Node* next;
    Node(int v) : val(v), next(nullptr) {}
};

Node* build_list(int n) {
    Node* head = nullptr;
    for (int i = 0; i < n; ++i) {
        Node* node = new Node(i);
        node->next = head;
        head = node;
    }
    return head;
}

void free_list(Node* head) {
    while (head) {
        Node* next = head->next;
        delete head;
        head = next;
    }
}

// ── Fold expressions ─────────────────────────────────────────────────────────

template <typename... T>
bool all_positive(T... vals) { return (... && (vals > 0)); }

template <typename... T>
bool any_negative(T... vals) { return (... || (vals < 0)); }

template <typename... T>
auto product(T... vals) { return (vals * ...); }

template <typename T, typename... Args>
void print_all(T first, Args... rest) {
    (void)first;
    ((void)rest, ...);  // fold expression with comma
}

// ── Variadic templates ────────────────────────────────────────────────────────

template <typename First, typename... Rest>
struct TypeList {
    using head = First;
    static constexpr int size = 1 + sizeof...(Rest);
};

template <typename... Args>
void forward_all(void (*fn)(Args...), Args... args) {
    fn(args...);
}

// ── C++20 explicit object parameter (deducing this) ─────────────────────────

struct Chainable {
    int value;
    Chainable(int v) : value(v) {}
    Chainable& set(this Chainable& self, int v) { self.value = v; return self; }
    int get(this const Chainable& self) { return self.value; }
};

// ── Coroutines (C++20) ────────────────────────────────────────────────────────

struct Task {
    struct promise_type {
        Task get_return_object() { return {}; }
        struct suspend_never { bool await_ready() { return true; } void await_suspend(void*) {} void await_resume() {} };
        suspend_never initial_suspend() { return {}; }
        suspend_never final_suspend() noexcept { return {}; }
        void return_void() {}
        void unhandled_exception() {}
    };
};

Task async_identity(int x) {
    co_return;
    (void)x;
}

struct Generator {
    struct promise_type {
        Generator get_return_object() { return {}; }
        struct suspend_always { bool await_ready() { return false; } void await_suspend(void*) {} void await_resume() {} };
        suspend_always initial_suspend() { return {}; }
        suspend_always final_suspend() noexcept { return {}; }
        void return_void() {}
        void unhandled_exception() {}
        int current_value;
        suspend_always yield_value(int v) { current_value = v; return {}; }
    };
};

Generator count_range(int start, int end) {
    for (int i = start; i < end; ++i) {
        co_yield i;
    }
}

// ── Linkage specification ─────────────────────────────────────────────────────

extern "C" {
    void c_style_function(int x) { (void)x; }
    int c_style_compute(int a, int b) { return a + b; }
}

// ── Module-style code (non-module syntax for compatibility) ──────────────────

// Inline namespace (versioning)
namespace api {
    inline namespace v2 {
        void process(int x) { (void)x; }
    }
    namespace v1 {
        void process(int x) { (void)x; }
    }
}

// ── CRTP pattern ──────────────────────────────────────────────────────────────

template <typename Derived>
struct Printable {
    void print() const {
        static_cast<const Derived*>(this)->print_impl();
    }
};

struct MyPrintable : Printable<MyPrintable> {
    void print_impl() const {}
};

// ── Type aliases and using ────────────────────────────────────────────────────

namespace detail {
    template <typename T>
    struct remove_ref { using type = T; };
    template <typename T>
    struct remove_ref<T&> { using type = T; };
    template <typename T>
    using remove_ref_t = typename remove_ref<T>::type;
}

// ── Ref qualifiers on methods ─────────────────────────────────────────────────

struct RefQualified {
    int* data;
    int size;

    int* get() & { return data; }
    const int* get() const & { return data; }
    int* get() && { return data; }

    RefQualified& mutate() & { return *this; }
    RefQualified mutate() && { return static_cast<RefQualified&&>(*this); }
};

// ── Deduction guides (C++17) ─────────────────────────────────────────────────

template <typename T>
struct Wrapper {
    T value;
    Wrapper(T v) : value(v) {}
};

Wrapper(const char*) -> Wrapper<const char*>;
Wrapper(int) -> Wrapper<int>;

// ── main ──────────────────────────────────────────────────────────────────────

int main() {
    // Use various features
    IntStack s;
    s.push(1);
    s.push(2);
    s.push(3);

    Dog d(3, "Rex", "Labrador");
    d.speak();
    d.fetch("ball");

    Vec2 v1(1.0f, 2.0f), v2(3.0f, 4.0f);
    Vec2 v3 = v1 + v2;
    v3 += v1;

    int r = use_lambdas();
    int sum = use_structured_bindings();
    int total = compute_sum(r, sum);

    Buffer buf = create_buffer(100);

    Chainable c(0);
    c.set(42).set(c.get() + 1);

    (void)v3;
    (void)total;
    (void)buf;

    return 0;
}
