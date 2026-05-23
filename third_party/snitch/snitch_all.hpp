#ifndef SNITCH_ALL_HPP
#define SNITCH_ALL_HPP
#ifndef SNITCH_CONFIG_HPP
#define SNITCH_CONFIG_HPP

#include <version> // for C++ feature check macros

// These are defined from build-time configuration.
// clang-format off
#define SNITCH_VERSION "1.4.0"
#define SNITCH_FULL_VERSION "1.4.0"
#define SNITCH_VERSION_MAJOR 1
#define SNITCH_VERSION_MINOR 4
#define SNITCH_VERSION_PATCH 0

#if !defined(SNITCH_MAX_TEST_CASES)
#    define SNITCH_MAX_TEST_CASES 256
#endif
#if !defined(SNITCH_MAX_NESTED_SECTIONS)
#    define SNITCH_MAX_NESTED_SECTIONS 8
#endif
#if !defined(SNITCH_MAX_EXPR_LENGTH)
#    define SNITCH_MAX_EXPR_LENGTH 256
#endif
#if !defined(SNITCH_MAX_MESSAGE_LENGTH)
#    define SNITCH_MAX_MESSAGE_LENGTH 256
#endif
#if !defined(SNITCH_MAX_TEST_NAME_LENGTH)
#    define SNITCH_MAX_TEST_NAME_LENGTH 256
#endif
#if !defined(SNITCH_MAX_TAG_LENGTH)
#    define SNITCH_MAX_TAG_LENGTH 64
#endif
#if !defined(SNITCH_MAX_CAPTURES)
#    define SNITCH_MAX_CAPTURES 8
#endif
#if !defined(SNITCH_MAX_CAPTURE_LENGTH)
#    define SNITCH_MAX_CAPTURE_LENGTH 128
#endif
#if !defined(SNITCH_MAX_UNIQUE_TAGS)
#    define SNITCH_MAX_UNIQUE_TAGS 64
#endif
#if !defined(SNITCH_MAX_COMMAND_LINE_ARGS)
#    define SNITCH_MAX_COMMAND_LINE_ARGS 64
#endif
#if !defined(SNITCH_MAX_REGISTERED_REPORTERS)
#    define SNITCH_MAX_REGISTERED_REPORTERS 2
#endif
#if !defined(SNITCH_MAX_PATH_LENGTH)
#    define SNITCH_MAX_PATH_LENGTH 128
#endif
#if !defined(SNITCH_MAX_REPORTER_SIZE_BYTES)
#    define SNITCH_MAX_REPORTER_SIZE_BYTES 128
#endif
#if !defined(SNITCH_MAX_FILE_OBJECT_SIZE_BYTES)
#    define SNITCH_MAX_FILE_OBJECT_SIZE_BYTES 128
#endif
#if !defined(SNITCH_DEFINE_MAIN)
#define SNITCH_DEFINE_MAIN 0
#endif
#if !defined(SNITCH_WITH_STDOUT)
#define SNITCH_WITH_STDOUT 0
#endif
#if !defined(SNITCH_WITH_STD_FILE_IO)
#define SNITCH_WITH_STD_FILE_IO 0
#endif
#if !defined(SNITCH_WITH_EXCEPTIONS)
#define SNITCH_WITH_EXCEPTIONS 0
#endif
#if !defined(SNITCH_WITH_TIMINGS)
#define SNITCH_WITH_TIMINGS 0
#endif
#if !defined(SNITCH_WITH_SHORTHAND_MACROS)
#define SNITCH_WITH_SHORTHAND_MACROS 1
#endif
#if !defined(SNITCH_DEFAULT_WITH_COLOR)
#define SNITCH_DEFAULT_WITH_COLOR 0
#endif
#if !defined(SNITCH_CONSTEXPR_FLOAT_USE_BITCAST)
#define SNITCH_CONSTEXPR_FLOAT_USE_BITCAST 0
#endif
#if !defined(SNITCH_APPEND_TO_CHARS)
#define SNITCH_APPEND_TO_CHARS 0
#endif
#if !defined(SNITCH_DECOMPOSE_SUCCESSFUL_ASSERTIONS)
#define SNITCH_DECOMPOSE_SUCCESSFUL_ASSERTIONS 0
#endif
#if !defined(SNITCH_WITH_ALL_REPORTERS)
#define SNITCH_WITH_ALL_REPORTERS 0
#endif
#if !defined(SNITCH_WITH_TEAMCITY_REPORTER)
#define SNITCH_WITH_TEAMCITY_REPORTER 0
#endif
#if !defined(SNITCH_WITH_CATCH2_XML_REPORTER)
#define SNITCH_WITH_CATCH2_XML_REPORTER 0
#endif
#if !defined(SNITCH_WITH_MULTITHREADING)
#define SNITCH_WITH_MULTITHREADING 0
#endif
#if !defined(SNITCH_SHARED_LIBRARY)
#define SNITCH_SHARED_LIBRARY 0
#endif
#if !defined(SNITCH_ENABLE)
#define SNITCH_ENABLE 1
#endif
// clang-format on

#if defined(_MSC_VER)
#    if defined(_KERNEL_MODE) || (defined(_HAS_EXCEPTIONS) && !_HAS_EXCEPTIONS)
#        define SNITCH_EXCEPTIONS_NOT_AVAILABLE
#    endif
#elif defined(__clang__) || defined(__GNUC__)
#    if !defined(__EXCEPTIONS)
#        define SNITCH_EXCEPTIONS_NOT_AVAILABLE
#    endif
#endif

#if defined(SNITCH_EXCEPTIONS_NOT_AVAILABLE)
#    undef SNITCH_WITH_EXCEPTIONS
#    define SNITCH_WITH_EXCEPTIONS 0
#endif

#if SNITCH_WITH_MULTITHREADING
#    define SNITCH_THREAD_LOCAL thread_local
#else
#    define SNITCH_THREAD_LOCAL
#endif

#if !defined(__cpp_lib_bit_cast)
#    undef SNITCH_CONSTEXPR_FLOAT_USE_BITCAST
#    define SNITCH_CONSTEXPR_FLOAT_USE_BITCAST 0
#endif

#if (!defined(__cpp_lib_to_chars)) || (defined(_GLIBCXX_RELEASE) && _GLIBCXX_RELEASE <= 11) ||     \
    (defined(_LIBCPP_VERSION) && _LIBCPP_VERSION <= 14000) ||                                      \
    (defined(_MSC_VER) && _MSC_VER <= 1924)
#    undef SNITCH_APPEND_TO_CHARS
#    define SNITCH_APPEND_TO_CHARS 0
#endif

#if SNITCH_SHARED_LIBRARY
#    if defined(_MSC_VER)
#        if defined(SNITCH_EXPORTS)
#            define SNITCH_EXPORT __declspec(dllexport)
#        else
#            define SNITCH_EXPORT __declspec(dllimport)
#        endif
#    elif defined(__clang__) || defined(__GNUC__)
#        define SNITCH_EXPORT [[gnu::visibility("default")]]
#    else
#        define SNITCH_EXPORT
#    endif
#else
#    define SNITCH_EXPORT
#endif

#endif

#ifndef SNITCH_CONCEPTS_HPP
#define SNITCH_CONCEPTS_HPP


#include <type_traits>

namespace snitch {

template<typename T>
concept integral = std::is_integral_v<T>;

template<typename T>
concept signed_integral = integral<T> && std::is_signed_v<T>;

template<typename T>
concept unsigned_integral = integral<T> && std::is_unsigned_v<T>;

template<typename T>
concept floating_point = std::is_floating_point_v<T>;

template<typename T, typename U>
concept convertible_to = std::is_convertible_v<T, U>;

template<typename T, typename U>
concept same_as = std::is_same_v<T, U>;

template<typename T>
concept enumeration = std::is_enum_v<T>;

namespace impl {
template<typename T>
using decay_object = std::remove_cv_t<std::remove_reference_t<T>>;

template<typename T>
struct is_function_pointer : std::false_type {};
template<typename T>
struct is_function_pointer<T*> : std::is_function<T> {};
} // namespace impl

template<typename T>
struct is_function_pointer : impl::is_function_pointer<std::remove_cv_t<T>> {};

template<typename T>
constexpr bool is_function_pointer_v = is_function_pointer<T>::value;

template<typename T>
concept function_pointer = is_function_pointer_v<impl::decay_object<T>>;

template<typename T>
concept member_function_pointer = std::is_member_function_pointer_v<impl::decay_object<T>>;

template<std::size_t N>
using char_array = char[N];

template<typename T>
struct is_raw_string : std::false_type {};
template<std::size_t N>
struct is_raw_string<char_array<N>> : std::true_type {};

template<typename T>
constexpr bool is_raw_string_v = is_raw_string<T>::value;

template<typename T>
concept raw_string = is_raw_string_v<impl::decay_object<T>>;

template<typename T>
concept pointer = std::is_pointer_v<impl::decay_object<T>>;
} // namespace snitch

#endif

#ifndef SNITCH_FUNCTION_HPP
#define SNITCH_FUNCTION_HPP


#include <utility>
#include <variant>

namespace snitch {
template<typename... Args>
struct overload : Args... {
    using Args::operator()...;
};

template<typename... Args>
overload(Args...) -> overload<Args...>;

template<auto T>
struct constant {
    static constexpr auto value = T;
};
} // namespace snitch

namespace snitch::impl {
template<typename T>
struct function_traits {
    static_assert(!std::is_same_v<T, T>, "incorrect template parameter for function_ref");
};

template<typename T, bool Noexcept>
struct function_traits_base {
    static_assert(!std::is_same_v<T, T>, "incorrect template parameter for function_ref");
};

template<typename Ret, typename... Args>
struct function_traits<Ret(Args...) noexcept> {
    using return_type             = Ret;
    using function_ptr            = Ret (*)(Args...) noexcept;
    using function_data_ptr       = Ret (*)(void*, Args...) noexcept;
    using function_const_data_ptr = Ret (*)(const void*, Args...) noexcept;

    static constexpr bool is_noexcept = true;

    template<typename ObjectType, auto MemberFunction>
    static constexpr function_data_ptr to_free_function() noexcept {
        return [](void* ptr, Args... args) noexcept {
            if constexpr (std::is_same_v<return_type, void>) {
                (static_cast<ObjectType*>(ptr)->*constant<MemberFunction>::value)(
                    std::forward<Args>(args)...);
            } else {
                return (static_cast<ObjectType*>(ptr)->*constant<MemberFunction>::value)(
                    std::forward<Args>(args)...);
            }
        };
    }

    template<typename ObjectType, auto MemberFunction>
    static constexpr function_const_data_ptr to_const_free_function() noexcept {
        return [](const void* ptr, Args... args) noexcept {
            if constexpr (std::is_same_v<return_type, void>) {
                (static_cast<const ObjectType*>(ptr)->*constant<MemberFunction>::value)(
                    std::forward<Args>(args)...);
            } else {
                return (static_cast<const ObjectType*>(ptr)->*constant<MemberFunction>::value)(
                    std::forward<Args>(args)...);
            }
        };
    }
};

template<typename Ret, typename... Args>
struct function_traits<Ret(Args...)> {
    using return_type             = Ret;
    using function_ptr            = Ret (*)(Args...);
    using function_data_ptr       = Ret (*)(void*, Args...);
    using function_const_data_ptr = Ret (*)(const void*, Args...);

    static constexpr bool is_noexcept = false;

    template<typename ObjectType, auto MemberFunction>
    static constexpr function_data_ptr to_free_function() noexcept {
        return [](void* ptr, Args... args) {
            if constexpr (std::is_same_v<return_type, void>) {
                (static_cast<ObjectType*>(ptr)->*constant<MemberFunction>::value)(
                    std::forward<Args>(args)...);
            } else {
                return (static_cast<ObjectType*>(ptr)->*constant<MemberFunction>::value)(
                    std::forward<Args>(args)...);
            }
        };
    }

    template<typename ObjectType, auto MemberFunction>
    static constexpr function_const_data_ptr to_const_free_function() noexcept {
        return [](const void* ptr, Args... args) {
            if constexpr (std::is_same_v<return_type, void>) {
                (static_cast<const ObjectType*>(ptr)->*constant<MemberFunction>::value)(
                    std::forward<Args>(args)...);
            } else {
                return (static_cast<const ObjectType*>(ptr)->*constant<MemberFunction>::value)(
                    std::forward<Args>(args)...);
            }
        };
    }
};
} // namespace snitch::impl

namespace snitch {
template<typename T>
class function_ref;

namespace impl {
template<typename T>
struct is_function_ref : std::false_type {};

template<typename T>
struct is_function_ref<function_ref<T>> : std::true_type {};

template<typename T>
concept not_function_ref = !is_function_ref<T>::value;

template<typename T, typename FunPtr>
concept function_ptr_or_stateless_lambda = not_function_ref<T> && convertible_to<T, FunPtr>;

template<typename T, typename FunPtr>
concept functor = not_function_ref<T> && !function_ptr_or_stateless_lambda<T, FunPtr> &&
                  requires { &T::operator(); };

template<typename T>
using function_ptr = T*;
} // namespace impl

template<typename T>
class function_ref {
    using traits = impl::function_traits<T>;

public:
    using return_type             = typename traits::return_type;
    using function_ptr            = typename traits::function_ptr;
    using function_data_ptr       = typename traits::function_data_ptr;
    using function_const_data_ptr = typename traits::function_const_data_ptr;

private:
    struct function_and_data_ptr {
        void*             data = nullptr;
        function_data_ptr ptr;
    };

    struct function_and_const_data_ptr {
        const void*             data = nullptr;
        function_const_data_ptr ptr;
    };

    using data_type =
        std::variant<function_ptr, function_and_data_ptr, function_and_const_data_ptr>;

    data_type data;

public:
    constexpr function_ref(const function_ref&) noexcept            = default;
    constexpr function_ref& operator=(const function_ref&) noexcept = default;

    template<impl::function_ptr_or_stateless_lambda<function_ptr> FunctionType>
    constexpr function_ref(const FunctionType& obj) noexcept :
        data{static_cast<function_ptr>(obj)} {}

    template<impl::functor<function_ptr> FunctorType>
    constexpr function_ref(FunctorType& obj) noexcept :
        function_ref(obj, constant<&FunctorType::operator()>{}) {}

    template<impl::functor<function_ptr> FunctorType>
    constexpr function_ref(const FunctorType& obj) noexcept :
        function_ref(obj, constant<&FunctorType::operator()>{}) {}

    // Prevent inadvertently using temporary stateful lambda; not supported at the moment.
    template<impl::functor<function_ptr> FunctorType>
    constexpr function_ref(FunctorType&& obj) noexcept = delete;

    template<typename ObjectType, auto MemberFunction>
    constexpr function_ref(ObjectType& obj, constant<MemberFunction>) noexcept :
        data{function_and_data_ptr{
            &obj, traits::template to_free_function<ObjectType, MemberFunction>()}} {}

    template<typename ObjectType, auto MemberFunction>
    constexpr function_ref(const ObjectType& obj, constant<MemberFunction>) noexcept :
        data{function_and_const_data_ptr{
            &obj, traits::template to_const_free_function<ObjectType, MemberFunction>()}} {}

    // Prevent inadvertently using temporary object; not supported at the moment.
    template<typename ObjectType, auto M>
    constexpr function_ref(ObjectType&& obj, constant<M>) noexcept = delete;

    template<typename... CArgs>
    constexpr return_type operator()(CArgs&&... args) const noexcept(traits::is_noexcept) {
        if constexpr (std::is_same_v<return_type, void>) {
            std::visit(
                overload{
                    [&](function_ptr f) { (*f)(std::forward<CArgs>(args)...); },
                    [&](const function_and_data_ptr& f) {
                        (*f.ptr)(f.data, std::forward<CArgs>(args)...);
                    },
                    [&](const function_and_const_data_ptr& f) {
                        (*f.ptr)(f.data, std::forward<CArgs>(args)...);
                    }},
                data);
        } else {
            return std::visit(
                overload{
                    [&](function_ptr f) { return (*f)(std::forward<CArgs>(args)...); },
                    [&](const function_and_data_ptr& f) {
                        return (*f.ptr)(f.data, std::forward<CArgs>(args)...);
                    },
                    [&](const function_and_const_data_ptr& f) {
                        return (*f.ptr)(f.data, std::forward<CArgs>(args)...);
                    }},
                data);
        }
    }
};
} // namespace snitch

#endif

#ifndef SNITCH_ERROR_HANDLING_HPP
#define SNITCH_ERROR_HANDLING_HPP


#include <string_view>

namespace snitch {
// Maximum length of error messages.
constexpr std::size_t max_message_length = SNITCH_MAX_MESSAGE_LENGTH;

[[noreturn]] SNITCH_EXPORT void terminate_with(std::string_view msg) noexcept;

SNITCH_EXPORT extern function_ref<void(std::string_view)> assertion_failed_handler;

[[noreturn]] SNITCH_EXPORT void assertion_failed(std::string_view msg);
} // namespace snitch

#endif

#ifndef SNITCH_TYPE_ID_HPP
#define SNITCH_TYPE_ID_HPP


namespace snitch {
using type_id_t = const void*;
}

namespace snitch::impl {
template<typename T>
struct type_id {
    constexpr static char value = 0;
};
} // namespace snitch::impl

namespace snitch {
template<typename T>
type_id_t type_id() noexcept {
    return &impl::type_id<T>::value;
}

template<>
constexpr type_id_t type_id<void>() noexcept {
    return nullptr;
}
} // namespace snitch

#endif

#ifndef SNITCH_ANY_HPP
#define SNITCH_ANY_HPP


#include <array>
#include <cstddef>
#include <utility>

namespace snitch {
namespace impl {
struct basic_vtable {
    type_id_t                                 id            = snitch::type_id<void>();
    function_ptr<void(void*) noexcept>        delete_object = [](void*) noexcept {};
    function_ptr<void(void*, void*) noexcept> move_object   = [](void*, void*) noexcept {};
};

SNITCH_EXPORT extern const basic_vtable empty_vtable;

template<typename T>
const basic_vtable* get_vtable() noexcept {
    static const basic_vtable table{
        .id            = snitch::type_id<T>(),
        .delete_object = [](void* storage) noexcept { reinterpret_cast<T*>(storage)->~T(); },
        .move_object =
            [](void* storage, void* from) noexcept {
                new (storage) T(std::move(*reinterpret_cast<T*>(from)));
            }};
    return &table;
}
} // namespace impl

template<std::size_t MaxSize>
class inplace_any {
    std::array<char, MaxSize> storage = {};
    const impl::basic_vtable* vtable  = &impl::empty_vtable;

    template<typename T>
    void check() const {
        if (vtable != impl::get_vtable<T>()) {
            if (vtable == &impl::empty_vtable) {
                assertion_failed("inplace_any is empty");
            } else {
                assertion_failed("inplace_any holds an object of a different type");
            }
        }
    }

public:
    constexpr inplace_any() = default;

    inplace_any(const inplace_any&) = delete;

    constexpr inplace_any(inplace_any&& other) noexcept : vtable(other.vtable) {
        vtable->move_object(storage.data(), other.storage.data());
        other.reset();
    }

    inplace_any& operator=(const inplace_any&) = delete;

    constexpr inplace_any& operator=(inplace_any&& other) noexcept {
        vtable->delete_object(storage.data());
        vtable = other.vtable;
        vtable->move_object(storage.data(), other.storage.data());
        other.reset();
        return *this;
    }

    template<typename T, typename... Args>
    explicit inplace_any(std::in_place_type_t<T>, Args&&... args) {
        emplace<T>(std::forward<Args>(args)...);
    }

    ~inplace_any() {
        reset();
    }

    bool has_value() const noexcept {
        return vtable != &impl::empty_vtable;
    }

    type_id_t type() const noexcept {
        return vtable->id;
    }

    template<typename T, typename... Args>
    T& emplace(Args&&... args) {
        static_assert(
            sizeof(T) <= MaxSize,
            "This type is too large to fit in this inplace_any, increase storage size");

        vtable->delete_object(storage.data());
        new (storage.data()) T(std::forward<Args>(args)...);
        vtable = impl::get_vtable<T>();
        return *reinterpret_cast<T*>(storage.data());
    }

    // Requires: not empty and stored type == T.
    template<typename T>
    const T& get() const {
        check<T>();
        return *reinterpret_cast<const T*>(storage.data());
    }

    // Requires: not empty and stored type == T.
    template<typename T>
    T& get() {
        check<T>();
        return *reinterpret_cast<T*>(storage.data());
    }

    // Requires: not empty and stored type == T.
    template<typename T>
    T& get_mutable() const {
        check<T>();
        return const_cast<T&>(*reinterpret_cast<const T*>(storage.data()));
    }

    void reset() noexcept {
        vtable->delete_object(storage.data());
        vtable = &impl::empty_vtable;
    }
};
} // namespace snitch

#endif

#ifndef SNITCH_FIXED_POINT_HPP
#define SNITCH_FIXED_POINT_HPP


#include <cstddef>
#include <cstdint>
#if SNITCH_CONSTEXPR_FLOAT_USE_BITCAST
#    include <bit> // for compile-time float to string
#endif
#include <array>
#include <limits>

namespace snitch::impl {
using fixed_digits_t = std::uint64_t;
using fixed_exp_t    = std::int32_t;

struct unsigned_fixed_data {
    fixed_digits_t digits   = 0;
    fixed_exp_t    exponent = 0;
};

struct signed_fixed_data {
    fixed_digits_t digits   = 0;
    fixed_exp_t    exponent = 0;
    bool           sign     = false;
};

struct unpacked64 {
    std::uint64_t l;
    std::uint64_t u;
};

constexpr unpacked64 unpack10(std::uint64_t v) noexcept {
    return {v % 10'000'000'000, v / 10'000'000'000};
}

class unsigned_fixed {
    unsigned_fixed_data data = {};

    constexpr void raise_exponent_to(fixed_exp_t new_exponent) noexcept {
        do {
            if (data.digits == 0u) {
                data.exponent = new_exponent;
            } else if (data.exponent < new_exponent - 1) {
                data.digits = data.digits / 10u;
                data.exponent += 1;
            } else {
                data.digits = (data.digits + 5u) / 10u;
                data.exponent += 1;
            }
        } while (data.exponent < new_exponent);
    }

    constexpr void raise_exponent() noexcept {
        data.digits = (data.digits + 5u) / 10u;
        data.exponent += 1;
    }

public:
    constexpr unsigned_fixed(fixed_digits_t digits_in, fixed_exp_t exponent_in) noexcept {
        // Normalise inputs so that we maximize the number of digits stored.
        if (digits_in > 0) {
            constexpr fixed_digits_t cap = std::numeric_limits<fixed_digits_t>::max() / 10u;

            if (digits_in < cap) {
                do {
                    digits_in *= 10u;
                    exponent_in -= 1;
                } while (digits_in < cap);
            }
        } else {
            // Pick the smallest possible exponent for zero;
            // This guarantees that we will preserve precision for whatever number
            // gets added to this.
            exponent_in = std::numeric_limits<fixed_exp_t>::min();
        }

        data.digits   = digits_in;
        data.exponent = exponent_in;
    }

    constexpr fixed_digits_t digits() const noexcept {
        return data.digits;
    }

    constexpr fixed_exp_t exponent() const noexcept {
        return data.exponent;
    }

    friend constexpr unsigned_fixed operator+(unsigned_fixed f1, unsigned_fixed f2) noexcept {
        // Bring both numbers to the same exponent before summing.
        // To prevent overflow: add one to the exponent.
        if (f1.data.exponent > f2.data.exponent) {
            f1.raise_exponent();
            f2.raise_exponent_to(f1.data.exponent + 1);
        } else if (f1.data.exponent < f2.data.exponent) {
            f1.raise_exponent_to(f2.data.exponent + 1);
            f2.raise_exponent();
        } else {
            f1.raise_exponent();
            f2.raise_exponent();
        }

        return unsigned_fixed(f1.data.digits + f2.data.digits, f1.data.exponent);
    }

    constexpr unsigned_fixed& operator+=(const unsigned_fixed f) noexcept {
        return *this = *this + f;
    }

    friend constexpr unsigned_fixed
    operator*(const unsigned_fixed f1, const unsigned_fixed f2) noexcept {
        // To prevent overflow: split each number as f_i = u_i*1e10 + l_i,
        // with l_i and u_i < 1e10, then develop the multiplication of each component:
        //   r = f1*f2 = u1*u2*1e20 + (l1*u2 + l2*u1)*1e10 + l1*l2
        // The resulting integer would overflow, so insted of storing the digits of r, we
        // store the digits of r/1e20:
        //   r/1e20 = u1*u2 + (l1*u2 + l2*u1)/1e10 + l1*l2/1e20 = u + l/1e10 + ll/1e20.
        // For simplicity, we ignore the term ll/1e20 since it is < 0.2 and would at most
        // contribute to changing the last digit of the output integer.

        const auto [l1, u1] = unpack10(f1.data.digits);
        const auto [l2, u2] = unpack10(f2.data.digits);

        // For the (l1*u2 + l2*u1) term, divide by 10 and round each component before summing,
        // since the addition may overflow. Note: although l < 1e10, and l*l can overflow, u < 2e9
        // so l*u cannot overflow.
        const fixed_digits_t l_over_10 = (l1 * u2 + 5u) / 10u + (l2 * u1 + 5u) / 10u;
        // Then shift the digits to the right, with rounding.
        const fixed_digits_t l_over_1e10 = (l_over_10 + 500'000'000) / 1'000'000'000;

        // u1*u2 is straightforward.
        const fixed_digits_t u = u1 * u2;

        // Adding back the lower part cannot overflow, by construction. The exponent
        // is increased by 20 because we computed the digits of (f1*f2)/1e20.
        return unsigned_fixed(u + l_over_1e10, f1.data.exponent + f2.data.exponent + 20);
    }

    constexpr unsigned_fixed& operator*=(const unsigned_fixed f) noexcept {
        return *this = *this * f;
    }
};

template<typename T>
struct float_traits;

template<>
struct float_traits<float> {
    using bits_full_t = std::uint32_t;
    using bits_sig_t  = std::uint32_t;
    using bits_exp_t  = std::uint8_t;

    using int_exp_t = std::int32_t;

    static constexpr bits_full_t bits     = 8u * sizeof(bits_full_t);
    static constexpr bits_full_t sig_bits = 23u;
    static constexpr bits_full_t exp_bits = bits - sig_bits - 1u;

    static constexpr bits_full_t sign_mask = bits_full_t{1u} << (bits - 1u);
    static constexpr bits_full_t sig_mask  = (bits_full_t{1u} << sig_bits) - 1u;
    static constexpr bits_full_t exp_mask  = ((bits_full_t{1u} << (bits - 1u)) - 1u) & ~sig_mask;

    static constexpr int_exp_t exp_origin    = -127;
    static constexpr int_exp_t exp_subnormal = exp_origin + 1;

    static constexpr bits_exp_t exp_bits_special = 0xff;
    static constexpr bits_sig_t sig_bits_nan     = 0x400000;
    static constexpr bits_sig_t sig_bits_inf     = 0x0;

    static constexpr std::size_t precision = 9u;

    static constexpr std::array<unsigned_fixed, sig_bits> sig_elems = {
        {unsigned_fixed(1192092895507812500u, -25), unsigned_fixed(2384185791015625000u, -25),
         unsigned_fixed(4768371582031250000u, -25), unsigned_fixed(9536743164062500000u, -25),
         unsigned_fixed(1907348632812500000u, -24), unsigned_fixed(3814697265625000000u, -24),
         unsigned_fixed(7629394531250000000u, -24), unsigned_fixed(1525878906250000000u, -23),
         unsigned_fixed(3051757812500000000u, -23), unsigned_fixed(6103515625000000000u, -23),
         unsigned_fixed(1220703125000000000u, -22), unsigned_fixed(2441406250000000000u, -22),
         unsigned_fixed(4882812500000000000u, -22), unsigned_fixed(9765625000000000000u, -22),
         unsigned_fixed(1953125000000000000u, -21), unsigned_fixed(3906250000000000000u, -21),
         unsigned_fixed(7812500000000000000u, -21), unsigned_fixed(1562500000000000000u, -20),
         unsigned_fixed(3125000000000000000u, -20), unsigned_fixed(6250000000000000000u, -20),
         unsigned_fixed(1250000000000000000u, -19), unsigned_fixed(2500000000000000000u, -19),
         unsigned_fixed(5000000000000000000u, -19)}};
};

template<>
struct float_traits<double> {
    using bits_full_t = std::uint64_t;
    using bits_sig_t  = std::uint64_t;
    using bits_exp_t  = std::uint16_t;

    using int_exp_t = std::int32_t;

    static constexpr bits_full_t bits     = 8u * sizeof(bits_full_t);
    static constexpr bits_full_t sig_bits = 52u;
    static constexpr bits_full_t exp_bits = bits - sig_bits - 1u;

    static constexpr bits_full_t sign_mask = bits_full_t{1u} << (bits - 1u);
    static constexpr bits_full_t sig_mask  = (bits_full_t{1u} << sig_bits) - 1u;
    static constexpr bits_full_t exp_mask  = ((bits_full_t{1u} << (bits - 1u)) - 1u) & ~sig_mask;

    static constexpr int_exp_t exp_origin    = -1023;
    static constexpr int_exp_t exp_subnormal = exp_origin + 1;

    static constexpr bits_exp_t exp_bits_special = 0x7ff;
    static constexpr bits_sig_t sig_bits_nan     = 0x8000000000000;
    static constexpr bits_sig_t sig_bits_inf     = 0x0;

    static constexpr std::size_t precision = 17u;

    static constexpr std::array<unsigned_fixed, sig_bits> sig_elems = {
        {unsigned_fixed(2220446049250313081u, -34), unsigned_fixed(4440892098500626162u, -34),
         unsigned_fixed(8881784197001252323u, -34), unsigned_fixed(1776356839400250465u, -33),
         unsigned_fixed(3552713678800500929u, -33), unsigned_fixed(7105427357601001859u, -33),
         unsigned_fixed(1421085471520200372u, -32), unsigned_fixed(2842170943040400743u, -32),
         unsigned_fixed(5684341886080801487u, -32), unsigned_fixed(1136868377216160297u, -31),
         unsigned_fixed(2273736754432320595u, -31), unsigned_fixed(4547473508864641190u, -31),
         unsigned_fixed(9094947017729282379u, -31), unsigned_fixed(1818989403545856476u, -30),
         unsigned_fixed(3637978807091712952u, -30), unsigned_fixed(7275957614183425903u, -30),
         unsigned_fixed(1455191522836685181u, -29), unsigned_fixed(2910383045673370361u, -29),
         unsigned_fixed(5820766091346740723u, -29), unsigned_fixed(1164153218269348145u, -28),
         unsigned_fixed(2328306436538696289u, -28), unsigned_fixed(4656612873077392578u, -28),
         unsigned_fixed(9313225746154785156u, -28), unsigned_fixed(1862645149230957031u, -27),
         unsigned_fixed(3725290298461914062u, -27), unsigned_fixed(7450580596923828125u, -27),
         unsigned_fixed(1490116119384765625u, -26), unsigned_fixed(2980232238769531250u, -26),
         unsigned_fixed(5960464477539062500u, -26), unsigned_fixed(1192092895507812500u, -25),
         unsigned_fixed(2384185791015625000u, -25), unsigned_fixed(4768371582031250000u, -25),
         unsigned_fixed(9536743164062500000u, -25), unsigned_fixed(1907348632812500000u, -24),
         unsigned_fixed(3814697265625000000u, -24), unsigned_fixed(7629394531250000000u, -24),
         unsigned_fixed(1525878906250000000u, -23), unsigned_fixed(3051757812500000000u, -23),
         unsigned_fixed(6103515625000000000u, -23), unsigned_fixed(1220703125000000000u, -22),
         unsigned_fixed(2441406250000000000u, -22), unsigned_fixed(4882812500000000000u, -22),
         unsigned_fixed(9765625000000000000u, -22), unsigned_fixed(1953125000000000000u, -21),
         unsigned_fixed(3906250000000000000u, -21), unsigned_fixed(7812500000000000000u, -21),
         unsigned_fixed(1562500000000000000u, -20), unsigned_fixed(3125000000000000000u, -20),
         unsigned_fixed(6250000000000000000u, -20), unsigned_fixed(1250000000000000000u, -19),
         unsigned_fixed(2500000000000000000u, -19), unsigned_fixed(5000000000000000000u, -19)}};
};

template<typename T>
struct float_bits {
    using traits = float_traits<T>;

    typename traits::bits_sig_t significand = 0u;
    typename traits::bits_exp_t exponent    = 0u;
    bool                        sign        = 0;
};

template<typename T>
[[nodiscard]] constexpr float_bits<T> to_bits(T f) noexcept {
    using traits      = float_traits<T>;
    using bits_full_t = typename traits::bits_full_t;
    using bits_sig_t  = typename traits::bits_sig_t;
    using bits_exp_t  = typename traits::bits_exp_t;

#if SNITCH_CONSTEXPR_FLOAT_USE_BITCAST

    const bits_full_t bits = std::bit_cast<bits_full_t>(f);

    return float_bits<T>{
        .significand = static_cast<bits_sig_t>(bits & traits::sig_mask),
        .exponent    = static_cast<bits_exp_t>((bits & traits::exp_mask) >> traits::sig_bits),
        .sign        = (bits & traits::sign_mask) != 0u};

#else

    float_bits<T> b;

    if (f != f) {
        // NaN
        b.sign        = false;
        b.exponent    = traits::exp_bits_special;
        b.significand = traits::sig_bits_nan;
    } else if (f == std::numeric_limits<T>::infinity()) {
        // +Inf
        b.sign        = false;
        b.exponent    = traits::exp_bits_special;
        b.significand = traits::sig_bits_inf;
    } else if (f == -std::numeric_limits<T>::infinity()) {
        // -Inf
        b.sign        = true;
        b.exponent    = traits::exp_bits_special;
        b.significand = traits::sig_bits_inf;
    } else {
        // General case
        if (f < static_cast<T>(0.0)) {
            b.sign = true;
            f      = -f;
        }

        b.exponent = static_cast<bits_exp_t>(-traits::exp_origin);

        if (f >= static_cast<T>(2.0)) {
            do {
                f /= static_cast<T>(2.0);
                b.exponent += 1u;
            } while (f >= static_cast<T>(2.0));
        } else if (f < static_cast<T>(1.0)) {
            do {
                f *= static_cast<T>(2.0);
                b.exponent -= 1u;
            } while (f < static_cast<T>(1.0) && b.exponent > 0u);
        }

        if (b.exponent == 0u) {
            // Sub-normals
            f *= static_cast<T>(static_cast<bits_sig_t>(2u) << (traits::sig_bits - 2u));
        } else {
            // Normals
            f *= static_cast<T>(static_cast<bits_sig_t>(2u) << (traits::sig_bits - 1u));
        }

        b.significand = static_cast<bits_sig_t>(static_cast<bits_full_t>(f) & traits::sig_mask);
    }

    return b;

#endif
}

static constexpr unsigned_fixed binary_table[2][10] = {
    {unsigned_fixed(2000000000000000000u, -18), unsigned_fixed(4000000000000000000u, -18),
     unsigned_fixed(1600000000000000000u, -17), unsigned_fixed(2560000000000000000u, -16),
     unsigned_fixed(6553600000000000000u, -14), unsigned_fixed(4294967296000000000u, -9),
     unsigned_fixed(1844674407370955162u, 1), unsigned_fixed(3402823669209384635u, 20),
     unsigned_fixed(1157920892373161954u, 59), unsigned_fixed(1340780792994259710u, 136)},
    {unsigned_fixed(5000000000000000000u, -19), unsigned_fixed(2500000000000000000u, -19),
     unsigned_fixed(6250000000000000000u, -20), unsigned_fixed(3906250000000000000u, -21),
     unsigned_fixed(1525878906250000000u, -23), unsigned_fixed(2328306436538696289u, -28),
     unsigned_fixed(5421010862427522170u, -38), unsigned_fixed(2938735877055718770u, -57),
     unsigned_fixed(8636168555094444625u, -96), unsigned_fixed(7458340731200206743u, -173)}};

template<typename T>
constexpr void apply_binary_exponent(
    unsigned_fixed&                           fix,
    std::size_t                               mul_div,
    typename float_bits<T>::traits::int_exp_t exponent) noexcept {

    using traits    = float_traits<T>;
    using int_exp_t = typename traits::int_exp_t;

    // NB: We skip the last bit of the exponent. One bit was lost to generate the sign.
    // In other words, for float binary32, although the exponent is encoded on 8 bits, the value
    // can range from -126 to +127, hence the maximum absolute value is 127, which fits on 7 bits.
    // NB2: To preserve as much accuracy as possible, we multiply the powers of two together
    // from smallest to largest (since multiplying small powers can be done without any loss of
    // precision), and finally multiply the combined powers to the input number.
    unsigned_fixed power(1, 0);
    for (std::size_t i = 0; i < traits::exp_bits - 1; ++i) {
        if ((exponent & (static_cast<int_exp_t>(1) << i)) != 0u) {
            power *= binary_table[mul_div][i];
        }
    }

    fix *= power;
}

template<typename T>
[[nodiscard]] constexpr signed_fixed_data to_fixed(const float_bits<T>& bits) noexcept {
    using traits     = float_traits<T>;
    using bits_sig_t = typename traits::bits_sig_t;
    using int_exp_t  = typename traits::int_exp_t;

    // NB: To preserve as much accuracy as possible, we accumulate the significand components from
    // smallest to largest.
    unsigned_fixed fix(0, 0);
    for (bits_sig_t i = 0; i < traits::sig_bits; ++i) {
        if ((bits.significand & (static_cast<bits_sig_t>(1u) << i)) != 0u) {
            fix += traits::sig_elems[static_cast<std::size_t>(i)];
        }
    }

    const bool subnormal = bits.exponent == 0x0;

    if (!subnormal) {
        fix += unsigned_fixed(1, 0);
    }

    int_exp_t exponent = subnormal ? traits::exp_subnormal
                                   : static_cast<int_exp_t>(bits.exponent) + traits::exp_origin;

    if (exponent > 0) {
        apply_binary_exponent<T>(fix, 0u, exponent);
    } else if (exponent < 0) {
        apply_binary_exponent<T>(fix, 1u, -exponent);
    }

    return {.digits = fix.digits(), .exponent = fix.exponent(), .sign = bits.sign};
}
} // namespace snitch::impl

#endif

#ifndef SNITCH_VECTOR_HPP
#define SNITCH_VECTOR_HPP


#include <array>
#include <cstddef>
#include <initializer_list>
#include <utility>

namespace snitch {
template<typename ElemType>
class small_vector_span {
    ElemType*    buffer_ptr  = nullptr;
    std::size_t  buffer_size = 0;
    std::size_t* data_size   = nullptr;

public:
    constexpr explicit small_vector_span(ElemType* b, std::size_t bl, std::size_t* s) noexcept :
        buffer_ptr(b), buffer_size(bl), data_size(s) {}

    constexpr std::size_t capacity() const noexcept {
        return buffer_size;
    }
    constexpr std::size_t available() const noexcept {
        return capacity() - size();
    }
    constexpr std::size_t size() const noexcept {
        return *data_size;
    }
    constexpr bool empty() const noexcept {
        return *data_size == 0;
    }
    constexpr void clear() noexcept {
        *data_size = 0;
    }

    // Requires: new_size <= capacity().
    constexpr void resize(std::size_t new_size) {
        if (new_size > buffer_size) {
            assertion_failed("small vector is full");
        }

        *data_size = new_size;
    }

    // Requires: size() + elem <= capacity().
    constexpr void grow(std::size_t elem) {
        if (*data_size + elem > buffer_size) {
            assertion_failed("small vector is full");
        }

        *data_size += elem;
    }

    // Requires: size() < capacity().
    constexpr ElemType& push_back(const ElemType& t) {
        if (*data_size == buffer_size) {
            assertion_failed("small vector is full");
        }

        ++*data_size;

        ElemType& elem = buffer_ptr[*data_size - 1];
        elem           = t;

        return elem;
    }

    // Requires: size() < capacity().
    constexpr ElemType& push_back(ElemType&& t) {
        if (*data_size == buffer_size) {
            assertion_failed("small vector is full");
        }

        ++*data_size;
        ElemType& elem = buffer_ptr[*data_size - 1];
        elem           = std::move(t);

        return elem;
    }

    // Requires: !empty().
    constexpr void pop_back() {
        if (*data_size == 0) {
            assertion_failed("pop_back() called on empty vector");
        }

        --*data_size;
    }

    // Requires: !empty().
    constexpr ElemType& back() {
        if (*data_size == 0) {
            assertion_failed("back() called on empty vector");
        }

        return buffer_ptr[*data_size - 1];
    }

    // Requires: !empty().
    constexpr const ElemType& back() const {
        if (*data_size == 0) {
            assertion_failed("back() called on empty vector");
        }

        return buffer_ptr[*data_size - 1];
    }

    constexpr ElemType* data() noexcept {
        return buffer_ptr;
    }
    constexpr const ElemType* data() const noexcept {
        return buffer_ptr;
    }
    constexpr ElemType* begin() noexcept {
        return data();
    }
    constexpr ElemType* end() noexcept {
        return begin() + size();
    }
    constexpr const ElemType* begin() const noexcept {
        return data();
    }
    constexpr const ElemType* end() const noexcept {
        return begin() + size();
    }
    constexpr const ElemType* cbegin() const noexcept {
        return data();
    }
    constexpr const ElemType* cend() const noexcept {
        return begin() + size();
    }

    // Requires: i < size().
    constexpr ElemType& operator[](std::size_t i) {
        if (i >= size()) {
            assertion_failed("operator[] called with incorrect index");
        }
        return buffer_ptr[i];
    }

    // Requires: i < size().
    constexpr const ElemType& operator[](std::size_t i) const {
        if (i >= size()) {
            assertion_failed("operator[] called with incorrect index");
        }
        return buffer_ptr[i];
    }
};

template<typename ElemType>
class small_vector_span<const ElemType> {
    const ElemType*    buffer_ptr  = nullptr;
    std::size_t        buffer_size = 0;
    const std::size_t* data_size   = nullptr;

public:
    constexpr small_vector_span() noexcept = default;

    constexpr explicit small_vector_span(
        const ElemType* b, std::size_t bl, const std::size_t* s) noexcept :
        buffer_ptr(b), buffer_size(bl), data_size(s) {}

    constexpr std::size_t capacity() const noexcept {
        return buffer_size;
    }
    constexpr std::size_t available() const noexcept {
        return capacity() - size();
    }
    constexpr std::size_t size() const noexcept {
        return data_size != nullptr ? *data_size : 0;
    }
    constexpr bool empty() const noexcept {
        return data_size == nullptr || *data_size == 0;
    }

    // Requires: !empty().
    constexpr const ElemType& back() const {
        if (empty()) {
            assertion_failed("back() called on empty vector");
        }

        return buffer_ptr[*data_size - 1];
    }

    constexpr const ElemType* data() const noexcept {
        return buffer_ptr;
    }
    constexpr const ElemType* begin() const noexcept {
        return data();
    }
    constexpr const ElemType* end() const noexcept {
        return begin() + size();
    }
    constexpr const ElemType* cbegin() const noexcept {
        return data();
    }
    constexpr const ElemType* cend() const noexcept {
        return begin() + size();
    }

    // Requires: i < size().
    constexpr const ElemType& operator[](std::size_t i) const {
        if (i >= size()) {
            assertion_failed("operator[] called with incorrect index");
        }
        return buffer_ptr[i];
    }
};

template<typename ElemType, std::size_t MaxLength>
class small_vector {
    std::array<ElemType, MaxLength> data_buffer = {};
    std::size_t                     data_size   = 0;

public:
    constexpr small_vector() noexcept                          = default;
    constexpr small_vector(const small_vector& other) noexcept = default;
    constexpr small_vector(small_vector&& other) noexcept      = default;
    constexpr small_vector(std::initializer_list<ElemType> list) {
        for (const auto& e : list) {
            span().push_back(e);
        }
    }

    constexpr small_vector& operator=(const small_vector& other) noexcept = default;
    constexpr small_vector& operator=(small_vector&& other) noexcept      = default;

    constexpr std::size_t capacity() const noexcept {
        return MaxLength;
    }
    constexpr std::size_t available() const noexcept {
        return MaxLength - data_size;
    }
    constexpr std::size_t size() const noexcept {
        return data_size;
    }
    constexpr bool empty() const noexcept {
        return data_size == 0u;
    }
    constexpr void clear() noexcept {
        span().clear();
    }

    // Requires: new_size <= capacity().
    constexpr void resize(std::size_t size) {
        span().resize(size);
    }

    // Requires: size() + elem <= capacity().
    constexpr void grow(std::size_t elem) {
        span().grow(elem);
    }

    // Requires: size() < capacity().
    constexpr ElemType& push_back(const ElemType& t) {
        return this->span().push_back(t);
    }

    // Requires: size() < capacity().
    constexpr ElemType& push_back(ElemType&& t) {
        return this->span().push_back(t);
    }

    // Requires: !empty().
    constexpr void pop_back() {
        return span().pop_back();
    }

    // Requires: !empty().
    constexpr ElemType& back() {
        return span().back();
    }

    // Requires: !empty().
    constexpr const ElemType& back() const {
        return span().back();
    }

    constexpr ElemType* data() noexcept {
        return data_buffer.data();
    }
    constexpr const ElemType* data() const noexcept {
        return data_buffer.data();
    }
    constexpr ElemType* begin() noexcept {
        return data();
    }
    constexpr ElemType* end() noexcept {
        return begin() + size();
    }
    constexpr const ElemType* begin() const noexcept {
        return data();
    }
    constexpr const ElemType* end() const noexcept {
        return begin() + size();
    }
    constexpr const ElemType* cbegin() const noexcept {
        return data();
    }
    constexpr const ElemType* cend() const noexcept {
        return begin() + size();
    }

    constexpr small_vector_span<ElemType> span() noexcept {
        return small_vector_span<ElemType>(data_buffer.data(), MaxLength, &data_size);
    }

    constexpr small_vector_span<const ElemType> span() const noexcept {
        return small_vector_span<const ElemType>(data_buffer.data(), MaxLength, &data_size);
    }

    constexpr operator small_vector_span<ElemType>() noexcept {
        return span();
    }

    constexpr operator small_vector_span<const ElemType>() const noexcept {
        return span();
    }

    // Requires: i < size().
    constexpr ElemType& operator[](std::size_t i) {
        return span()[i];
    }

    // Requires: i < size().
    constexpr const ElemType& operator[](std::size_t i) const {
        return span()[i];
    }
};
} // namespace snitch

#endif

#ifndef SNITCH_STRING_HPP
#define SNITCH_STRING_HPP


#include <string_view>

namespace snitch {
using small_string_span = small_vector_span<char>;
using small_string_view = small_vector_span<const char>;

template<std::size_t MaxLength>
class small_string {
    std::array<char, MaxLength> data_buffer = {};
    std::size_t                 data_size   = 0u;

public:
    constexpr small_string() noexcept                          = default;
    constexpr small_string(const small_string& other) noexcept = default;
    constexpr small_string(small_string&& other) noexcept      = default;

    // Requires: str.size() <= MaxLength.
    constexpr small_string(std::string_view str) {
        resize(str.size());
        for (std::size_t i = 0; i < str.size(); ++i) {
            data_buffer[i] = str[i];
        }
    }

    constexpr small_string& operator=(const small_string& other) noexcept = default;
    constexpr small_string& operator=(small_string&& other) noexcept      = default;

    constexpr std::string_view str() const noexcept {
        return std::string_view(data(), length());
    }

    constexpr std::size_t capacity() const noexcept {
        return MaxLength;
    }
    constexpr std::size_t available() const noexcept {
        return MaxLength - data_size;
    }
    constexpr std::size_t size() const noexcept {
        return data_size;
    }
    constexpr std::size_t length() const noexcept {
        return data_size;
    }
    constexpr bool empty() const noexcept {
        return data_size == 0u;
    }
    constexpr void clear() noexcept {
        span().clear();
    }

    // Requires: new_size <= capacity().
    constexpr void resize(std::size_t length) {
        span().resize(length);
    }

    // Requires: size() + elem <= capacity().
    constexpr void grow(std::size_t chars) {
        span().grow(chars);
    }

    // Requires: size() < capacity().
    constexpr char& push_back(char t) {
        return span().push_back(t);
    }

    // Requires: !empty().
    constexpr void pop_back() {
        return span().pop_back();
    }

    // Requires: !empty().
    constexpr char& back() {
        return span().back();
    }

    // Requires: !empty().
    constexpr const char& back() const {
        return span().back();
    }

    constexpr char* data() noexcept {
        return data_buffer.data();
    }
    constexpr const char* data() const noexcept {
        return data_buffer.data();
    }
    constexpr char* begin() noexcept {
        return data();
    }
    constexpr char* end() noexcept {
        return begin() + length();
    }
    constexpr const char* begin() const noexcept {
        return data();
    }
    constexpr const char* end() const noexcept {
        return begin() + length();
    }
    constexpr const char* cbegin() const noexcept {
        return data();
    }
    constexpr const char* cend() const noexcept {
        return begin() + length();
    }

    constexpr small_string_span span() noexcept {
        return small_string_span(data_buffer.data(), MaxLength, &data_size);
    }

    constexpr small_string_view span() const noexcept {
        return small_string_view(data_buffer.data(), MaxLength, &data_size);
    }

    constexpr operator small_string_span() noexcept {
        return span();
    }

    constexpr operator small_string_view() const noexcept {
        return span();
    }

    constexpr operator std::string_view() const noexcept {
        return std::string_view(data(), length());
    }

    // Requires: i < size().
    constexpr char& operator[](std::size_t i) {
        return span()[i];
    }

    // Requires: i < size().
    constexpr char operator[](std::size_t i) const {
        return const_cast<small_string*>(this)->span()[i];
    }
};
} // namespace snitch

#endif

#ifndef SNITCH_APPEND_HPP
#define SNITCH_APPEND_HPP


#include <cstddef>
#include <limits>
#include <string_view>
#include <utility>

namespace snitch {
// These types are used to define the largest printable integer types.
// In C++, integer literals must fit on uintmax_t/intmax_t, so these are good candidates.
// They aren't perfect though. On most 64 bit platforms they are defined as 64 bit integers,
// even though those platforms usually support 128 bit integers.
using large_uint_t = std::uintmax_t;
using large_int_t  = std::intmax_t;

static_assert(
    sizeof(large_uint_t) >= sizeof(impl::fixed_digits_t),
    "large_uint_t is too small to support the float-to-fixed-point conversion implementation");
} // namespace snitch

namespace snitch::impl {
SNITCH_EXPORT [[nodiscard]] bool append_fast(small_string_span ss, std::string_view str) noexcept;
SNITCH_EXPORT [[nodiscard]] bool append_fast(small_string_span ss, const void* ptr) noexcept;
SNITCH_EXPORT [[nodiscard]] bool append_fast(small_string_span ss, large_uint_t i) noexcept;
SNITCH_EXPORT [[nodiscard]] bool append_fast(small_string_span ss, large_int_t i) noexcept;
SNITCH_EXPORT [[nodiscard]] bool append_fast(small_string_span ss, float f) noexcept;
SNITCH_EXPORT [[nodiscard]] bool append_fast(small_string_span ss, double f) noexcept;

[[nodiscard]] constexpr bool append_constexpr(small_string_span ss, std::string_view str) noexcept {
    const bool        could_fit  = str.size() <= ss.available();
    const std::size_t copy_count = could_fit ? str.size() : ss.available();

    const std::size_t offset = ss.size();
    ss.grow(copy_count);
    for (std::size_t i = 0; i < copy_count; ++i) {
        ss[offset + i] = str[i];
    }

    return could_fit;
}

template<large_uint_t Base = 10u, unsigned_integral T>
[[nodiscard]] constexpr std::size_t num_digits(T x) noexcept {
    return x >= Base ? 1u + num_digits<Base>(x / Base) : 1u;
}

template<large_int_t Base = 10, signed_integral T>
[[nodiscard]] constexpr std::size_t num_digits(T x) noexcept {
    return (x >= Base || x <= -Base) ? 1u + num_digits<Base>(x / Base) : x > 0 ? 1u : 2u;
}

constexpr std::array<char, 16> digits = {'0', '1', '2', '3', '4', '5', '6', '7',
                                         '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

constexpr std::size_t max_uint_length = num_digits(std::numeric_limits<large_uint_t>::max());
constexpr std::size_t max_int_length  = max_uint_length + 1;

template<large_uint_t Base = 10u, unsigned_integral T>
[[nodiscard]] constexpr bool append_constexpr(small_string_span ss, T i) noexcept {
    if (i != 0u) {
        small_string<max_uint_length> tmp;
        tmp.resize(num_digits<Base>(i));
        std::size_t k = 1;
        for (large_uint_t j = i; j != 0u; j /= Base, ++k) {
            tmp[tmp.size() - k] = digits[j % Base];
        }
        return append_constexpr(ss, tmp);
    } else {
        return append_constexpr(ss, "0");
    }
}

template<large_int_t Base = 10, signed_integral T>
[[nodiscard]] constexpr bool append_constexpr(small_string_span ss, T i) noexcept {
    if (i > 0) {
        small_string<max_int_length> tmp;
        tmp.resize(num_digits<Base>(i));
        std::size_t k = 1;
        for (large_int_t j = i; j != 0; j /= Base, ++k) {
            tmp[tmp.size() - k] = digits[j % Base];
        }
        return append_constexpr(ss, tmp);
    } else if (i < 0) {
        small_string<max_int_length> tmp;
        tmp.resize(num_digits<Base>(i));
        std::size_t k = 1;
        for (large_int_t j = i; j != 0; j /= Base, ++k) {
            tmp[tmp.size() - k] = digits[-(j % Base)];
        }
        tmp[0] = '-';
        return append_constexpr(ss, tmp);
    } else {
        return append_constexpr(ss, "0");
    }
}

// Minimum number of digits in the exponent, set to 2 to match std::printf.
constexpr std::size_t min_exp_digits = 2u;

[[nodiscard]] constexpr std::size_t num_exp_digits(fixed_exp_t x) noexcept {
    const std::size_t exp_digits = num_digits<10>(static_cast<large_uint_t>(x > 0 ? x : -x));
    return exp_digits < min_exp_digits ? min_exp_digits : exp_digits;
}

[[nodiscard]] constexpr std::size_t num_digits(const signed_fixed_data& x) noexcept {
    // Don't forget to modify the stored exponent by the number of stored digits, since we always
    // print floating point numbers as 1.23456 but store them as 123456.
    // Why +3:
    // +1 for fractional separator '.'
    // +1 for exponent separator 'e'
    // +1 for exponent sign
    const std::size_t stored_digits = num_digits<10>(static_cast<large_uint_t>(x.digits));
    return stored_digits + (x.sign ? 1u : 0u) +
           num_exp_digits(static_cast<fixed_exp_t>(x.exponent + stored_digits - 1)) + 3u;
}

constexpr std::size_t max_float_length = num_digits(signed_fixed_data{
    .digits   = std::numeric_limits<fixed_digits_t>::max(),
    .exponent = float_traits<double>::exp_origin,
    .sign     = true});

[[nodiscard]] constexpr fixed_digits_t
round_half_to_even(fixed_digits_t i, bool only_zero) noexcept {
    fixed_digits_t r = (i + 5u) / 10u;
    if (only_zero && i % 10u == 5u) {
        // Exact tie detected, correct the rounded value to the nearest even integer.
        r -= 1u - (i / 10u) % 2u;
    }
    return r;
}

[[nodiscard]] constexpr signed_fixed_data
set_precision(signed_fixed_data fd, std::size_t p) noexcept {
    // Truncate the digits of the input to the chosen precision (number of digits on both
    // sides of the decimal point). Precision must be less or equal to 19.
    // We have a choice of the rounding mode here; to stay as close as possible to the
    // std::printf() behavior, we use round-half-to-even (i.e., round to nearest, and break ties
    // to nearest even integer). std::printf() is supposed to follow the current rounding mode,
    // and round-half-to-even is the default rounding mode for IEEE 754 floats. We don't follow
    // the current rounding mode, but we can at least follow the default.

    std::size_t base_digits = num_digits<10>(static_cast<large_uint_t>(fd.digits));

    bool only_zero = true;
    while (base_digits > p) {
        if (base_digits > p + 1u) {
            if (fd.digits % 10u > 0u) {
                only_zero = false;
            }
            fd.digits = fd.digits / 10u;
            base_digits -= 1u;
        } else {
            fd.digits   = round_half_to_even(fd.digits, only_zero);
            base_digits = num_digits<10>(static_cast<large_uint_t>(fd.digits));
        }

        fd.exponent += 1;
    }

    return fd;
}

[[nodiscard]] constexpr bool append_constexpr(small_string_span ss, signed_fixed_data fd) noexcept {
    // Statically allocate enough space for the biggest float,
    small_string<max_float_length> tmp;

    // Resize to fit the digits (without exponent part).
    // +1 for fractional separator '.'
    // +1 for sign
    const std::size_t stored_digits = num_digits<10>(static_cast<large_uint_t>(fd.digits));
    tmp.resize(stored_digits + 1u + (fd.sign ? 1u : 0u));

    // The exponent has a fixed size, so we can start by writing the main digits.
    // We write the digits with always a single digit before the decimal separator,
    // and the rest as fractional part. This will require adjusting the value of
    // the exponent later.
    std::size_t k = 1u;
    for (fixed_digits_t j = fd.digits; j != 0u; j /= 10u, ++k) {
        if (j < 10u) {
            tmp[tmp.size() - k] = '.';
            ++k;
        }
        tmp[tmp.size() - k] = digits[j % 10u];
    }

    // Add a negative sign for negative floats.
    if (fd.sign) {
        tmp[0] = '-';
    }

    // Now write the exponent, adjusted for the chosen display (one digit before the decimal
    // separator).
    const fixed_exp_t exponent = static_cast<fixed_exp_t>(fd.exponent + stored_digits - 1);

    // Allocate space for it, +1 for 'e', and +1 for exponent sign.
    tmp.grow(num_exp_digits(exponent) + 2u);

    k = 1;
    for (fixed_exp_t j = exponent > 0 ? exponent : -exponent; j != 0; j /= 10, ++k) {
        tmp[tmp.size() - k] = digits[j % 10];
    }

    // Pad exponent with zeros if it is shorter than the min number of digits.
    for (; k <= min_exp_digits; ++k) {
        tmp[tmp.size() - k] = '0';
    }

    // Write the sign, and exponent delimitation character.
    tmp[tmp.size() - k] = exponent >= 0 ? '+' : '-';
    ++k;
    tmp[tmp.size() - k] = 'e';
    ++k;

    // Finally write as much of the string as we can to the chosen destination.
    return append_constexpr(ss, tmp);
}

template<floating_point T>
[[nodiscard]] constexpr bool append_constexpr(
    small_string_span ss, T f, std::size_t precision = float_traits<T>::precision) noexcept {
    if constexpr (std::numeric_limits<T>::is_iec559) {
        using traits = float_traits<T>;

        // Float/double precision cannot be greater than 19 digits.
        precision = precision <= 19u ? precision : 19u;

        const float_bits<T> bits = to_bits(f);

        // Handle special cases.
        if (bits.exponent == 0x0) {
            if (bits.significand == 0x0) {
                // Zero.
                constexpr std::string_view zeros = "000000000000000000";
                return append_constexpr(ss, bits.sign ? "-0." : "0.") &&
                       append_constexpr(ss, zeros.substr(0, precision - 1)) &&
                       append_constexpr(ss, "e+00");
            } else {
                // Subnormals.
                return append_constexpr(ss, set_precision(to_fixed(bits), precision));
            }
        } else if (bits.exponent == traits::exp_bits_special) {
            if (bits.significand == traits::sig_bits_inf) {
                // Infinity.
                constexpr std::string_view plus_inf_str  = "inf";
                constexpr std::string_view minus_inf_str = "-inf";
                return bits.sign ? append_constexpr(ss, minus_inf_str)
                                 : append_constexpr(ss, plus_inf_str);
            } else {
                // NaN.
                constexpr std::string_view nan_str = "nan";
                return append_constexpr(ss, nan_str);
            }
        } else {
            // Normal number.
            return append_constexpr(ss, set_precision(to_fixed(bits), precision));
        }
    } else {
        constexpr std::string_view unknown_str = "?";
        return append_constexpr(ss, unknown_str);
    }
}

[[nodiscard]] constexpr bool append_constexpr(small_string_span ss, const void* p) noexcept {
    if (p == nullptr) {
        constexpr std::string_view nullptr_str = "nullptr";
        return append_constexpr(ss, nullptr_str);
    } else {
        constexpr std::string_view unknown_ptr_str = "0x????????";
        return append_constexpr(ss, unknown_ptr_str);
    }
}
} // namespace snitch::impl

namespace snitch {
[[nodiscard]] constexpr bool append(small_string_span ss, std::string_view str) noexcept {
    if (std::is_constant_evaluated()) {
        return impl::append_constexpr(ss, str);
    } else {
        return impl::append_fast(ss, str);
    }
}

[[nodiscard]] constexpr bool append(small_string_span ss, const void* ptr) noexcept {
    if (std::is_constant_evaluated()) {
        return impl::append_constexpr(ss, ptr);
    } else {
        return impl::append_fast(ss, ptr);
    }
}

[[nodiscard]] constexpr bool append(small_string_span ss, std::nullptr_t) noexcept {
    constexpr std::string_view nullptr_str = "nullptr";
    return append(ss, nullptr_str);
}

[[nodiscard]] constexpr bool append(small_string_span ss, large_uint_t i) noexcept {
    if (std::is_constant_evaluated()) {
        return impl::append_constexpr(ss, i);
    } else {
        return impl::append_fast(ss, i);
    }
}
[[nodiscard]] constexpr bool append(small_string_span ss, large_int_t i) noexcept {
    if (std::is_constant_evaluated()) {
        return impl::append_constexpr(ss, i);
    } else {
        return impl::append_fast(ss, i);
    }
}

[[nodiscard]] constexpr bool append(small_string_span ss, float f) noexcept {
    if (std::is_constant_evaluated()) {
        return impl::append_constexpr(ss, f);
    } else {
        return impl::append_fast(ss, f);
    }
}

[[nodiscard]] constexpr bool append(small_string_span ss, double f) noexcept {
    if (std::is_constant_evaluated()) {
        return impl::append_constexpr(ss, f);
    } else {
        return impl::append_fast(ss, f);
    }
}

[[nodiscard]] constexpr bool append(small_string_span ss, bool value) noexcept {
    constexpr std::string_view true_str  = "true";
    constexpr std::string_view false_str = "false";
    return append(ss, value ? true_str : false_str);
}

template<signed_integral T>
[[nodiscard]] constexpr bool append(small_string_span ss, T value) noexcept {
    return append(ss, static_cast<large_int_t>(value));
}

template<unsigned_integral T>
[[nodiscard]] constexpr bool append(small_string_span ss, T value) noexcept {
    return append(ss, static_cast<large_uint_t>(value));
}

template<enumeration T>
[[nodiscard]] constexpr bool append(small_string_span ss, T value) noexcept {
    return append(ss, static_cast<std::underlying_type_t<T>>(value));
}

template<typename T>
    requires(raw_string<T> || pointer<T> || function_pointer<T> || member_function_pointer<T>)
[[nodiscard]] constexpr bool append(small_string_span ss, T&& value) noexcept {
    if constexpr (raw_string<T>) {
        return append(ss, std::string_view(value, std::extent_v<impl::decay_object<T>> - 1u));
    } else {
        if (value == nullptr) {
            return append(ss, nullptr);
        }

        if constexpr (function_pointer<T> || member_function_pointer<T>) {
            constexpr std::string_view function_ptr_str = "0x????????";
            return append(ss, function_ptr_str);
        } else if constexpr (std::is_same_v<impl::decay_object<T>, const char*>) {
            return append(ss, std::string_view(value));
        } else {
            return append(ss, static_cast<const void*>(value));
        }
    }
}

template<typename T>
concept string_appendable = requires(small_string_span ss, T value) { append(ss, value); };

template<string_appendable T, string_appendable U, string_appendable... Args>
[[nodiscard]] constexpr bool append(small_string_span ss, T&& t, U&& u, Args&&... args) noexcept {
    return append(ss, std::forward<T>(t)) && append(ss, std::forward<U>(u)) &&
           (append(ss, std::forward<Args>(args)) && ...);
}
} // namespace snitch

#endif

#ifndef SNITCH_STRING_UTILITY_HPP
#define SNITCH_STRING_UTILITY_HPP


#include <cstddef>
#include <string_view>
#include <utility>

namespace snitch {
constexpr void truncate_end(small_string_span ss) noexcept {
    std::size_t num_dots     = 3;
    std::size_t final_length = ss.size() + num_dots;
    if (final_length > ss.capacity()) {
        final_length = ss.capacity();
    }

    const std::size_t offset = final_length >= num_dots ? final_length - num_dots : 0;
    num_dots                 = final_length - offset;

    ss.resize(final_length);
    for (std::size_t i = 0; i < num_dots; ++i) {
        ss[offset + i] = '.';
    }
}

template<string_appendable... Args>
constexpr bool append_or_truncate(small_string_span ss, Args&&... args) noexcept {
    if (!append(ss, std::forward<Args>(args)...)) {
        truncate_end(ss);
        return false;
    }

    return true;
}

template<std::size_t N, std::size_t M>
constexpr small_string<N> resize_or_truncate(const small_string<M>& str) noexcept {
    if constexpr (N == M) {
        return str;
    } else if constexpr (N > M) {
        small_string<N> out;
        append(out, std::string_view{str});
        return out;
    } else {
        small_string<N> out;
        append_or_truncate(out, std::string_view{str});
        return out;
    }
}

template<std::size_t N, std::size_t M>
constexpr small_string<N> resize_or_truncate(std::string_view str) noexcept {
    small_string<N> out;
    append(out, str);
    return out;
}

SNITCH_EXPORT [[nodiscard]] bool replace_all(
    small_string_span string, std::string_view pattern, std::string_view replacement) noexcept;

// Requires: replacement.length() > pattern.length()
SNITCH_EXPORT [[nodiscard]] bool escape_all_or_truncate(
    small_string_span string, std::string_view pattern, std::string_view replacement);

SNITCH_EXPORT [[nodiscard]] std::size_t
find_first_not_escaped(std::string_view str, char c) noexcept;

SNITCH_EXPORT [[nodiscard]] bool is_match(std::string_view string, std::string_view regex) noexcept;
} // namespace snitch

#endif

#ifndef SNITCH_TIME_HPP
#define SNITCH_TIME_HPP


#if SNITCH_WITH_TIMINGS

namespace snitch {
using time_point_t = std::size_t;

SNITCH_EXPORT time_point_t get_current_time() noexcept;

SNITCH_EXPORT float get_duration_in_seconds(time_point_t start, time_point_t end) noexcept;
} // namespace snitch

#endif
#endif

#ifndef SNITCH_TEST_DATA_HPP
#define SNITCH_TEST_DATA_HPP


#include <cstddef>
#include <optional>
#include <string_view>

namespace snitch {
class registry;

/// Identifies a location in source code
struct source_location {
    /// Absolute path to the file
    std::string_view file = {};
    /// Line number (starts at 1)
    std::size_t line = 0u;
};

/// Identifies a test case
struct test_id {
    /// Name of the test case, as given in the source
    std::string_view name = {};
    /// Tags of the test case, as given in the source
    std::string_view tags = {};
    /// Name of the type for which this test case is instanciated (templated test cases only)
    std::string_view type = {};
    /// Name of the fixture class from which the test case is instanciated (method test cases only)
    std::string_view fixture = {};
};

/// Identies a section
struct section_id {
    /// Name of the section, as given in the source
    std::string_view name = {};
    /// Description of the section, as given in the source
    std::string_view description = {};
};

/// Section data
struct section {
    /// Identifiers (name, description)
    section_id id = {};
    /// Location (file, line)
    source_location location = {};

    /// Counts all assertions; passed, failed, or allowed failed
    std::size_t assertion_count = 0;
    /// Counts failed assertions
    std::size_t assertion_failure_count = 0;
    /// Counts allowed failed assertions (e.g., [!shouldfail] and [!mayfail])
    std::size_t allowed_assertion_failure_count = 0;

#if SNITCH_WITH_TIMINGS
    /// Time index of the instant when the section was first entered.
    time_point_t start_time = 0;
#endif
};

/// List of test case filters
using filter_info = small_vector_span<const std::string_view>;
/// List of active sections (in increasing nesting level)
using section_info = small_vector_span<const section>;
/// List of active captures (in order of declaration)
using capture_info = small_vector_span<const std::string_view>;

enum class location_type {
    /// The true location is precisely at the indicated location
    exact,
    /// The true location is somewhere inside the section starting at the indicated location
    section_scope,
    /// The true location is somewhere inside the test case starting at the indicated location
    test_case_scope,
    /// The true location is somehere further down the call stack from the indicated location
    in_check
};

/// Identifies a location in source code
struct assertion_location {
    /// Absolute path to the file
    std::string_view file = {};
    /// Line number (starts at 1)
    std::size_t line = 0u;
    /// Type of location
    location_type type = location_type::exact;
};

/// State of a test case after execution
enum class test_case_state {
    /// All checks passed
    success,
    /// Some checks failed and the test does not allow failure
    failed,
    /// Some checks failed and the tests allows failure (e.g., [!shouldfail] and [!mayfail])
    allowed_fail,
    /// Test case explicitly skipped (with SKIP(...))
    skipped
};

/// Content of an expression
struct expression_info {
    /// Macro used for the assertion (CHECK, etc.)
    std::string_view type;
    /// Expression as written in the source code
    std::string_view expected;
    /// Expression with evaluated operands
    std::string_view actual;
};

/// Payload of an assertion (error message, expression, ...)
using assertion_data = std::variant<std::string_view, expression_info>;
} // namespace snitch

namespace snitch::event {
/// Fired at the start of a test run (application started)
struct test_run_started {
    /// Name of the test application
    std::string_view name = {};
    /// List of test case filters, as given in the command-line arguments
    filter_info filters = {};
};

/// Fired at the end of a test run (application finished)
struct test_run_ended {
    /// Name of the test application
    std::string_view name = {};
    /// List of test case filters, as given in the command-line arguments
    filter_info filters = {};

    /// Counts all test cases; passed, failed, allowed to fail, or skipped
    std::size_t run_count = 0;
    /// Counts all failed test cases
    std::size_t fail_count = 0;
    /// Counts all allowed failed test cases
    std::size_t allowed_fail_count = 0;
    /// Counts all skipped test cases
    std::size_t skip_count = 0;

    /// Counts all assertions; passed, failed, or allowed failed
    std::size_t assertion_count = 0;
    /// Counts failed assertions
    std::size_t assertion_failure_count = 0;
    /// Counts allowed failed assertions (e.g., [!shouldfail] and [!mayfail])
    std::size_t allowed_assertion_failure_count = 0;

#if SNITCH_WITH_TIMINGS
    /// Total test duration, in seconds
    float duration = 0.0f;
#endif

    /// True if all tests passed, or all failures were allowed
    bool success = true;
};

/// Fired at the start of a test case
struct test_case_started {
    /// Test ID
    const test_id& id;
    /// Test location
    const source_location& location;
};

/// Fired at the end of a test case
struct test_case_ended {
    /// Test ID
    const test_id& id;
    /// Test location
    const source_location& location;

    /// Counts all assertions; passed, failed, or allowed failed
    std::size_t assertion_count = 0;
    /// Counts failed assertions
    std::size_t assertion_failure_count = 0;
    /// Counts allowed failed assertions (e.g., [!shouldfail] and [!mayfail])
    std::size_t allowed_assertion_failure_count = 0;

    /// Test result
    test_case_state state = test_case_state::success;

#if SNITCH_WITH_TIMINGS
    /// Test case duration, in seconds
    float duration = 0.0f;
#endif

    bool failure_expected = false;
    bool failure_allowed  = false;
};

struct section_started {
    /// Identifiers (name, description)
    section_id id = {};
    /// Location (file, line)
    source_location location = {};
};

struct section_ended {
    /// Identifiers (name, description)
    section_id id = {};
    /// Location (file, line)
    source_location location = {};

    /// Whether the section has been skipped.
    bool skipped = false;

    /// Counts all assertions; passed, failed, or allowed failed
    std::size_t assertion_count = 0;
    /// Counts failed assertions
    std::size_t assertion_failure_count = 0;
    /// Counts allowed failed assertions (e.g., [!shouldfail] and [!mayfail])
    std::size_t allowed_assertion_failure_count = 0;

#if SNITCH_WITH_TIMINGS
    /// Section duration, in seconds
    float duration = 0.0f;
#endif
};

struct assertion_failed {
    const test_id&            id;
    section_info              sections = {};
    capture_info              captures = {};
    const assertion_location& location;
    assertion_data            data     = {};
    bool                      expected = false; /// [!shouldfail]
    bool                      allowed  = false; /// [!mayfail]
};

struct assertion_succeeded {
    const test_id&            id;
    section_info              sections = {};
    capture_info              captures = {};
    const assertion_location& location;
    assertion_data            data = {};
};

struct test_case_skipped {
    const test_id&            id;
    section_info              sections = {};
    capture_info              captures = {};
    const assertion_location& location;
    std::string_view          message = {};
};

/// Fired at the start of a test listing run (application started)
struct list_test_run_started {
    /// Name of the test application
    std::string_view name = {};
    /// List of test case filters, as given in the command-line arguments
    filter_info filters = {};
};

/// Fired for each selected test case in a test listing run
struct test_case_listed {
    /// Test ID
    const test_id& id;
    /// Test location
    const source_location& location;
};

/// Fired at the end of a test run (application finished)
struct list_test_run_ended {
    /// Name of the test application
    std::string_view name = {};
    /// List of test case filters, as given in the command-line arguments
    filter_info filters = {};
};

using data = std::variant<
    test_run_started,
    test_run_ended,
    test_case_started,
    test_case_ended,
    section_started,
    section_ended,
    assertion_failed,
    assertion_succeeded,
    test_case_skipped,
    list_test_run_started,
    list_test_run_ended,
    test_case_listed>;
} // namespace snitch::event

namespace snitch {
// Maximum depth of nested sections in a test case (section in section in section ...).
constexpr std::size_t max_nested_sections = SNITCH_MAX_NESTED_SECTIONS;
// Maximum number of captured expressions in a test case.
constexpr std::size_t max_captures = SNITCH_MAX_CAPTURES;
// Maximum length of a captured expression.
constexpr std::size_t max_capture_length = SNITCH_MAX_CAPTURE_LENGTH;
} // namespace snitch

namespace snitch::impl {
using test_ptr = void (*)();

enum class test_case_state { not_run, success, skipped, failed, allowed_fail };

struct test_case {
    test_id         id       = {};
    source_location location = {};
    test_ptr        func     = nullptr;
    test_case_state state    = test_case_state::not_run;
};

struct section_nesting_level {
    std::size_t current_section_id  = 0;
    std::size_t previous_section_id = 0;
    std::size_t max_section_id      = 0;
};

struct section_state {
    small_vector<section, max_nested_sections>               current_section = {};
    small_vector<section_nesting_level, max_nested_sections> levels          = {};
    std::size_t                                              depth           = 0;
    bool                                                     leaf_executed   = false;
};

using capture_state = small_vector<small_string<max_capture_length>, max_captures>;

// NB: +2 is because we need one for the test case location, and one for the check location
using location_state = small_vector<assertion_location, max_nested_sections + 2>;

struct info_state {
    section_state  sections  = {};
    capture_state  captures  = {};
    location_state locations = {};
};

struct test_state {
    registry&  reg;
    test_case& test;

    info_state info = {};

#if SNITCH_WITH_EXCEPTIONS
    std::optional<info_state> held_info = {};
#endif

    std::size_t asserts          = 0;
    std::size_t failures         = 0;
    std::size_t allowed_failures = 0;
    bool        may_fail         = false;
    bool        should_fail      = false;
    bool        in_check         = false;

#if SNITCH_WITH_EXCEPTIONS
    bool unhandled_exception = false;
#endif

#if SNITCH_WITH_TIMINGS
    float duration = 0.0f;
#endif
};

SNITCH_EXPORT test_state& get_current_test() noexcept;

SNITCH_EXPORT test_state* try_get_current_test() noexcept;

SNITCH_EXPORT void set_current_test(test_state* current) noexcept;

SNITCH_EXPORT void push_location(test_state& test, const assertion_location& location) noexcept;

SNITCH_EXPORT void pop_location(test_state& test) noexcept;

struct scoped_test_check {
    test_state& test;

    SNITCH_EXPORT explicit scoped_test_check(const source_location& location) noexcept;

    SNITCH_EXPORT ~scoped_test_check() noexcept;
};
} // namespace snitch::impl

namespace snitch {
#if SNITCH_WITH_EXCEPTIONS
/*! \brief Notify the testing framework that an exception was manually handled.
 * \details If handling exceptions explicitly with a `try/catch` block in a test case,
 * this should be called at the end of the `catch` block. This clears up internal state
 * that would have been used to report that exception, had it not been handled. Calling
 * this is not strictly necessary in most cases, but omitting it can lead to confusing
 * contextual data (incorrect section/capture/info) if another exception is thrown afterwards
 * and not handled.
 */
SNITCH_EXPORT void notify_exception_handled() noexcept;
#endif
} // namespace snitch

#endif

#ifndef SNITCH_CAPTURE_HPP
#define SNITCH_CAPTURE_HPP


#include <cstddef>
#include <string_view>

namespace snitch::impl {
struct scoped_capture {
    test_state& state;
    std::size_t count = 0;

    SNITCH_EXPORT ~scoped_capture();
};

SNITCH_EXPORT std::string_view extract_next_name(std::string_view& names) noexcept;

struct test_state;

// Requires: number of captures < max_captures.
SNITCH_EXPORT small_string<max_capture_length>& add_capture(test_state& state);

// Requires: number of captures < max_captures.
template<string_appendable T>
void add_capture(test_state& state, std::string_view& names, const T& arg) {
    auto& capture = add_capture(state);
    append_or_truncate(capture, extract_next_name(names), " := ", arg);
}

// Requires: number of captures < max_captures.
template<string_appendable... Args>
scoped_capture add_captures(test_state& state, std::string_view names, const Args&... args) {
    (add_capture(state, names, args), ...);
    return {state, sizeof...(args)};
}

// Requires: number of captures < max_captures.
template<string_appendable... Args>
scoped_capture add_info(test_state& state, const Args&... args) {
    auto& capture = add_capture(state);
    append_or_truncate(capture, args...);
    return {state, 1};
}
} // namespace snitch::impl

#endif

#ifndef SNITCH_CLI_HPP
#define SNITCH_CLI_HPP


#include <cstddef>
#include <optional>
#include <string_view>

// Testing framework configuration.
// --------------------------------

namespace snitch {
// Maximum number of command line arguments.
constexpr std::size_t max_command_line_args = SNITCH_MAX_COMMAND_LINE_ARGS;
} // namespace snitch

namespace snitch::cli {
struct argument {
    std::string_view                name       = {};
    std::optional<std::string_view> value_name = {};
    std::optional<std::string_view> value      = {};
};

struct input {
    std::string_view                              executable = {};
    small_vector<argument, max_command_line_args> arguments  = {};
};

SNITCH_EXPORT extern function_ref<void(std::string_view) noexcept> console_print;

template<typename... Args>
void print(Args&&... args) noexcept {
    small_string<max_message_length> message;
    append_or_truncate(message, std::forward<Args>(args)...);
    console_print(message);
}

struct print_help_settings {
    bool with_color = true;
};

SNITCH_EXPORT void print_help(
    std::string_view           program_name,
    const print_help_settings& settings = print_help_settings{}) noexcept;

SNITCH_EXPORT std::optional<input> parse_arguments(int argc, const char* const argv[]) noexcept;

SNITCH_EXPORT std::optional<cli::argument>
              get_option(const cli::input& args, std::string_view name) noexcept;

SNITCH_EXPORT std::optional<cli::argument>
              get_positional_argument(const cli::input& args, std::string_view name) noexcept;

SNITCH_EXPORT void for_each_positional_argument(
    const cli::input&                                    args,
    std::string_view                                     name,
    const function_ref<void(std::string_view) noexcept>& callback) noexcept;
} // namespace snitch::cli

#endif

#ifndef SNITCH_CONSOLE_HPP
#define SNITCH_CONSOLE_HPP


#include <string_view>

namespace snitch::impl {
SNITCH_EXPORT void stdout_print(std::string_view message) noexcept;

using color_t = std::string_view;

namespace color {
constexpr color_t error [[maybe_unused]]      = "\x1b[1;31m";
constexpr color_t warning [[maybe_unused]]    = "\x1b[1;33m";
constexpr color_t status [[maybe_unused]]     = "\x1b[1;36m";
constexpr color_t fail [[maybe_unused]]       = "\x1b[1;31m";
constexpr color_t skipped [[maybe_unused]]    = "\x1b[1;33m";
constexpr color_t pass [[maybe_unused]]       = "\x1b[1;32m";
constexpr color_t highlight1 [[maybe_unused]] = "\x1b[1;35m";
constexpr color_t highlight2 [[maybe_unused]] = "\x1b[1;36m";
constexpr color_t reset [[maybe_unused]]      = "\x1b[0m";
} // namespace color

template<typename T>
struct colored {
    const T& value;
    color_t  color_start;
    color_t  color_end;
};

template<typename T>
colored<T> make_colored(const T& t, bool with_color, color_t start) noexcept {
    return {t, with_color ? start : "", with_color ? color::reset : ""};
}

template<typename T>
bool append(small_string_span ss, const colored<T>& colored_value) noexcept {
    if (ss.available() <= colored_value.color_start.size() + colored_value.color_end.size()) {
        return false;
    }

    bool could_fit = true;
    if (!append(ss, colored_value.color_start, colored_value.value)) {
        ss.resize(ss.capacity() - colored_value.color_end.size());
        could_fit = false;
    }

    return append(ss, colored_value.color_end) && could_fit;
}
} // namespace snitch::impl

#endif

#ifndef SNITCH_MATCHER_HPP
#define SNITCH_MATCHER_HPP


#include <optional>

namespace snitch::matchers {
enum class match_status { failed, matched };
}

namespace snitch {
template<typename T, typename U>
concept matcher_for = requires(const T& m, const U& value) {
    { m.match(value) } -> convertible_to<bool>;
    { m.describe_match(value, matchers::match_status{}) } -> convertible_to<std::string_view>;
};
} // namespace snitch

namespace snitch::impl {
template<typename T>
concept exception_with_what = requires(const T& e) {
    { e.what() } -> convertible_to<std::string_view>;
};

template<typename T, typename M>
[[nodiscard]] constexpr auto match(T&& value, M&& matcher) noexcept {
    using result_type = decltype(matcher.describe_match(value, matchers::match_status::failed));
    if (!matcher.match(value)) {
        return std::pair<bool, result_type>(
            false, matcher.describe_match(value, matchers::match_status::failed));
    } else {
        return std::pair<bool, result_type>(
            true, matcher.describe_match(value, matchers::match_status::matched));
    }
}
} // namespace snitch::impl

namespace snitch::matchers {
struct contains_substring {
    std::string_view substring_pattern;

    SNITCH_EXPORT explicit contains_substring(std::string_view pattern) noexcept;

    SNITCH_EXPORT bool match(std::string_view message) const noexcept;

    SNITCH_EXPORT small_string<max_message_length>
                  describe_match(std::string_view message, match_status status) const noexcept;
};

template<typename T, std::size_t N>
struct is_any_of {
    small_vector<T, N> list;

    template<typename... Args>
    explicit is_any_of(const Args&... args) noexcept : list({args...}) {}

    bool match(const T& value) const noexcept {
        for (const auto& v : list) {
            if (v == value) {
                return true;
            }
        }

        return false;
    }

    small_string<max_message_length>
    describe_match(const T& value, match_status status) const noexcept {
        small_string<max_message_length> description_buffer;
        append_or_truncate(
            description_buffer, "'", value, "' was ",
            (status == match_status::failed ? "not " : ""), "found in {");

        bool first = true;
        for (const auto& v : list) {
            if (!first) {
                append_or_truncate(description_buffer, ", '", v, "'");
            } else {
                append_or_truncate(description_buffer, "'", v, "'");
            }
            first = false;
        }
        append_or_truncate(description_buffer, "}");

        return description_buffer;
    }
};

template<typename T, typename... Args>
is_any_of(T, Args...) -> is_any_of<T, sizeof...(Args) + 1>;

struct with_what_contains : private contains_substring {
    SNITCH_EXPORT explicit with_what_contains(std::string_view pattern) noexcept;

    template<snitch::impl::exception_with_what E>
    bool match(const E& e) const noexcept {
        return contains_substring::match(e.what());
    }

    template<snitch::impl::exception_with_what E>
    small_string<max_message_length>
    describe_match(const E& e, match_status status) const noexcept {
        return contains_substring::describe_match(e.what(), status);
    }
};

template<typename T, matcher_for<T> M>
bool operator==(const T& value, const M& m) noexcept {
    return m.match(value);
}

template<typename T, matcher_for<T> M>
bool operator==(const M& m, const T& value) noexcept {
    return m.match(value);
}
} // namespace snitch::matchers

#endif

#ifndef SNITCH_EXPRESSION_HPP
#define SNITCH_EXPRESSION_HPP


#include <string_view>

namespace snitch {
// Maximum length of a `CHECK(...)` or `REQUIRE(...)` expression,
// beyond which automatic variable printing is disabled.
constexpr std::size_t max_expr_length = SNITCH_MAX_EXPR_LENGTH;
} // namespace snitch

namespace snitch::impl {
#define DEFINE_OPERATOR(OP, NAME, DISP, DISP_INV)                                                  \
    struct operator_##NAME {                                                                       \
        static constexpr std::string_view actual  = DISP;                                          \
        static constexpr std::string_view inverse = DISP_INV;                                      \
                                                                                                   \
        template<typename T, typename U>                                                           \
        constexpr bool operator()(const T& lhs, const U& rhs) const noexcept(noexcept(lhs OP rhs)) \
            requires(requires(const T& lhs, const U& rhs) { lhs OP rhs; })                         \
        {                                                                                          \
            return lhs OP rhs;                                                                     \
        }                                                                                          \
    }

DEFINE_OPERATOR(<, less, " < ", " >= ");
DEFINE_OPERATOR(>, greater, " > ", " <= ");
DEFINE_OPERATOR(<=, less_equal, " <= ", " > ");
DEFINE_OPERATOR(>=, greater_equal, " >= ", " < ");
DEFINE_OPERATOR(==, equal, " == ", " != ");
DEFINE_OPERATOR(!=, not_equal, " != ", " == ");

#undef DEFINE_OPERATOR

struct expression {
    std::string_view              type     = {};
    std::string_view              expected = {};
    small_string<max_expr_length> actual   = {};
    bool                          success  = true;

    template<string_appendable T>
    [[nodiscard]] constexpr bool append_value(T&& value) noexcept {
        return append(actual, std::forward<T>(value));
    }

    template<typename T>
    [[nodiscard]] constexpr bool append_value(T&&) noexcept {
        constexpr std::string_view unknown_value = "?";
        return append(actual, unknown_value);
    }
};

struct nondecomposable_expression : expression {};

struct invalid_expression {
    // This is an invalid expression; any further operator should produce another invalid
    // expression. We don't want to decompose these operators, but we need to declare them
    // so the expression compiles until calling to_expression(). This enable conditional
    // decomposition.
#define EXPR_OPERATOR_INVALID(OP)                                                                  \
    template<typename V>                                                                           \
    constexpr invalid_expression operator OP(const V&) noexcept {                                  \
        return {};                                                                                 \
    }

    EXPR_OPERATOR_INVALID(<=)
    EXPR_OPERATOR_INVALID(<)
    EXPR_OPERATOR_INVALID(>=)
    EXPR_OPERATOR_INVALID(>)
    EXPR_OPERATOR_INVALID(==)
    EXPR_OPERATOR_INVALID(!=)
    EXPR_OPERATOR_INVALID(&&)
    EXPR_OPERATOR_INVALID(||)
    EXPR_OPERATOR_INVALID(=)
    EXPR_OPERATOR_INVALID(+=)
    EXPR_OPERATOR_INVALID(-=)
    EXPR_OPERATOR_INVALID(*=)
    EXPR_OPERATOR_INVALID(/=)
    EXPR_OPERATOR_INVALID(%=)
    EXPR_OPERATOR_INVALID(^=)
    EXPR_OPERATOR_INVALID(&=)
    EXPR_OPERATOR_INVALID(|=)
    EXPR_OPERATOR_INVALID(<<=)
    EXPR_OPERATOR_INVALID(>>=)
    EXPR_OPERATOR_INVALID(^)
    EXPR_OPERATOR_INVALID(|)
    EXPR_OPERATOR_INVALID(&)

#undef EXPR_OPERATOR_INVALID

    constexpr nondecomposable_expression to_expression() const noexcept {
        // This should be unreachable, because we check if an expression is decomposable
        // before calling the decomposed expression. But the code will be instantiated in
        // constexpr expressions, so don't static_assert.
        return nondecomposable_expression{};
    }
};

template<bool Expected, typename T, typename O, typename U>
struct extracted_binary_expression {
    std::string_view type;
    std::string_view expected;
    const T&         lhs;
    const U&         rhs;

    // This is a binary expression; any further operator should produce an invalid
    // expression, since we can't/won't decompose complex expressions. We don't want to decompose
    // these operators, but we need to declare them so the expression compiles until cast to bool.
    // This enable conditional decomposition.
#define EXPR_OPERATOR_INVALID(OP)                                                                  \
    template<typename V>                                                                           \
    constexpr invalid_expression operator OP(const V&) noexcept {                                  \
        return {};                                                                                 \
    }

    EXPR_OPERATOR_INVALID(<=)
    EXPR_OPERATOR_INVALID(<)
    EXPR_OPERATOR_INVALID(>=)
    EXPR_OPERATOR_INVALID(>)
    EXPR_OPERATOR_INVALID(==)
    EXPR_OPERATOR_INVALID(!=)
    EXPR_OPERATOR_INVALID(&&)
    EXPR_OPERATOR_INVALID(||)
    EXPR_OPERATOR_INVALID(=)
    EXPR_OPERATOR_INVALID(+=)
    EXPR_OPERATOR_INVALID(-=)
    EXPR_OPERATOR_INVALID(*=)
    EXPR_OPERATOR_INVALID(/=)
    EXPR_OPERATOR_INVALID(%=)
    EXPR_OPERATOR_INVALID(^=)
    EXPR_OPERATOR_INVALID(&=)
    EXPR_OPERATOR_INVALID(|=)
    EXPR_OPERATOR_INVALID(<<=)
    EXPR_OPERATOR_INVALID(>>=)
    EXPR_OPERATOR_INVALID(^)
    EXPR_OPERATOR_INVALID(|)
    EXPR_OPERATOR_INVALID(&)

#define EXPR_COMMA ,
    EXPR_OPERATOR_INVALID(EXPR_COMMA)
#undef EXPR_COMMA

#undef EXPR_OPERATOR_INVALID

    // NB: Cannot make this noexcept since user operators may throw.
    constexpr expression to_expression() const noexcept(noexcept(static_cast<bool>(O{}(lhs, rhs))))
        requires(requires(const T& lhs, const U& rhs) { O{}(lhs, rhs); })
    {
        expression expr{type, expected};

        const bool actual = O{}(lhs, rhs);
        expr.success      = (actual == Expected);

        if (!expr.success || SNITCH_DECOMPOSE_SUCCESSFUL_ASSERTIONS) {
            if constexpr (matcher_for<T, U>) {
                using namespace snitch::matchers;
                const auto status = std::is_same_v<O, operator_equal> == actual
                                        ? match_status::matched
                                        : match_status::failed;
                if (!expr.append_value(lhs.describe_match(rhs, status))) {
                    expr.actual.clear();
                }
            } else if constexpr (matcher_for<U, T>) {
                using namespace snitch::matchers;
                const auto status = std::is_same_v<O, operator_equal> == actual
                                        ? match_status::matched
                                        : match_status::failed;
                if (!expr.append_value(rhs.describe_match(lhs, status))) {
                    expr.actual.clear();
                }
            } else {
                if (!expr.append_value(lhs) ||
                    !(actual ? expr.append_value(O::actual) : expr.append_value(O::inverse)) ||
                    !expr.append_value(rhs)) {
                    expr.actual.clear();
                }
            }
        }

        return expr;
    }

    constexpr nondecomposable_expression to_expression() const noexcept
        requires(!requires(const T& lhs, const U& rhs) { O{}(lhs, rhs); })
    {
        // This should be unreachable, because we check if an expression is decomposable
        // before calling the decomposed expression. But the code will be instantiated in
        // constexpr expressions, so don't static_assert.
        return nondecomposable_expression{};
    }
};

template<bool Expected, typename T>
struct extracted_unary_expression {
    std::string_view type;
    std::string_view expected;
    const T&         lhs;

    // Operators we want to decompose.
#define EXPR_OPERATOR(OP, OP_TYPE)                                                                 \
    template<typename U>                                                                           \
    constexpr extracted_binary_expression<Expected, T, OP_TYPE, U> operator OP(const U& rhs)       \
        const noexcept {                                                                           \
        return {type, expected, lhs, rhs};                                                         \
    }

    EXPR_OPERATOR(<, operator_less)
    EXPR_OPERATOR(>, operator_greater)
    EXPR_OPERATOR(<=, operator_less_equal)
    EXPR_OPERATOR(>=, operator_greater_equal)
    EXPR_OPERATOR(==, operator_equal)
    EXPR_OPERATOR(!=, operator_not_equal)

#undef EXPR_OPERATOR

    // We don't want to decompose the following operators, but we need to declare them so the
    // expression compiles until cast to bool. This enable conditional decomposition.
#define EXPR_OPERATOR_INVALID(OP)                                                                  \
    template<typename V>                                                                           \
    constexpr invalid_expression operator OP(const V&) noexcept {                                  \
        return {};                                                                                 \
    }

    EXPR_OPERATOR_INVALID(&&)
    EXPR_OPERATOR_INVALID(||)
    EXPR_OPERATOR_INVALID(=)
    EXPR_OPERATOR_INVALID(+=)
    EXPR_OPERATOR_INVALID(-=)
    EXPR_OPERATOR_INVALID(*=)
    EXPR_OPERATOR_INVALID(/=)
    EXPR_OPERATOR_INVALID(%=)
    EXPR_OPERATOR_INVALID(^=)
    EXPR_OPERATOR_INVALID(&=)
    EXPR_OPERATOR_INVALID(|=)
    EXPR_OPERATOR_INVALID(<<=)
    EXPR_OPERATOR_INVALID(>>=)
    EXPR_OPERATOR_INVALID(^)
    EXPR_OPERATOR_INVALID(|)
    EXPR_OPERATOR_INVALID(&)

#define EXPR_COMMA ,
    EXPR_OPERATOR_INVALID(EXPR_COMMA)
#undef EXPR_COMMA

#undef EXPR_OPERATOR_INVALID

    constexpr expression to_expression() const noexcept(noexcept(static_cast<bool>(lhs)))
        requires(requires(const T& lhs) { static_cast<bool>(lhs); })
    {
        expression expr{type, expected};

        expr.success = (static_cast<bool>(lhs) == Expected);

        if (!expr.success || SNITCH_DECOMPOSE_SUCCESSFUL_ASSERTIONS) {
            if (!expr.append_value(lhs)) {
                expr.actual.clear();
            }
        }

        return expr;
    }

    constexpr nondecomposable_expression to_expression() const noexcept
        requires(!requires(const T& lhs) { static_cast<bool>(lhs); })
    {
        // This should be unreachable, because we check if an expression is decomposable
        // before calling the decomposed expression. But the code will be instantiated in
        // constexpr expressions, so don't static_assert.
        return nondecomposable_expression{};
    }
};

template<bool Expected>
struct expression_extractor {
    std::string_view type;
    std::string_view expected;

    template<typename T>
    constexpr extracted_unary_expression<Expected, T> operator<=(const T& lhs) const noexcept {
        return {type, expected, lhs};
    }
};

template<typename T>
constexpr bool is_decomposable = !std::is_same_v<T, nondecomposable_expression>;
} // namespace snitch::impl

#endif

#ifndef SNITCH_FILE_HPP
#define SNITCH_FILE_HPP


#include <string_view>

namespace snitch {
// Maximum length of a file path.
constexpr std::size_t max_path_length = SNITCH_MAX_PATH_LENGTH;
// Maximum size of a file object, in bytes.
constexpr std::size_t max_file_object_size_bytes = SNITCH_MAX_FILE_OBJECT_SIZE_BYTES;

using file_object_storage = inplace_any<max_file_object_size_bytes>;
} // namespace snitch

namespace snitch::impl {
SNITCH_EXPORT void stdio_file_open(file_object_storage& storage, std::string_view path);

SNITCH_EXPORT void
stdio_file_write(const file_object_storage& storage, std::string_view message) noexcept;

SNITCH_EXPORT void stdio_file_close(file_object_storage& storage) noexcept;

class file_writer {
    file_object_storage storage;

public:
    SNITCH_EXPORT constexpr file_writer() noexcept = default;

    // Requires: permission to write to the given path, path length less than max_path_length
    SNITCH_EXPORT explicit file_writer(std::string_view path);

    file_writer(const file_writer&)            = delete;
    file_writer& operator=(const file_writer&) = delete;

    SNITCH_EXPORT file_writer(file_writer&& other) noexcept;

    SNITCH_EXPORT file_writer& operator=(file_writer&& other) noexcept;

    SNITCH_EXPORT ~file_writer();

    SNITCH_EXPORT void write(std::string_view message) noexcept;

    SNITCH_EXPORT bool is_open() noexcept;

    SNITCH_EXPORT void close() noexcept;
};
} // namespace snitch::impl

namespace snitch::io {
// Requires: permission to write to the given path, path length less than max_path_length
SNITCH_EXPORT extern function_ref<void(file_object_storage& storage, std::string_view path)>
    file_open;

SNITCH_EXPORT extern function_ref<void(
    const file_object_storage& storage, std::string_view message) noexcept>
    file_write;

SNITCH_EXPORT extern function_ref<void(file_object_storage& storage) noexcept> file_close;
} // namespace snitch::io

#endif

#ifndef SNITCH_REPORTER_CONSOLE_HPP
#define SNITCH_REPORTER_CONSOLE_HPP


#include <string_view>

namespace snitch::reporter::console {
struct reporter {
    std::size_t counter = 0;

    reporter() = default;

    SNITCH_EXPORT explicit reporter(registry& r) noexcept;

    SNITCH_EXPORT bool configure(registry&, std::string_view, std::string_view) noexcept;

    SNITCH_EXPORT void report(const registry& r, const snitch::event::data& event) noexcept;
};
} // namespace snitch::reporter::console

#endif

#ifndef SNITCH_TYPE_NAME_HPP
#define SNITCH_TYPE_NAME_HPP


#include <string_view>

namespace snitch::impl {
template<typename T>
constexpr std::string_view get_type_name() noexcept {
#if defined(__clang__)
    constexpr auto prefix   = std::string_view{"[T = "};
    constexpr auto suffix   = "]";
    constexpr auto function = std::string_view{__PRETTY_FUNCTION__};
#elif defined(__GNUC__)
    constexpr auto prefix   = std::string_view{"with T = "};
    constexpr auto suffix   = "; ";
    constexpr auto function = std::string_view{__PRETTY_FUNCTION__};
#elif defined(_MSC_VER)
    constexpr auto prefix   = std::string_view{"get_type_name<"};
    constexpr auto suffix   = ">(void)";
    constexpr auto function = std::string_view{__FUNCSIG__};
#else
#    error Unsupported compiler
#endif

    const auto start = function.find(prefix) + prefix.size();
    const auto end   = function.find(suffix);
    const auto size  = end - start;

    return function.substr(start, size);
}
} // namespace snitch::impl

namespace snitch {
template<typename T>
constexpr std::string_view type_name = impl::get_type_name<T>();
}

#endif

#ifndef SNITCH_REGISTRY_HPP
#define SNITCH_REGISTRY_HPP


#include <cstddef>
#include <string_view>
#include <utility>

namespace snitch {
// Maximum number of test cases in the whole program.
// A "test case" is created for each uses of the `*_TEST_CASE` macros,
// and for each type for the `TEMPLATE_LIST_TEST_CASE` macro.
constexpr std::size_t max_test_cases = SNITCH_MAX_TEST_CASES;
// Maximum length of a full test case name.
// The full test case name includes the base name, plus any type.
constexpr std::size_t max_test_name_length = SNITCH_MAX_TEST_NAME_LENGTH;
// Maximum length of a tag, including brackets.
constexpr std::size_t max_tag_length = SNITCH_MAX_TAG_LENGTH;
// Maximum number of unique tags in the whole program.
constexpr std::size_t max_unique_tags = SNITCH_MAX_UNIQUE_TAGS;
// Maximum number of registered reporters to select from the command line.
constexpr std::size_t max_registered_reporters = SNITCH_MAX_REGISTERED_REPORTERS;
// Maximum size of a reporter instance, in bytes.
constexpr std::size_t max_reporter_size_bytes = SNITCH_MAX_REPORTER_SIZE_BYTES;
// Is snitch disabled?
constexpr bool is_enabled = SNITCH_ENABLE;
} // namespace snitch

namespace snitch::impl {
struct name_and_tags {
    std::string_view name = {};
    std::string_view tags = {};
};

struct fixture_name_and_tags {
    std::string_view fixture = {};
    std::string_view name    = {};
    std::string_view tags    = {};
};

SNITCH_EXPORT bool
make_full_name(small_string<max_test_name_length>& buffer, const test_id& id) noexcept;

template<typename T, typename F>
constexpr test_ptr to_test_case_ptr(const F&) noexcept {
    return []() { F{}.template operator()<T>(); };
}

struct abort_exception {};

SNITCH_EXPORT bool parse_colour_mode_option(registry& reg, std::string_view color_option) noexcept;
SNITCH_EXPORT bool parse_color_option(registry& reg, std::string_view color_option) noexcept;
} // namespace snitch::impl

namespace snitch {
template<typename... Args>
struct type_list {};

struct filter_result {
    bool included = false;
    bool implicit = false;
};

SNITCH_EXPORT [[nodiscard]] filter_result
filter_result_and(filter_result first, filter_result second) noexcept;

SNITCH_EXPORT [[nodiscard]] filter_result
filter_result_or(filter_result first, filter_result second) noexcept;

SNITCH_EXPORT [[nodiscard]] filter_result
is_filter_match_name(std::string_view name, std::string_view filter) noexcept;

SNITCH_EXPORT [[nodiscard]] filter_result
is_filter_match_tags(std::string_view tags, std::string_view filter) noexcept;

SNITCH_EXPORT [[nodiscard]] filter_result
is_filter_match_id(std::string_view name, std::string_view tags, std::string_view filter) noexcept;

using print_function  = function_ref<void(std::string_view) noexcept>;
using report_function = function_ref<void(const registry&, const event::data&) noexcept>;
using configure_report_function =
    function_ref<bool(registry&, std::string_view, std::string_view) noexcept>;
using initialize_report_function = function_ref<void(registry&) noexcept>;
using finish_report_function     = function_ref<void(registry&) noexcept>;

struct registered_reporter {
    std::string_view           name;
    initialize_report_function initialize = [](registry&) noexcept {};
    configure_report_function  configure =
        [](registry&, std::string_view, std::string_view) noexcept { return false; };
    report_function        callback = [](const registry&, const event::data&) noexcept {};
    finish_report_function finish   = [](registry&) noexcept {};
};

template<typename T>
concept reporter_type = requires(registry& reg) {
    T{reg};
} && requires(T& rep, registry& reg, std::string_view k, std::string_view v) {
    { rep.configure(reg, k, v) } -> convertible_to<bool>;
} && requires(T& rep, const registry& reg, const event::data& e) { rep.report(reg, e); };

class registry {
    // Contains all registered test cases.
    small_vector<impl::test_case, max_test_cases> test_list;

    // Contains all registered reporters.
    small_vector<registered_reporter, max_registered_reporters> registered_reporters;

    // Used when writing output to file.
    std::optional<impl::file_writer> file_writer;

    // Type-erased storage for the current reporter instance.
    inplace_any<max_reporter_size_bytes> reporter_storage;

    template<typename T>
    void initialize_reporter(registry&) noexcept {
        this->reporter_storage.emplace<T>(*this);
    }

    template<typename T>
    void report(const registry&, const event::data& e) noexcept {
        this->reporter_storage.get<T>().report(*this, e);
    }

    template<typename T>
    bool configure_reporter(registry&, std::string_view k, std::string_view v) noexcept {
        return this->reporter_storage.get<T>().configure(*this, k, v);
    }

    SNITCH_EXPORT void destroy_reporter(registry&) noexcept;

    SNITCH_EXPORT void report_default(const registry&, const event::data& e) noexcept;

public:
    enum class verbosity { quiet, normal, high, full } verbose = verbosity::normal;
    bool with_color                                            = SNITCH_DEFAULT_WITH_COLOR == 1;

    using print_function             = snitch::print_function;
    using initialize_report_function = snitch::initialize_report_function;
    using configure_report_function  = snitch::configure_report_function;
    using report_function            = snitch::report_function;
    using finish_report_function     = snitch::finish_report_function;

    print_function         print_callback  = &snitch::impl::stdout_print;
    report_function        report_callback = {*this, constant<&registry::report_default>{}};
    finish_report_function finish_callback = [](registry&) noexcept {};

    // Internal API; do not use.
    template<typename T>
    void append_or_print(small_string<max_message_length>& ss, T&& value) const noexcept {
        const std::size_t init_size = ss.size();
        if (append(ss, value)) {
            return;
        }

        ss.resize(init_size);
        this->print_callback(ss);
        ss.clear();

        if (append(ss, value)) {
            return;
        }

        if constexpr (std::is_convertible_v<std::decay_t<T>, std::string_view>) {
            ss.clear();
            this->print_callback(value);
        } else {
            this->print_callback(ss);
            ss.clear();
            static_cast<void>(append(ss, "..."));
        }
    }

    template<typename... Args>
    void print(Args&&... args) const noexcept {
        small_string<max_message_length> message;
        (append_or_print(message, std::forward<Args>(args)), ...);
        if (!message.empty()) {
            this->print_callback(message);
        }
    }

    template<convertible_to<std::string_view> T>
    void print(const T& str) const noexcept {
        this->print_callback(str);
    }

    // Requires: number of reporters + 1 <= max_registered_reporters.
    SNITCH_EXPORT std::string_view add_reporter(
        std::string_view                                 name,
        const std::optional<initialize_report_function>& initialize,
        const std::optional<configure_report_function>&  configure,
        const report_function&                           report,
        const std::optional<finish_report_function>&     finish);

    // Requires: number of reporters + 1 <= max_registered_reporters.
    template<reporter_type T>
    std::string_view add_reporter(std::string_view name) {
        return this->add_reporter(
            name, initialize_report_function{*this, constant<&registry::initialize_reporter<T>>{}},
            configure_report_function{*this, constant<&registry::configure_reporter<T>>{}},
            report_function{*this, constant<&registry::report<T>>{}},
            finish_report_function{*this, constant<&registry::destroy_reporter>{}});
    }

    // Internal API; do not use.
    // Requires: number of tests + 1 <= max_test_cases, well-formed test ID.
    SNITCH_EXPORT const char*
    add_impl(const test_id& id, const source_location& location, impl::test_ptr func);

    // Internal API; do not use.
    // Requires: number of tests + 1 <= max_test_cases, well-formed test ID.
    SNITCH_EXPORT const char*
    add(const impl::name_and_tags& id, const source_location& location, impl::test_ptr func);

    // Internal API; do not use.
    // Requires: number of tests + added tests <= max_test_cases, well-formed test ID.
    template<typename... Args, typename F>
    const char*
    add_with_types(const impl::name_and_tags& id, const source_location& location, const F& func) {
        static_assert(sizeof...(Args) > 0, "empty type list in TEMPLATE_TEST_CASE");
        return (
            add_impl(
                {id.name, id.tags, type_name<Args>}, location, impl::to_test_case_ptr<Args>(func)),
            ...);
    }

    // Internal API; do not use.
    // Requires: number of tests + added tests <= max_test_cases, well-formed test ID.
    template<typename T, typename F>
    const char* add_with_type_list(
        const impl::name_and_tags& id, const source_location& location, const F& func) {
        return [&]<template<typename...> typename TL, typename... Args>(type_list<TL<Args...>>) {
            static_assert(sizeof...(Args) > 0, "empty type list in TEMPLATE_LIST_TEST_CASE");
            return this->add_with_types<Args...>(id, location, func);
        }(type_list<T>{});
    }

    // Internal API; do not use.
    // Requires: number of tests + 1 <= max_test_cases, well-formed test ID.
    SNITCH_EXPORT const char* add_fixture(
        const impl::fixture_name_and_tags& id,
        const source_location&             location,
        impl::test_ptr                     func);

    // Internal API; do not use.
    // Requires: number of tests + added tests <= max_test_cases, well-formed test ID.
    template<typename... Args, typename F>
    const char* add_fixture_with_types(
        const impl::fixture_name_and_tags& id, const source_location& location, const F& func) {
        return (
            add_impl(
                {id.name, id.tags, type_name<Args>, id.fixture}, location,
                impl::to_test_case_ptr<Args>(func)),
            ...);
    }

    // Internal API; do not use.
    // Requires: number of tests + added tests <= max_test_cases, well-formed test ID.
    template<typename T, typename F>
    const char* add_fixture_with_type_list(
        const impl::fixture_name_and_tags& id, const source_location& location, const F& func) {
        return [&]<template<typename...> typename TL, typename... Args>(type_list<TL<Args...>>) {
            return this->add_fixture_with_types<Args...>(id, location, func);
        }(type_list<T>{});
    }

    // Internal API; do not use.
    SNITCH_EXPORT static void report_assertion(bool success, std::string_view message) noexcept;

    // Internal API; do not use.
    SNITCH_EXPORT static void
    report_assertion(bool success, std::string_view message1, std::string_view message2) noexcept;

    // Internal API; do not use.
    SNITCH_EXPORT static void report_assertion(bool success, const impl::expression& exp) noexcept;

    // Internal API; do not use.
    SNITCH_EXPORT static void report_skipped(std::string_view message) noexcept;

    // Internal API; do not use.
    SNITCH_EXPORT static void report_section_started(const section& sec) noexcept;

    // Internal API; do not use.
    SNITCH_EXPORT static void report_section_ended(const section& sec) noexcept;

    // Internal API; do not use.
    SNITCH_EXPORT impl::test_state run(impl::test_case& test) noexcept;

    // Internal API; do not use.
    SNITCH_EXPORT bool run_tests(std::string_view run_name) noexcept;

    // Internal API; do not use.
    SNITCH_EXPORT bool run_selected_tests(
        std::string_view                                   run_name,
        const filter_info&                                 filter_strings,
        const function_ref<bool(const test_id&) noexcept>& filter) noexcept;

    SNITCH_EXPORT bool run_tests(const cli::input& args) noexcept;

    // Requires: output file path (if configured) is valid
    SNITCH_EXPORT void configure(const cli::input& args);

    SNITCH_EXPORT void list_all_tests() const noexcept;

    // Requires: number unique tags <= max_unique_tags.
    SNITCH_EXPORT void list_all_tags() const;

    SNITCH_EXPORT void list_tests_with_tag(std::string_view tag) const noexcept;

    SNITCH_EXPORT void list_all_reporters() const noexcept;

    SNITCH_EXPORT small_vector_span<impl::test_case> test_cases() noexcept;
    SNITCH_EXPORT small_vector_span<const impl::test_case> test_cases() const noexcept;

    SNITCH_EXPORT small_vector_span<registered_reporter> reporters() noexcept;
    SNITCH_EXPORT small_vector_span<const registered_reporter> reporters() const noexcept;
};

SNITCH_EXPORT extern constinit registry tests;
} // namespace snitch

#endif

#ifndef SNITCH_MACROS_CHECK_BASE_HPP
#define SNITCH_MACROS_CHECK_BASE_HPP


#include <string_view>

#if SNITCH_WITH_EXCEPTIONS
#    define SNITCH_TESTING_ABORT                                                                   \
        throw snitch::impl::abort_exception {}
#else
#    define SNITCH_TESTING_ABORT std::terminate()
#endif

#define SNITCH_NEW_CHECK                                                                           \
    snitch::impl::scoped_test_check {                                                              \
        SNITCH_CURRENT_LOCATION                                                                    \
    }

#define SNITCH_EXPR(TYPE, EXPECTED, ...)                                                           \
    auto SNITCH_CURRENT_EXPRESSION =                                                               \
        (snitch::impl::expression_extractor<EXPECTED>{TYPE, #__VA_ARGS__} <= __VA_ARGS__)          \
            .to_expression()

#define SNITCH_IS_DECOMPOSABLE(...)                                                                \
    snitch::impl::is_decomposable<decltype((snitch::impl::expression_extractor<true>{              \
                                                std::declval<std::string_view>(),                  \
                                                std::declval<std::string_view>()} <= __VA_ARGS__)  \
                                               .to_expression())>

#define SNITCH_REPORT_EXPRESSION(MAYBE_ABORT)                                                      \
    snitch::registry::report_assertion(                                                            \
        SNITCH_CURRENT_EXPRESSION.success, SNITCH_CURRENT_EXPRESSION);                             \
    if (!SNITCH_CURRENT_EXPRESSION.success) {                                                      \
        MAYBE_ABORT;                                                                               \
    }

#endif

#ifndef SNITCH_MACROS_WARNINGS_HPP
#define SNITCH_MACROS_WARNINGS_HPP


// clang-format off
#if defined(__clang__)
#    define SNITCH_WARNING_PUSH _Pragma("clang diagnostic push")
#    define SNITCH_WARNING_POP _Pragma("clang diagnostic pop")
#    define SNITCH_WARNING_DISABLE_PARENTHESES _Pragma("clang diagnostic ignored \"-Wparentheses\"")
#    define SNITCH_WARNING_DISABLE_CONSTANT_COMPARISON
#elif defined(__GNUC__)
#    define SNITCH_WARNING_PUSH _Pragma("GCC diagnostic push")
#    define SNITCH_WARNING_POP _Pragma("GCC diagnostic pop")
#    define SNITCH_WARNING_DISABLE_PARENTHESES _Pragma("GCC diagnostic ignored \"-Wparentheses\"")
#    define SNITCH_WARNING_DISABLE_CONSTANT_COMPARISON
#elif defined(_MSC_VER)
#    define SNITCH_WARNING_PUSH _Pragma("warning(push)")
#    define SNITCH_WARNING_POP _Pragma("warning(pop)")
#    define SNITCH_WARNING_DISABLE_PARENTHESES
#    define SNITCH_WARNING_DISABLE_CONSTANT_COMPARISON _Pragma("warning(disable: 4127)")
#else
#    define SNITCH_WARNING_PUSH
#    define SNITCH_WARNING_POP
#    define SNITCH_WARNING_DISABLE_PARENTHESES
#    define SNITCH_WARNING_DISABLE_CONSTANT_COMPARISON
#endif
// clang-format on

#endif

#ifndef SNITCH_MACROS_UTILITY_HPP
#define SNITCH_MACROS_UTILITY_HPP


#define SNITCH_CONCAT_IMPL(x, y) x##y
#define SNITCH_MACRO_CONCAT(x, y) SNITCH_CONCAT_IMPL(x, y)

#define SNITCH_CURRENT_LOCATION                                                                    \
    snitch::source_location {                                                                      \
        std::string_view{__FILE__}, static_cast<std::size_t>(__LINE__)                             \
    }

#define SNITCH_DISCARD_ARGS(...)                                                                   \
    do {                                                                                           \
        SNITCH_WARNING_PUSH                                                                        \
        SNITCH_WARNING_DISABLE_PARENTHESES                                                         \
        SNITCH_WARNING_DISABLE_CONSTANT_COMPARISON                                                 \
        static_cast<void>(sizeof(__VA_ARGS__, 0));                                                 \
        SNITCH_WARNING_POP                                                                         \
    } while (0)

#define SNITCH_VOID_STATEMENT static_cast<void>(0)

#endif

#ifndef SNITCH_MACROS_CHECK_HPP
#define SNITCH_MACROS_CHECK_HPP


#if SNITCH_ENABLE

#    define SNITCH_REQUIRE_IMPL(CHECK, EXPECTED, MAYBE_ABORT, ...)                                 \
        do {                                                                                       \
            auto SNITCH_CURRENT_CHECK = SNITCH_NEW_CHECK;                                          \
            SNITCH_WARNING_PUSH                                                                    \
            SNITCH_WARNING_DISABLE_PARENTHESES                                                     \
            SNITCH_WARNING_DISABLE_CONSTANT_COMPARISON                                             \
            if constexpr (SNITCH_IS_DECOMPOSABLE(__VA_ARGS__)) {                                   \
                SNITCH_EXPR(CHECK, EXPECTED, __VA_ARGS__);                                         \
                SNITCH_REPORT_EXPRESSION(MAYBE_ABORT);                                             \
            } else {                                                                               \
                const auto SNITCH_CURRENT_EXPRESSION = snitch::impl::expression{                   \
                    CHECK, #__VA_ARGS__, {}, static_cast<bool>(__VA_ARGS__) == EXPECTED};          \
                SNITCH_REPORT_EXPRESSION(MAYBE_ABORT);                                             \
            }                                                                                      \
            SNITCH_WARNING_POP                                                                     \
        } while (0)

// clang-format off
#    define SNITCH_REQUIRE(...)       SNITCH_REQUIRE_IMPL("REQUIRE",       true,  SNITCH_TESTING_ABORT,  __VA_ARGS__)
#    define SNITCH_CHECK(...)         SNITCH_REQUIRE_IMPL("CHECK",         true,  (void)0,               __VA_ARGS__)
#    define SNITCH_REQUIRE_FALSE(...) SNITCH_REQUIRE_IMPL("REQUIRE_FALSE", false, SNITCH_TESTING_ABORT,  __VA_ARGS__)
#    define SNITCH_CHECK_FALSE(...)   SNITCH_REQUIRE_IMPL("CHECK_FALSE",   false, (void)0,               __VA_ARGS__)
// clang-format on

#    define SNITCH_SUCCEED(MESSAGE)                                                                \
        do {                                                                                       \
            auto SNITCH_CURRENT_CHECK = SNITCH_NEW_CHECK;                                          \
            snitch::registry::report_assertion(true, (MESSAGE));                                   \
        } while (0)

#    define SNITCH_FAIL(MESSAGE)                                                                   \
        do {                                                                                       \
            auto SNITCH_CURRENT_CHECK = SNITCH_NEW_CHECK;                                          \
            snitch::registry::report_assertion(false, (MESSAGE));                                  \
            SNITCH_TESTING_ABORT;                                                                  \
        } while (0)

#    define SNITCH_FAIL_CHECK(MESSAGE)                                                             \
        do {                                                                                       \
            auto SNITCH_CURRENT_CHECK = SNITCH_NEW_CHECK;                                          \
            snitch::registry::report_assertion(false, (MESSAGE));                                  \
        } while (0)

#    define SNITCH_SKIP(MESSAGE)                                                                   \
        do {                                                                                       \
            auto SNITCH_CURRENT_CHECK = SNITCH_NEW_CHECK;                                          \
            snitch::registry::report_skipped((MESSAGE));                                           \
            SNITCH_TESTING_ABORT;                                                                  \
        } while (0)

#    define SNITCH_SKIP_CHECK(MESSAGE)                                                             \
        do {                                                                                       \
            auto SNITCH_CURRENT_CHECK = SNITCH_NEW_CHECK;                                          \
            snitch::registry::report_skipped((MESSAGE));                                           \
        } while (0)

#    define SNITCH_REQUIRE_THAT_IMPL(CHECK, MAYBE_ABORT, EXPR, ...)                                \
        do {                                                                                       \
            auto       SNITCH_CURRENT_CHECK      = SNITCH_NEW_CHECK;                               \
            const auto SNITCH_TEMP_RESULT        = snitch::impl::match(EXPR, __VA_ARGS__);         \
            const auto SNITCH_CURRENT_EXPRESSION = snitch::impl::expression{                       \
                CHECK, #EXPR ", " #__VA_ARGS__,                                                    \
                snitch::resize_or_truncate<snitch::max_expr_length>(SNITCH_TEMP_RESULT.second),    \
                SNITCH_TEMP_RESULT.first};                                                         \
            SNITCH_REPORT_EXPRESSION(MAYBE_ABORT);                                                 \
        } while (0)

// clang-format off
#    define SNITCH_REQUIRE_THAT(EXPR, ...) SNITCH_REQUIRE_THAT_IMPL("REQUIRE_THAT", SNITCH_TESTING_ABORT,  EXPR, __VA_ARGS__)
#    define SNITCH_CHECK_THAT(EXPR, ...)   SNITCH_REQUIRE_THAT_IMPL("CHECK_THAT",   (void)0,               EXPR, __VA_ARGS__)
// clang-format on

#else // SNITCH_ENABLE
// clang-format off
#    define SNITCH_REQUIRE(...)       SNITCH_DISCARD_ARGS(__VA_ARGS__)
#    define SNITCH_CHECK(...)         SNITCH_DISCARD_ARGS(__VA_ARGS__)
#    define SNITCH_REQUIRE_FALSE(...) SNITCH_DISCARD_ARGS(__VA_ARGS__)
#    define SNITCH_CHECK_FALSE(...)   SNITCH_DISCARD_ARGS(__VA_ARGS__)

#    define SNITCH_SUCCEED(MESSAGE)    SNITCH_VOID_STATEMENT
#    define SNITCH_FAIL(MESSAGE)       SNITCH_VOID_STATEMENT
#    define SNITCH_FAIL_CHECK(MESSAGE) SNITCH_VOID_STATEMENT
#    define SNITCH_SKIP(MESSAGE)       SNITCH_VOID_STATEMENT
#    define SNITCH_SKIP_CHECK(MESSAGE) SNITCH_VOID_STATEMENT

#    define SNITCH_REQUIRE_THAT(EXPR, ...) SNITCH_DISCARD_ARGS(EXPR, __VA_ARGS__)
#    define SNITCH_CHECK_THAT(EXPR, ...)   SNITCH_DISCARD_ARGS(EXPR, __VA_ARGS__)
// clang-format on

#endif // SNITCH_ENABLE

// clang-format on
#if SNITCH_WITH_SHORTHAND_MACROS
#    define SUCCEED(MESSAGE) SNITCH_SUCCEED(MESSAGE)
#    define FAIL(MESSAGE) SNITCH_FAIL(MESSAGE)
#    define FAIL_CHECK(MESSAGE) SNITCH_FAIL_CHECK(MESSAGE)
#    define SKIP(MESSAGE) SNITCH_SKIP(MESSAGE)
#    define SKIP_CHECK(MESSAGE) SNITCH_SKIP_CHECK(MESSAGE)

#    define REQUIRE(...) SNITCH_REQUIRE(__VA_ARGS__)
#    define CHECK(...) SNITCH_CHECK(__VA_ARGS__)
#    define REQUIRE_FALSE(...) SNITCH_REQUIRE_FALSE(__VA_ARGS__)
#    define CHECK_FALSE(...) SNITCH_CHECK_FALSE(__VA_ARGS__)
#    define REQUIRE_THAT(EXP, ...) SNITCH_REQUIRE_THAT(EXP, __VA_ARGS__)
#    define CHECK_THAT(EXP, ...) SNITCH_CHECK_THAT(EXP, __VA_ARGS__)
#endif
// clang-format on

#endif

#ifndef SNITCH_MACROS_CONSTEVAL_HPP
#define SNITCH_MACROS_CONSTEVAL_HPP


#if SNITCH_ENABLE

#    define SNITCH_CONSTEVAL_REQUIRE_IMPL(CHECK, EXPECTED, MAYBE_ABORT, ...)                       \
        do {                                                                                       \
            auto SNITCH_CURRENT_CHECK = SNITCH_NEW_CHECK;                                          \
            SNITCH_WARNING_PUSH                                                                    \
            SNITCH_WARNING_DISABLE_PARENTHESES                                                     \
            SNITCH_WARNING_DISABLE_CONSTANT_COMPARISON                                             \
            if constexpr (SNITCH_IS_DECOMPOSABLE(__VA_ARGS__)) {                                   \
                constexpr SNITCH_EXPR(CHECK, EXPECTED, __VA_ARGS__);                               \
                SNITCH_REPORT_EXPRESSION(MAYBE_ABORT);                                             \
            } else {                                                                               \
                constexpr auto SNITCH_CURRENT_EXPRESSION = snitch::impl::expression{               \
                    CHECK, #__VA_ARGS__, {}, static_cast<bool>(__VA_ARGS__) == EXPECTED};          \
                SNITCH_REPORT_EXPRESSION(MAYBE_ABORT);                                             \
            }                                                                                      \
            SNITCH_WARNING_POP                                                                     \
        } while (0)

// clang-format off
#    define SNITCH_CONSTEVAL_REQUIRE(...)       SNITCH_CONSTEVAL_REQUIRE_IMPL("CONSTEVAL_REQUIRE",       true,  SNITCH_TESTING_ABORT,  __VA_ARGS__)
#    define SNITCH_CONSTEVAL_CHECK(...)         SNITCH_CONSTEVAL_REQUIRE_IMPL("CONSTEVAL_CHECK",         true,  (void)0,               __VA_ARGS__)
#    define SNITCH_CONSTEVAL_REQUIRE_FALSE(...) SNITCH_CONSTEVAL_REQUIRE_IMPL("CONSTEVAL_REQUIRE_FALSE", false, SNITCH_TESTING_ABORT,  __VA_ARGS__)
#    define SNITCH_CONSTEVAL_CHECK_FALSE(...)   SNITCH_CONSTEVAL_REQUIRE_IMPL("CONSTEVAL_CHECK_FALSE",   false, (void)0,               __VA_ARGS__)
// clang-format on

#    define SNITCH_CONSTEVAL_REQUIRE_THAT_IMPL(CHECK, MAYBE_ABORT, EXPR, ...)                      \
        do {                                                                                       \
            auto           SNITCH_CURRENT_CHECK      = SNITCH_NEW_CHECK;                           \
            constexpr auto SNITCH_TEMP_RESULT        = snitch::impl::match(EXPR, __VA_ARGS__);     \
            constexpr auto SNITCH_CURRENT_EXPRESSION = snitch::impl::expression{                   \
                CHECK, #EXPR ", " #__VA_ARGS__,                                                    \
                snitch::resize_or_truncate<snitch::max_expr_length>(SNITCH_TEMP_RESULT.second),    \
                SNITCH_TEMP_RESULT.first};                                                         \
            SNITCH_REPORT_EXPRESSION(MAYBE_ABORT);                                                 \
        } while (0)

// clang-format off
#    define SNITCH_CONSTEVAL_REQUIRE_THAT(EXPR, ...) SNITCH_CONSTEVAL_REQUIRE_THAT_IMPL("CONSTEVAL_REQUIRE_THAT", SNITCH_TESTING_ABORT,  EXPR, __VA_ARGS__)
#    define SNITCH_CONSTEVAL_CHECK_THAT(EXPR, ...)   SNITCH_CONSTEVAL_REQUIRE_THAT_IMPL("CONSTEVAL_CHECK_THAT",   (void)0,               EXPR, __VA_ARGS__)
// clang-format on

#else // SNITCH_ENABLE

// clang-format off
#    define SNITCH_CONSTEVAL_REQUIRE(...)            SNITCH_DISCARD_ARGS(__VA_ARGS__)
#    define SNITCH_CONSTEVAL_CHECK(...)              SNITCH_DISCARD_ARGS(__VA_ARGS__)
#    define SNITCH_CONSTEVAL_REQUIRE_FALSE(...)      SNITCH_DISCARD_ARGS(__VA_ARGS__)
#    define SNITCH_CONSTEVAL_CHECK_FALSE(...)        SNITCH_DISCARD_ARGS(__VA_ARGS__)
#    define SNITCH_CONSTEVAL_REQUIRE_THAT(EXPR, ...) SNITCH_DISCARD_ARGS(EXPR, __VA_ARGS__)
#    define SNITCH_CONSTEVAL_CHECK_THAT(EXPR, ...)   SNITCH_DISCARD_ARGS(EXPR, __VA_ARGS__)
// clang-format on

#endif // SNITCH_ENABLE

// clang-format off
#if SNITCH_WITH_SHORTHAND_MACROS
#    define CONSTEVAL_REQUIRE(...)           SNITCH_CONSTEVAL_REQUIRE(__VA_ARGS__)
#    define CONSTEVAL_CHECK(...)             SNITCH_CONSTEVAL_CHECK(__VA_ARGS__)
#    define CONSTEVAL_REQUIRE_FALSE(...)     SNITCH_CONSTEVAL_REQUIRE_FALSE(__VA_ARGS__)
#    define CONSTEVAL_CHECK_FALSE(...)       SNITCH_CONSTEVAL_CHECK_FALSE(__VA_ARGS__)
#    define CONSTEVAL_REQUIRE_THAT(EXP, ...) SNITCH_CONSTEVAL_REQUIRE_THAT(EXP, __VA_ARGS__)
#    define CONSTEVAL_CHECK_THAT(EXP, ...)   SNITCH_CONSTEVAL_CHECK_THAT(EXP, __VA_ARGS__)
#endif
// clang-format on

#endif

#ifndef SNITCH_MACROS_CONSTEXPR_HPP
#define SNITCH_MACROS_CONSTEXPR_HPP


#if SNITCH_ENABLE

#    define SNITCH_CONSTEXPR_REQUIRE_IMPL(CHECK, EXPECTED, MAYBE_ABORT, ...)                       \
        do {                                                                                       \
            auto SNITCH_CURRENT_CHECK = SNITCH_NEW_CHECK;                                          \
            SNITCH_WARNING_PUSH                                                                    \
            SNITCH_WARNING_DISABLE_PARENTHESES                                                     \
            SNITCH_WARNING_DISABLE_CONSTANT_COMPARISON                                             \
            if constexpr (SNITCH_IS_DECOMPOSABLE(__VA_ARGS__)) {                                   \
                {                                                                                  \
                    constexpr SNITCH_EXPR(CHECK "[compile-time]", EXPECTED, __VA_ARGS__);          \
                    SNITCH_REPORT_EXPRESSION(MAYBE_ABORT);                                         \
                }                                                                                  \
                {                                                                                  \
                    SNITCH_EXPR(CHECK "[run-time]", EXPECTED, __VA_ARGS__);                        \
                    SNITCH_REPORT_EXPRESSION(MAYBE_ABORT);                                         \
                }                                                                                  \
            } else {                                                                               \
                {                                                                                  \
                    constexpr auto SNITCH_CURRENT_EXPRESSION = snitch::impl::expression{           \
                        CHECK "[compile-time]",                                                    \
                        #__VA_ARGS__,                                                              \
                        {},                                                                        \
                        static_cast<bool>(__VA_ARGS__) == EXPECTED};                               \
                    SNITCH_REPORT_EXPRESSION(MAYBE_ABORT);                                         \
                }                                                                                  \
                {                                                                                  \
                    const auto SNITCH_CURRENT_EXPRESSION = snitch::impl::expression{               \
                        CHECK "[run-time]",                                                        \
                        #__VA_ARGS__,                                                              \
                        {},                                                                        \
                        static_cast<bool>(__VA_ARGS__) == EXPECTED};                               \
                    SNITCH_REPORT_EXPRESSION(MAYBE_ABORT);                                         \
                }                                                                                  \
            }                                                                                      \
            SNITCH_WARNING_POP                                                                     \
        } while (0)

// clang-format off
#    define SNITCH_CONSTEXPR_REQUIRE(...)       SNITCH_CONSTEXPR_REQUIRE_IMPL("CONSTEXPR_REQUIRE",       true,  SNITCH_TESTING_ABORT,  __VA_ARGS__)
#    define SNITCH_CONSTEXPR_CHECK(...)         SNITCH_CONSTEXPR_REQUIRE_IMPL("CONSTEXPR_CHECK",         true,  (void)0,               __VA_ARGS__)
#    define SNITCH_CONSTEXPR_REQUIRE_FALSE(...) SNITCH_CONSTEXPR_REQUIRE_IMPL("CONSTEXPR_REQUIRE_FALSE", false, SNITCH_TESTING_ABORT,  __VA_ARGS__)
#    define SNITCH_CONSTEXPR_CHECK_FALSE(...)   SNITCH_CONSTEXPR_REQUIRE_IMPL("CONSTEXPR_CHECK_FALSE",   false, (void)0,               __VA_ARGS__)
// clang-format on

#    define SNITCH_CONSTEXPR_REQUIRE_THAT_IMPL(CHECK, MAYBE_ABORT, EXPR, ...)                      \
        do {                                                                                       \
            auto SNITCH_CURRENT_CHECK = SNITCH_NEW_CHECK;                                          \
            {                                                                                      \
                constexpr auto SNITCH_TEMP_RESULT        = snitch::impl::match(EXPR, __VA_ARGS__); \
                constexpr auto SNITCH_CURRENT_EXPRESSION = snitch::impl::expression{               \
                    CHECK "[compile-time]", #EXPR ", " #__VA_ARGS__,                               \
                    snitch::resize_or_truncate<snitch::max_expr_length>(                           \
                        SNITCH_TEMP_RESULT.second),                                                \
                    SNITCH_TEMP_RESULT.first};                                                     \
                SNITCH_REPORT_EXPRESSION(MAYBE_ABORT);                                             \
            }                                                                                      \
            {                                                                                      \
                const auto SNITCH_TEMP_RESULT        = snitch::impl::match(EXPR, __VA_ARGS__);     \
                const auto SNITCH_CURRENT_EXPRESSION = snitch::impl::expression{                   \
                    CHECK "[run-time]", #EXPR ", " #__VA_ARGS__,                                   \
                    snitch::resize_or_truncate<snitch::max_expr_length>(                           \
                        SNITCH_TEMP_RESULT.second),                                                \
                    SNITCH_TEMP_RESULT.first};                                                     \
                SNITCH_REPORT_EXPRESSION(MAYBE_ABORT);                                             \
            }                                                                                      \
        } while (0)

// clang-format off
#    define SNITCH_CONSTEXPR_REQUIRE_THAT(EXPR, ...) SNITCH_CONSTEXPR_REQUIRE_THAT_IMPL("CONSTEXPR_REQUIRE_THAT", SNITCH_TESTING_ABORT,  EXPR, __VA_ARGS__)
#    define SNITCH_CONSTEXPR_CHECK_THAT(EXPR, ...)   SNITCH_CONSTEXPR_REQUIRE_THAT_IMPL("CONSTEXPR_CHECK_THAT",   (void)0,               EXPR, __VA_ARGS__)
// clang-format on

#else // SNITCH_ENABLE

// clang-format off
#    define SNITCH_CONSTEXPR_REQUIRE(...)            SNITCH_DISCARD_ARGS(__VA_ARGS__)
#    define SNITCH_CONSTEXPR_CHECK(...)              SNITCH_DISCARD_ARGS(__VA_ARGS__)
#    define SNITCH_CONSTEXPR_REQUIRE_FALSE(...)      SNITCH_DISCARD_ARGS(__VA_ARGS__)
#    define SNITCH_CONSTEXPR_CHECK_FALSE(...)        SNITCH_DISCARD_ARGS(__VA_ARGS__)
#    define SNITCH_CONSTEXPR_REQUIRE_THAT(EXPR, ...) SNITCH_DISCARD_ARGS(EXPR, __VA_ARGS__)
#    define SNITCH_CONSTEXPR_CHECK_THAT(EXPR, ...)   SNITCH_DISCARD_ARGS(EXPR, __VA_ARGS__)
// clang-format on
#endif // SNITCH_ENABLE

// clang-format off
#if SNITCH_WITH_SHORTHAND_MACROS
#    define CONSTEXPR_REQUIRE(...)           SNITCH_CONSTEXPR_REQUIRE(__VA_ARGS__)
#    define CONSTEXPR_CHECK(...)             SNITCH_CONSTEXPR_CHECK(__VA_ARGS__)
#    define CONSTEXPR_REQUIRE_FALSE(...)     SNITCH_CONSTEXPR_REQUIRE_FALSE(__VA_ARGS__)
#    define CONSTEXPR_CHECK_FALSE(...)       SNITCH_CONSTEXPR_CHECK_FALSE(__VA_ARGS__)
#    define CONSTEXPR_REQUIRE_THAT(EXP, ...) SNITCH_CONSTEXPR_REQUIRE_THAT(EXP, __VA_ARGS__)
#    define CONSTEXPR_CHECK_THAT(EXP, ...)   SNITCH_CONSTEXPR_CHECK_THAT(EXP, __VA_ARGS__)
#endif
// clang-format on

#endif

#ifndef SNITCH_MACROS_EXCEPTIONS_HPP
#define SNITCH_MACROS_EXCEPTIONS_HPP

#if SNITCH_WITH_EXCEPTIONS

#    include <exception>

#    if SNITCH_ENABLE
#        define SNITCH_REQUIRE_THROWS_AS_IMPL(MAYBE_ABORT, EXPRESSION, ...)                        \
            do {                                                                                   \
                auto SNITCH_CURRENT_CHECK       = SNITCH_NEW_CHECK;                                \
                bool SNITCH_NO_EXCEPTION_THROWN = false;                                           \
                try {                                                                              \
                    static_cast<void>(EXPRESSION);                                                 \
                    SNITCH_NO_EXCEPTION_THROWN = true;                                             \
                } catch (const __VA_ARGS__&) {                                                     \
                    snitch::registry::report_assertion(                                            \
                        true, #__VA_ARGS__ " was thrown as expected");                             \
                    snitch::notify_exception_handled();                                            \
                } catch (...) {                                                                    \
                    try {                                                                          \
                        throw;                                                                     \
                    } catch (const std::exception& e) {                                            \
                        snitch::registry::report_assertion(                                        \
                            false,                                                                 \
                            #__VA_ARGS__ " expected but other std::exception thrown; message: ",   \
                            e.what());                                                             \
                    } catch (...) {                                                                \
                        snitch::registry::report_assertion(                                        \
                            false, #__VA_ARGS__ " expected but other unknown exception thrown");   \
                    }                                                                              \
                    snitch::notify_exception_handled();                                            \
                    MAYBE_ABORT;                                                                   \
                }                                                                                  \
                if (SNITCH_NO_EXCEPTION_THROWN) {                                                  \
                    snitch::registry::report_assertion(                                            \
                        false, #__VA_ARGS__ " expected but no exception thrown");                  \
                    MAYBE_ABORT;                                                                   \
                }                                                                                  \
            } while (0)

#        define SNITCH_REQUIRE_THROWS_AS(EXPRESSION, ...)                                          \
            SNITCH_REQUIRE_THROWS_AS_IMPL(SNITCH_TESTING_ABORT, EXPRESSION, __VA_ARGS__)
#        define SNITCH_CHECK_THROWS_AS(EXPRESSION, ...)                                            \
            SNITCH_REQUIRE_THROWS_AS_IMPL((void)0, EXPRESSION, __VA_ARGS__)

#        define SNITCH_REQUIRE_THROWS_MATCHES_IMPL(MAYBE_ABORT, EXPRESSION, EXCEPTION, ...)        \
            do {                                                                                   \
                auto SNITCH_CURRENT_CHECK       = SNITCH_NEW_CHECK;                                \
                bool SNITCH_NO_EXCEPTION_THROWN = false;                                           \
                try {                                                                              \
                    static_cast<void>(EXPRESSION);                                                 \
                    SNITCH_NO_EXCEPTION_THROWN = true;                                             \
                } catch (const EXCEPTION& e) {                                                     \
                    auto&& SNITCH_TEMP_MATCHER = __VA_ARGS__;                                      \
                    if (!SNITCH_TEMP_MATCHER.match(e)) {                                           \
                        snitch::registry::report_assertion(                                        \
                            false,                                                                 \
                            "could not match caught " #EXCEPTION " with expected content: ",       \
                            SNITCH_TEMP_MATCHER.describe_match(                                    \
                                e, snitch::matchers::match_status::failed));                       \
                        snitch::notify_exception_handled();                                        \
                        MAYBE_ABORT;                                                               \
                    } else {                                                                       \
                        snitch::registry::report_assertion(                                        \
                            true, "caught " #EXCEPTION " matched expected content: ",              \
                            SNITCH_TEMP_MATCHER.describe_match(                                    \
                                e, snitch::matchers::match_status::matched));                      \
                        snitch::notify_exception_handled();                                        \
                    }                                                                              \
                } catch (...) {                                                                    \
                    try {                                                                          \
                        throw;                                                                     \
                    } catch (const std::exception& e) {                                            \
                        snitch::registry::report_assertion(                                        \
                            false,                                                                 \
                            #EXCEPTION " expected but other std::exception thrown; message: ",     \
                            e.what());                                                             \
                    } catch (...) {                                                                \
                        snitch::registry::report_assertion(                                        \
                            false, #EXCEPTION " expected but other unknown exception thrown");     \
                    }                                                                              \
                    snitch::notify_exception_handled();                                            \
                    MAYBE_ABORT;                                                                   \
                }                                                                                  \
                if (SNITCH_NO_EXCEPTION_THROWN) {                                                  \
                    snitch::registry::report_assertion(                                            \
                        false, #EXCEPTION " expected but no exception thrown");                    \
                    MAYBE_ABORT;                                                                   \
                }                                                                                  \
            } while (0)

#        define SNITCH_REQUIRE_THROWS_MATCHES(EXPRESSION, EXCEPTION, ...)                          \
            SNITCH_REQUIRE_THROWS_MATCHES_IMPL(                                                    \
                SNITCH_TESTING_ABORT, EXPRESSION, EXCEPTION, __VA_ARGS__)
#        define SNITCH_CHECK_THROWS_MATCHES(EXPRESSION, EXCEPTION, ...)                            \
            SNITCH_REQUIRE_THROWS_MATCHES_IMPL((void)0, EXPRESSION, EXCEPTION, __VA_ARGS__)

#        define SNITCH_REQUIRE_NOTHROW_IMPL(MAYBE_ABORT, ...)                                      \
            do {                                                                                   \
                auto SNITCH_CURRENT_CHECK = SNITCH_NEW_CHECK;                                      \
                try {                                                                              \
                    static_cast<void>(__VA_ARGS__);                                                \
                    snitch::registry::report_assertion(true, #__VA_ARGS__ " did not throw");       \
                } catch (...) {                                                                    \
                    try {                                                                          \
                        throw;                                                                     \
                    } catch (const std::exception& e) {                                            \
                        snitch::registry::report_assertion(                                        \
                            false,                                                                 \
                            "expected " #__VA_ARGS__                                               \
                            " not to throw but it threw a std::exception; message: ",              \
                            e.what());                                                             \
                    } catch (...) {                                                                \
                        snitch::registry::report_assertion(                                        \
                            false, "expected " #__VA_ARGS__                                        \
                                   " not to throw but it threw an unknown exception");             \
                    }                                                                              \
                    snitch::notify_exception_handled();                                            \
                    MAYBE_ABORT;                                                                   \
                }                                                                                  \
            } while (0)

#        define SNITCH_REQUIRE_NOTHROW(...)                                                        \
            SNITCH_REQUIRE_NOTHROW_IMPL(SNITCH_TESTING_ABORT, __VA_ARGS__)
#        define SNITCH_CHECK_NOTHROW(...) SNITCH_REQUIRE_NOTHROW_IMPL((void)0, __VA_ARGS__)

#    else // SNITCH_ENABLE

// clang-format off
#    define SNITCH_REQUIRE_THROWS_AS(EXPRESSION, ...)                 SNITCH_DISCARD_ARGS(EXPRESSION, sizeof(__VA_ARGS__))
#    define SNITCH_CHECK_THROWS_AS(EXPRESSION, ...)                   SNITCH_DISCARD_ARGS(EXPRESSION, sizeof(__VA_ARGS__))
#    define SNITCH_REQUIRE_THROWS_MATCHES(EXPRESSION, EXCEPTION, ...) SNITCH_DISCARD_ARGS(EXPRESSION, sizeof(EXCEPTION), __VA_ARGS__)
#    define SNITCH_CHECK_THROWS_MATCHES(EXPRESSION, EXCEPTION, ...)   SNITCH_DISCARD_ARGS(EXPRESSION, sizeof(EXCEPTION), __VA_ARGS__)
#    define SNITCH_REQUIRE_NOTHROW(...)                               SNITCH_DISCARD_ARGS(__VA_ARGS__)
#    define SNITCH_CHECK_NOTHROW(...)                                 SNITCH_DISCARD_ARGS(__VA_ARGS__)
// clang-format on

#    endif // SNITCH_ENABLE

// clang-format off
#if SNITCH_WITH_SHORTHAND_MACROS
#    define REQUIRE_THROWS_AS(EXPRESSION, ...)                 SNITCH_REQUIRE_THROWS_AS(EXPRESSION, __VA_ARGS__)
#    define CHECK_THROWS_AS(EXPRESSION, ...)                   SNITCH_CHECK_THROWS_AS(EXPRESSION, __VA_ARGS__)
#    define REQUIRE_THROWS_MATCHES(EXPRESSION, EXCEPTION, ...) SNITCH_REQUIRE_THROWS_MATCHES(EXPRESSION, EXCEPTION, __VA_ARGS__)
#    define CHECK_THROWS_MATCHES(EXPRESSION, EXCEPTION, ...)   SNITCH_CHECK_THROWS_MATCHES(EXPRESSION, EXCEPTION, __VA_ARGS__)
#    define REQUIRE_NOTHROW(...)                               SNITCH_REQUIRE_NOTHROW(__VA_ARGS__)
#    define CHECK_NOTHROW(...)                                 SNITCH_CHECK_NOTHROW(__VA_ARGS__)
#endif
// clang-format on

#endif

#endif

#ifndef SNITCH_SECTION_HPP
#define SNITCH_SECTION_HPP


namespace snitch::impl {
struct section_entry_checker {
    section_id      id       = {};
    source_location location = {};
    test_state&     state;
    bool            entered = false;

    SNITCH_EXPORT ~section_entry_checker();

    // Requires: number of sections < max_nested_sections.
    SNITCH_EXPORT explicit operator bool();
};
} // namespace snitch::impl

#endif

#ifndef SNITCH_MACROS_MISC_HPP
#define SNITCH_MACROS_MISC_HPP


#if SNITCH_ENABLE
#    define SNITCH_SECTION(...)                                                                    \
        if (snitch::impl::section_entry_checker SNITCH_MACRO_CONCAT(section_id_, __COUNTER__){     \
                {__VA_ARGS__}, SNITCH_CURRENT_LOCATION, snitch::impl::get_current_test()})

#    define SNITCH_CAPTURE(...)                                                                    \
        auto SNITCH_MACRO_CONCAT(capture_id_, __COUNTER__) = snitch::impl::add_captures(           \
            snitch::impl::get_current_test(), #__VA_ARGS__, __VA_ARGS__)

#    define SNITCH_INFO(...)                                                                       \
        auto SNITCH_MACRO_CONCAT(capture_id_, __COUNTER__) =                                       \
            snitch::impl::add_info(snitch::impl::get_current_test(), __VA_ARGS__)
#else // SNITCH_ENABLE
// clang-format off
#    define SNITCH_SECTION(NAME, ...) if constexpr (false)
#    define SNITCH_CAPTURE(...)       SNITCH_DISCARD_ARGS(__VA_ARGS__)
#    define SNITCH_INFO(...)          SNITCH_DISCARD_ARGS(__VA_ARGS__)
// clang-format on
#endif // SNITCH_ENABLE

// clang-format off
#if SNITCH_WITH_SHORTHAND_MACROS
#    define SECTION(NAME, ...) SNITCH_SECTION(NAME, __VA_ARGS__)
#    define CAPTURE(...)       SNITCH_CAPTURE(__VA_ARGS__)
#    define INFO(...)          SNITCH_INFO(__VA_ARGS__)
#endif
// clang-format on

#endif

#ifndef SNITCH_MACROS_REPORTER_HPP
#define SNITCH_MACROS_REPORTER_HPP


#if SNITCH_ENABLE
#    define SNITCH_REGISTER_REPORTER_CALLBACKS(NAME, ...)                                          \
        static const std::string_view SNITCH_MACRO_CONCAT(reporter_id_, __COUNTER__)               \
            [[maybe_unused]] = snitch::tests.add_reporter(NAME, __VA_ARGS__)

#    define SNITCH_REGISTER_REPORTER(NAME, TYPE)                                                   \
        static const std::string_view SNITCH_MACRO_CONCAT(reporter_id_, __COUNTER__)               \
            [[maybe_unused]] = snitch::tests.add_reporter<TYPE>(NAME)
#else // SNITCH_ENABLE
#    define SNITCH_REGISTER_REPORTER_CALLBACKS(NAME, ...) /* nothing */
#    define SNITCH_REGISTER_REPORTER(NAME, TYPE) static_assert(NAME)
#endif // SNITCH_ENABLE

// clang-format off
#if SNITCH_WITH_SHORTHAND_MACROS
#    define REGISTER_REPORTER_CALLBACKS(...) SNITCH_REGISTER_REPORTER_CALLBACKS(__VA_ARGS__)
#    define REGISTER_REPORTER(...)           SNITCH_REGISTER_REPORTER(__VA_ARGS__)
#endif
// clang-format on

#endif

#ifndef SNITCH_MACROS_TEST_CASE_HPP
#define SNITCH_MACROS_TEST_CASE_HPP


#if SNITCH_ENABLE
#    define SNITCH_TEST_CASE_IMPL(ID, ...)                                                         \
        static void        ID();                                                                   \
        static const char* SNITCH_MACRO_CONCAT(test_id_, __COUNTER__) [[maybe_unused]] =           \
            snitch::tests.add({__VA_ARGS__}, SNITCH_CURRENT_LOCATION, &ID);                        \
        void ID()

#    define SNITCH_TEST_CASE(...)                                                                  \
        SNITCH_TEST_CASE_IMPL(SNITCH_MACRO_CONCAT(test_fun_, __COUNTER__), __VA_ARGS__)

#    define SNITCH_TEMPLATE_LIST_TEST_CASE_IMPL(ID, NAME, TAGS, TYPES)                             \
        template<typename TestType>                                                                \
        static void        ID();                                                                   \
        static const char* SNITCH_MACRO_CONCAT(test_id_, __COUNTER__) [[maybe_unused]] =           \
            snitch::tests.add_with_type_list<TYPES>(                                               \
                {NAME, TAGS}, SNITCH_CURRENT_LOCATION,                                             \
                []<typename TestType>() { ID<TestType>(); });                                      \
        template<typename TestType>                                                                \
        void ID()

#    define SNITCH_TEMPLATE_LIST_TEST_CASE(NAME, TAGS, TYPES)                                      \
        SNITCH_TEMPLATE_LIST_TEST_CASE_IMPL(                                                       \
            SNITCH_MACRO_CONCAT(test_fun_, __COUNTER__), NAME, TAGS, TYPES)

#    define SNITCH_TEMPLATE_TEST_CASE_IMPL(ID, NAME, TAGS, ...)                                    \
        template<typename TestType>                                                                \
        static void        ID();                                                                   \
        static const char* SNITCH_MACRO_CONCAT(test_id_, __COUNTER__) [[maybe_unused]] =           \
            snitch::tests.add_with_types<__VA_ARGS__>(                                             \
                {NAME, TAGS}, SNITCH_CURRENT_LOCATION,                                             \
                []<typename TestType>() { ID<TestType>(); });                                      \
        template<typename TestType>                                                                \
        void ID()

#    define SNITCH_TEMPLATE_TEST_CASE(NAME, TAGS, ...)                                             \
        SNITCH_TEMPLATE_TEST_CASE_IMPL(                                                            \
            SNITCH_MACRO_CONCAT(test_fun_, __COUNTER__), NAME, TAGS, __VA_ARGS__)

#    define SNITCH_TEST_CASE_METHOD_IMPL(ID, FIXTURE, ...)                                         \
        namespace {                                                                                \
        struct ID : FIXTURE {                                                                      \
            void test_fun();                                                                       \
        };                                                                                         \
        }                                                                                          \
        static const char* SNITCH_MACRO_CONCAT(test_id_, __COUNTER__) [[maybe_unused]] =           \
            snitch::tests.add_fixture(                                                             \
                {#FIXTURE, __VA_ARGS__}, SNITCH_CURRENT_LOCATION, []() { ID{}.test_fun(); });      \
        void ID::test_fun()

#    define SNITCH_TEST_CASE_METHOD(FIXTURE, ...)                                                  \
        SNITCH_TEST_CASE_METHOD_IMPL(                                                              \
            SNITCH_MACRO_CONCAT(test_fixture_, __COUNTER__), FIXTURE, __VA_ARGS__)

#    define SNITCH_TEMPLATE_LIST_TEST_CASE_METHOD_IMPL(ID, FIXTURE, NAME, TAGS, TYPES)             \
        namespace {                                                                                \
        template<typename TestType>                                                                \
        struct ID : FIXTURE<TestType> {                                                            \
            void test_fun();                                                                       \
        };                                                                                         \
        }                                                                                          \
        static const char* SNITCH_MACRO_CONCAT(test_id_, __COUNTER__) [[maybe_unused]] =           \
            snitch::tests.add_fixture_with_type_list<TYPES>(                                       \
                {#FIXTURE, NAME, TAGS}, SNITCH_CURRENT_LOCATION,                                   \
                []<typename TestType>() { ID<TestType>{}.test_fun(); });                           \
        template<typename TestType>                                                                \
        void ID<TestType>::test_fun()

#    define SNITCH_TEMPLATE_LIST_TEST_CASE_METHOD(FIXTURE, NAME, TAGS, TYPES)                      \
        SNITCH_TEMPLATE_LIST_TEST_CASE_METHOD_IMPL(                                                \
            SNITCH_MACRO_CONCAT(test_fixture_, __COUNTER__), FIXTURE, NAME, TAGS, TYPES)

#    define SNITCH_TEMPLATE_TEST_CASE_METHOD_IMPL(ID, FIXTURE, NAME, TAGS, ...)                    \
        namespace {                                                                                \
        template<typename TestType>                                                                \
        struct ID : FIXTURE<TestType> {                                                            \
            void test_fun();                                                                       \
        };                                                                                         \
        }                                                                                          \
        static const char* SNITCH_MACRO_CONCAT(test_id_, __COUNTER__) [[maybe_unused]] =           \
            snitch::tests.add_fixture_with_types<__VA_ARGS__>(                                     \
                {#FIXTURE, NAME, TAGS}, SNITCH_CURRENT_LOCATION,                                   \
                []<typename TestType>() { ID<TestType>{}.test_fun(); });                           \
        template<typename TestType>                                                                \
        void ID<TestType>::test_fun()

#    define SNITCH_TEMPLATE_TEST_CASE_METHOD(FIXTURE, NAME, TAGS, ...)                             \
        SNITCH_TEMPLATE_TEST_CASE_METHOD_IMPL(                                                     \
            SNITCH_MACRO_CONCAT(test_fixture_, __COUNTER__), FIXTURE, NAME, TAGS, __VA_ARGS__)

#else // SNITCH_ENABLE

#    define SNITCH_TEST_CASE(...)                                                                  \
        [[maybe_unused]] static void SNITCH_MACRO_CONCAT(test_id_, __COUNTER__)()

#    define SNITCH_TEMPLATE_LIST_TEST_CASE(NAME, TAGS, TYPES) SNITCH_VOID_STATEMENT

#    define SNITCH_TEMPLATE_TEST_CASE(NAME, TAGS, ...)                                             \
        template<typename TestType>                                                                \
        [[maybe_unused]] static void SNITCH_MACRO_CONCAT(test_id_, __COUNTER__)()

#    define SNITCH_TEST_CASE_METHOD_IMPL(ID, FIXTURE, ...)                                         \
        namespace {                                                                                \
        struct ID : FIXTURE {                                                                      \
            void test_fun();                                                                       \
        };                                                                                         \
        }                                                                                          \
        [[maybe_unused]] void ID::test_fun()

#    define SNITCH_TEST_CASE_METHOD(FIXTURE, ...)                                                  \
        SNITCH_TEST_CASE_METHOD_IMPL(SNITCH_MACRO_CONCAT(test_id_, __COUNTER__), FIXTURE)

#    define SNITCH_TEMPLATE_LIST_TEST_CASE_METHOD(FIXTURE, NAME, TAGS, TYPES) SNITCH_VOID_STATEMENT

#    define SNITCH_TEMPLATE_TEST_CASE_METHOD(FIXTURE, NAME, TAGS, ...) SNITCH_VOID_STATEMENT
#endif // SNITCH_ENABLE

// clang-format off
#if SNITCH_WITH_SHORTHAND_MACROS
#    define TEST_CASE(NAME, ...)                       SNITCH_TEST_CASE(NAME, __VA_ARGS__)
#    define TEMPLATE_LIST_TEST_CASE(NAME, TAGS, TYPES) SNITCH_TEMPLATE_LIST_TEST_CASE(NAME, TAGS, TYPES)
#    define TEMPLATE_TEST_CASE(NAME, TAGS, ...)        SNITCH_TEMPLATE_TEST_CASE(NAME, TAGS, __VA_ARGS__)

#    define TEST_CASE_METHOD(FIXTURE, NAME, ...)                       SNITCH_TEST_CASE_METHOD(FIXTURE, NAME, __VA_ARGS__)
#    define TEMPLATE_LIST_TEST_CASE_METHOD(FIXTURE, NAME, TAGS, TYPES) SNITCH_TEMPLATE_LIST_TEST_CASE_METHOD(FIXTURE, NAME, TAGS, TYPES)
#    define TEMPLATE_TEST_CASE_METHOD(FIXTURE, NAME, TAGS, ...)        SNITCH_TEMPLATE_TEST_CASE_METHOD(FIXTURE, NAME, TAGS, __VA_ARGS__)
#endif
// clang-format on

#endif

#ifndef SNITCH_MAIN_HPP
#define SNITCH_MAIN_HPP


namespace snitch {
SNITCH_EXPORT int main(int argc, char* argv[]);
} // namespace snitch

#endif

#ifndef SNITCH_REPORTER_CATCH2_XML_HPP
#define SNITCH_REPORTER_CATCH2_XML_HPP


#if SNITCH_WITH_CATCH2_XML_REPORTER || SNITCH_WITH_ALL_REPORTERS


#    include <cstddef>
#    include <string_view>

namespace snitch::reporter::catch2_xml {
struct reporter {
    std::size_t indent_level = 0;

    SNITCH_EXPORT explicit reporter(registry& r) noexcept;

    SNITCH_EXPORT bool configure(registry&, std::string_view, std::string_view) noexcept;

    SNITCH_EXPORT void report(const registry& r, const snitch::event::data& event) noexcept;
};
} // namespace snitch::reporter::catch2_xml

#endif
#endif

#ifndef SNITCH_REPORTER_TEAMCITY_HPP
#define SNITCH_REPORTER_TEAMCITY_HPP


#if SNITCH_WITH_TEAMCITY_REPORTER || SNITCH_WITH_ALL_REPORTERS


#    include <string_view>

namespace snitch::reporter::teamcity {
SNITCH_EXPORT void initialize(registry& r) noexcept;

SNITCH_EXPORT void report(const registry& r, const snitch::event::data& event) noexcept;
} // namespace snitch::reporter::teamcity

#endif
#endif

#if defined(SNITCH_IMPLEMENTATION)

namespace snitch::impl {
const basic_vtable empty_vtable = {};
} // namespace snitch::impl

#endif

#if defined(SNITCH_IMPLEMENTATION)


#include <algorithm> // for std::copy
#include <cstdint> // for std::uintptr_t
#if SNITCH_APPEND_TO_CHARS
#    include <charconv> // for std::to_chars
#    include <system_error> // for std::errc
#endif

namespace snitch::impl {
namespace {
using snitch::small_string_span;
using namespace std::literals;

#if SNITCH_APPEND_TO_CHARS
template<floating_point T>
bool append_to(small_string_span ss, T value) noexcept {
    constexpr auto fmt       = std::chars_format::scientific;
    constexpr auto precision = same_as<float, std::remove_cvref_t<T>> ? 8 : 16;
    auto [end, err] = std::to_chars(ss.end(), ss.begin() + ss.capacity(), value, fmt, precision);
    if (err != std::errc{}) {
        // Not enough space, try into a temporary string that *should* be big enough,
        // and copy whatever we can. 32 characters is enough for all integers and floating
        // point values encoded on 64 bit or less.
        small_string<32> fallback;
        auto [end2, err2] = std::to_chars(
            fallback.end(), fallback.begin() + fallback.capacity(), value, fmt, precision);
        if (err2 != std::errc{}) {
            return false;
        }
        fallback.grow(end2 - fallback.begin());
        return append(ss, fallback);
    }

    ss.grow(end - ss.end());
    return true;
}

template<large_int_t Base = 10, integral T>
bool append_to(small_string_span ss, T value) noexcept {
    auto [end, err] = std::to_chars(ss.end(), ss.begin() + ss.capacity(), value, Base);
    if (err != std::errc{}) {
        // Not enough space, try into a temporary string that *should* be big enough,
        // and copy whatever we can. 32 characters is enough for all integers and floating
        // point values encoded on 64 bit or less.
        small_string<32> fallback;
        auto [end2, err2] =
            std::to_chars(fallback.end(), fallback.begin() + fallback.capacity(), value, Base);
        if (err2 != std::errc{}) {
            return false;
        }
        fallback.grow(end2 - fallback.begin());
        return append(ss, fallback);
    }
    ss.grow(end - ss.end());
    return true;
}
#else
template<floating_point T>
bool append_to(small_string_span ss, T value) noexcept {
    return append_constexpr(ss, value);
}

template<large_int_t Base = 10, integral T>
bool append_to(small_string_span ss, T value) noexcept {
    return append_constexpr<Base>(ss, value);
}
#endif
} // namespace

bool append_fast(small_string_span ss, std::string_view str) noexcept {
    if (str.empty()) {
        return true;
    }

    const bool        could_fit  = str.size() <= ss.available();
    const std::size_t copy_count = std::min(str.size(), ss.available());

    const std::size_t offset = ss.size();
    ss.grow(copy_count);
    std::copy(str.begin(), str.begin() + copy_count, ss.begin() + offset);

    return could_fit;
}

bool append_fast(small_string_span ss, const void* ptr) noexcept {
    if (ptr == nullptr) {
        return append(ss, nullptr);
    }

    if (!append_fast(ss, "0x"sv)) {
        return false;
    }

    const auto int_ptr = reinterpret_cast<std::uintptr_t>(ptr);

    // Pad with zeros.
    constexpr std::size_t max_digits = 2 * sizeof(void*);
    std::size_t           padding    = max_digits - num_digits<16>(int_ptr);
    while (padding > 0) {
        constexpr std::string_view zeroes = "0000000000000000";
        const std::size_t          batch  = std::min(zeroes.size(), padding);
        if (!append_fast(ss, zeroes.substr(0, batch))) {
            return false;
        }

        padding -= batch;
    }
    return append_to<16>(ss, int_ptr);
}

bool append_fast(small_string_span ss, large_uint_t i) noexcept {
    return append_to(ss, i);
}

bool append_fast(small_string_span ss, large_int_t i) noexcept {
    return append_to(ss, i);
}

bool append_fast(small_string_span ss, float f) noexcept {
    return append_to(ss, f);
}

bool append_fast(small_string_span ss, double d) noexcept {
    return append_to(ss, d);
}
} // namespace snitch::impl

#endif

#if defined(SNITCH_IMPLEMENTATION)


namespace snitch::impl {
namespace {
void trim(std::string_view& str, std::string_view patterns) noexcept {
    std::size_t start = str.find_first_not_of(patterns);
    if (start == str.npos) {
        return;
    }

    str.remove_prefix(start);

    std::size_t end = str.find_last_not_of(patterns);
    if (end != str.npos) {
        str.remove_suffix(str.size() - end - 1);
    }
}
} // namespace

scoped_capture::~scoped_capture() {
#if SNITCH_WITH_EXCEPTIONS
    if (std::uncaught_exceptions() > 0 && !state.held_info.has_value()) {
        // We are unwinding the stack because an exception has been thrown;
        // keep a copy of the full capture state since we will want to preserve the information
        // when reporting the exception.
        state.held_info = state.info;
    }
#endif

    state.info.captures.resize(state.info.captures.size() - count);
}

std::string_view extract_next_name(std::string_view& names) noexcept {
    std::string_view result;

    auto pos = names.find_first_of(",()\"\"''");

    bool in_string = false;
    bool in_char   = false;
    int  parens    = 0;
    while (pos != names.npos) {
        switch (names[pos]) {
        case '"':
            if (!in_char) {
                in_string = !in_string;
            }
            break;
        case '\'':
            if (!in_string) {
                in_char = !in_char;
            }
            break;
        case '(':
            if (!in_string && !in_char) {
                ++parens;
            }
            break;
        case ')':
            if (!in_string && !in_char) {
                --parens;
            }
            break;
        case ',':
            if (!in_string && !in_char && parens == 0) {
                result = names.substr(0, pos);
                trim(result, " \t\n\r");
                names.remove_prefix(pos + 1);
                return result;
            }
            break;
        }

        pos = names.find_first_of(",()\"\"''", pos + 1);
    }

    std::swap(result, names);
    trim(result, " \t\n\r");
    return result;
}

small_string<max_capture_length>& add_capture(test_state& state) {
    if (state.info.captures.available() == 0) {
        state.reg.print(
            make_colored("error:", state.reg.with_color, color::fail),
            " max number of captures reached; "
            "please increase 'SNITCH_MAX_CAPTURES' (currently ",
            max_captures, ")\n.");
        assertion_failed("max number of captures reached");
    }

#if SNITCH_WITH_EXCEPTIONS
    if (std::uncaught_exceptions() == 0) {
        notify_exception_handled();
    }
#endif

    state.info.captures.grow(1);
    state.info.captures.back().clear();
    return state.info.captures.back();
}
} // namespace snitch::impl

#endif

#if defined(SNITCH_IMPLEMENTATION)


#include <algorithm> // for std::find

namespace snitch::impl { namespace {
using namespace std::literals;

constexpr std::size_t max_arg_names = 2;

namespace argument_type {
enum type { optional = 0b00, mandatory = 0b01, repeatable = 0b10 };
}

struct expected_argument {
    small_vector<std::string_view, max_arg_names> names;
    std::optional<std::string_view>               value_name;
    bool                                          ignored = false;
    std::string_view                              description;
    argument_type::type                           type = argument_type::optional;
};

using expected_arguments = small_vector<expected_argument, max_command_line_args>;

struct parser_settings {
    bool silent     = false;
    bool tolerant   = false;
    bool with_color = true;
};

std::string_view extract_executable(std::string_view path) noexcept {
    if (auto folder_end = path.find_last_of("\\/"); folder_end != path.npos) {
        path.remove_prefix(folder_end + 1);
    }
    if (auto extension_start = path.find_last_of('.'); extension_start != path.npos) {
        path.remove_suffix(path.size() - extension_start);
    }

    return path;
}

bool is_option(const expected_argument& e) noexcept {
    return !e.names.empty();
}

bool is_option(const cli::argument& a) noexcept {
    return !a.name.empty();
}

bool has_value(const expected_argument& e) noexcept {
    return e.value_name.has_value();
}

bool is_mandatory(const expected_argument& e) noexcept {
    return (e.type & argument_type::mandatory) != 0;
}

bool is_repeatable(const expected_argument& e) noexcept {
    return (e.type & argument_type::repeatable) != 0;
}

std::optional<cli::input> parse_arguments(
    int                       argc,
    const char* const         argv[],
    const expected_arguments& expected,
    const parser_settings&    settings = parser_settings{}) noexcept {

    std::optional<cli::input> ret(std::in_place);
    ret->executable = extract_executable(argv[0]);

    auto& args = ret->arguments;
    bool  bad  = false;

    // Check validity of inputs
    small_vector<bool, max_command_line_args> expected_found;
    for (const auto& e : expected) {
        expected_found.push_back(false);

        if (is_option(e)) {
            if (e.names.size() == 1) {
                if (!e.names[0].starts_with('-')) {
                    terminate_with("option name must start with '-' or '--'");
                }
            } else {
                if (!(e.names[0].starts_with('-') && e.names[1].starts_with("--"))) {
                    terminate_with("option names must be given with '-' first and '--' second");
                }
            }
        } else {
            if (!has_value(e)) {
                terminate_with("positional argument must have a value name");
            }
        }
    }

    // Parse
    for (int argi = 1; argi < argc; ++argi) {
        std::string_view arg(argv[argi]);

        if (arg.starts_with('-')) {
            // Options start with dashes.
            bool found = false;

            for (std::size_t arg_index = 0; arg_index < expected.size(); ++arg_index) {
                const auto& e = expected[arg_index];

                if (e.ignored || !is_option(e)) {
                    continue;
                }

                if (std::find(e.names.cbegin(), e.names.cend(), arg) == e.names.cend()) {
                    continue;
                }

                found = true;

                if (expected_found[arg_index] && !is_repeatable(e)) {
                    if (!settings.silent) {
                        cli::print(
                            make_colored("error:", settings.with_color, color::error),
                            " duplicate command line argument '", arg, "'\n");
                    }
                    bad = true;
                    break;
                }

                expected_found[arg_index] = true;

                if (has_value(e)) {
                    if (argi + 1 == argc) {
                        if (!settings.silent) {
                            cli::print(
                                make_colored("error:", settings.with_color, color::error),
                                " missing value '<", *e.value_name,
                                ">' for command line argument '", arg, "'\n");
                        }
                        bad = true;
                        break;
                    }

                    argi += 1;
                    args.push_back(cli::argument{
                        e.names.back(), e.value_name, {std::string_view(argv[argi])}});
                } else {
                    args.push_back(cli::argument{e.names.back()});
                }

                break;
            }

            if (!found) {
                if (!settings.silent) {
                    cli::print(
                        make_colored("warning:", settings.with_color, color::warning),
                        " unknown command line argument '", arg, "'\n");
                }
            }

            // Not a supported argument; figure out if this is a known argument (e.g. from Catch2)
            // and whether we need to ignore the next item if it is an option.
            for (std::size_t arg_index = 0; arg_index < expected.size(); ++arg_index) {
                const auto& e = expected[arg_index];

                if (!e.ignored) {
                    continue;
                }

                if (std::find(e.names.cbegin(), e.names.cend(), arg) == e.names.cend()) {
                    continue;
                }

                if (has_value(e)) {
                    argi += 1;
                }

                break;
            }
        } else {
            // If no dash, this is a positional argument.
            bool found = false;

            for (std::size_t arg_index = 0; arg_index < expected.size(); ++arg_index) {
                const auto& e = expected[arg_index];

                if (e.ignored || is_option(e)) {
                    continue;
                }

                if (expected_found[arg_index] && !is_repeatable(e)) {
                    continue;
                }

                found = true;

                args.push_back(cli::argument{""sv, e.value_name, {arg}});
                expected_found[arg_index] = true;
                break;
            }

            if (!found) {
                if (!settings.silent) {
                    cli::print(
                        make_colored("error:", settings.with_color, color::error),
                        " too many positional arguments\n");
                }
                bad = true;
            }
        }
    }

    for (std::size_t arg_index = 0; arg_index < expected.size(); ++arg_index) {
        const auto& e = expected[arg_index];
        if (!expected_found[arg_index] && is_mandatory(e) && !e.ignored) {
            if (!settings.silent) {
                if (!is_option(e)) {
                    cli::print(
                        make_colored("error:", settings.with_color, color::error),
                        " missing positional argument '<", *e.value_name, ">'\n");
                } else {
                    cli::print(
                        make_colored("error:", settings.with_color, color::error),
                        " missing option '<", e.names.back(), ">'\n");
                }
            }
            bad = true;
        }
    }

    if (bad && !settings.tolerant) {
        ret.reset();
    }

    return ret;
}

void print_help(
    std::string_view                program_name,
    std::string_view                program_description,
    const expected_arguments&       expected,
    const cli::print_help_settings& settings = cli::print_help_settings{}) noexcept {

    // Print program description
    cli::print(make_colored(program_description, settings.with_color, color::highlight2), "\n");

    // Print command line usage example
    cli::print(make_colored("Usage:", settings.with_color, color::pass), "\n");
    cli::print("  ", program_name);
    if (std::any_of(expected.cbegin(), expected.cend(), [](auto& e) { return is_option(e); })) {
        cli::print(" [options...]");
    }

    for (const auto& e : expected) {
        if (e.ignored || is_option(e)) {
            continue;
        }

        if (!is_mandatory(e) && !is_repeatable(e)) {
            cli::print(" [<", *e.value_name, ">]");
        } else if (is_mandatory(e) && !is_repeatable(e)) {
            cli::print(" <", *e.value_name, ">");
        } else if (!is_mandatory(e) && is_repeatable(e)) {
            cli::print(" [<", *e.value_name, ">...]");
        } else if (is_mandatory(e) && is_repeatable(e)) {
            cli::print(" <", *e.value_name, ">...");
        } else {
            terminate_with("unhandled argument type");
        }
    }

    cli::print("\n\n");

    // List arguments
    small_string<max_message_length> heading;
    for (const auto& e : expected) {
        if (e.ignored) {
            continue;
        }

        heading.clear();

        bool success = true;
        if (is_option(e)) {
            if (e.names[0].starts_with("--")) {
                success = success && append(heading, "    ");
            }

            success = success && append(heading, e.names[0]);

            if (e.names.size() == 2) {
                success = success && append(heading, ", ", e.names[1]);
            }

            if (has_value(e)) {
                success = success && append(heading, " <", *e.value_name, ">");
            }
        } else {
            success = success && append(heading, "<", *e.value_name, ">");
        }

        if (!success) {
            truncate_end(heading);
        }

        cli::print(
            "  ", make_colored(heading, settings.with_color, color::highlight1), " ", e.description,
            "\n");
    }
}

// clang-format off
constexpr expected_arguments expected_args = {
    {{"-l", "--list-tests"},    {},                         false, "List tests by name"},
    {{"--list-tags"},           {},                         false, "List tags by name"},
    {{"--list-tests-with-tag"}, {"tag"},                    false, "List tests by name with a given tag"},
    {{"--list-reporters"},      {},                         false, "List available test reporters (see --reporter)"},
    {{"-r", "--reporter"},      {"reporter[::key=value]*"}, false, "Choose which reporter to use to output the test results"},
    {{"-v", "--verbosity"},     {"quiet|normal|high|full"}, false, "Define how much gets sent to the standard output"},
    {{"-o", "--out"},           {"path"},                   false, "Saves output to a file given as 'path'"},
    {{"--color"},               {"always|default|never"},   false, "Enable/disable color in output"},
    {{"--colour-mode"},         {"ansi|default|none"},      false, "Enable/disable color in output (for compatibility with Catch2)"},
    {{"-h", "--help"},          {},                         false, "Print help"},
    {{},                        {"test regex"},             false, "A regex to select which test cases to run", argument_type::repeatable},
    // For compatibility with Catch2; unused.
    // This is used just to swallow the argument and its parameters.
    // The argument will still be reported as unknown.
    {{"-s", "--success"},           {},    true, ""},
    {{"-b", "--break"},             {},    true, ""},
    {{"-e", "--nothrow"},           {},    true, ""},
    {{"-i", "--invisibles"},        {},    true, ""},
    {{"-n", "--name"},              {},    true, ""},
    {{"-a", "--abort"},             {},    true, ""},
    {{"-x", "--abortx"},            {"x"}, true, ""},
    {{"-w", "--warn"},              {"x"}, true, ""},
    {{"-d", "--durations"},         {"x"}, true, ""},
    {{"-D", "--min-duration"},      {"x"}, true, ""},
    {{"-f", "--input-file"},        {"x"}, true, ""},
    {{"-#", "--filenames-as-tags"}, {"x"}, true, ""},
    {{"-c", "--section"},           {"x"}, true, ""},
    {{"--list-listeners"},          {},    true, ""},
    {{"--order"},                   {"x"}, true, ""},
    {{"--rng-seed"},                {"x"}, true, ""},
    {{"--libidentify"},             {},    true, ""},
    {{"--wait-for-keypress"},       {"x"}, true, ""},
    {{"--shard-count"},             {"x"}, true, ""},
    {{"--shard-index"},             {"x"}, true, ""},
    {{"--allow-running-no-tests"},  {},    true, ""}};
// clang-format on

bool parse_color_options(int argc, const char* const argv[]) noexcept {
    bool with_color = SNITCH_DEFAULT_WITH_COLOR == 1;

    constexpr expected_arguments output_args = [&]() {
        using namespace std::literals;
        constexpr std::array copy_args = {"--color"sv, "--colour-mode"sv};
        expected_arguments   args      = expected_args;
        for (auto& e : args) {
            e.ignored =
                std::find_if(e.names.cbegin(), e.names.cend(), [&](const auto n) {
                    return std::find(copy_args.cbegin(), copy_args.cend(), n) != copy_args.cend();
                }) == e.names.cend();
        }

        return args;
    }();

    const std::optional<cli::input> ret_args =
        parse_arguments(argc, argv, output_args, {.silent = true, .tolerant = true});

    if (ret_args.has_value()) {
        if (const auto& o = cli::get_option(ret_args.value(), "--color")) {
            if (o->value == "always") {
                with_color = true;
            } else if (o->value == "never") {
                with_color = false;
            }
        }
        if (const auto& o = cli::get_option(ret_args.value(), "--colour-mode")) {
            if (o->value == "ansi") {
                with_color = true;
            } else if (o->value == "none") {
                with_color = false;
            }
        }
    }

    return with_color;
}

constexpr const char* program_description =
    "Test runner (snitch v" SNITCH_FULL_VERSION " | compatible with Catch2 v3.4.0)";
}} // namespace snitch::impl

namespace snitch::cli {
function_ref<void(std::string_view) noexcept> console_print = &snitch::impl::stdout_print;

void print_help(std::string_view program_name, const print_help_settings& settings) noexcept {
    print_help(program_name, impl::program_description, impl::expected_args, settings);
}

std::optional<cli::input> parse_arguments(int argc, const char* const argv[]) noexcept {
    // First, parse just looking for color options so we can display console messages correctly.
    const bool with_color = impl::parse_color_options(argc, argv);

    // Now parse everything for real.
    std::optional<cli::input> ret_args =
        impl::parse_arguments(argc, argv, impl::expected_args, {.with_color = with_color});

    if (!ret_args) {
        print("\n");
        print_help(argv[0], {.with_color = with_color});
    }

    return ret_args;
}

std::optional<cli::argument> get_option(const cli::input& args, std::string_view name) noexcept {
    std::optional<cli::argument> ret;

    auto iter = std::find_if(args.arguments.cbegin(), args.arguments.cend(), [&](const auto& arg) {
        return arg.name == name;
    });

    if (iter != args.arguments.cend()) {
        ret = *iter;
    }

    return ret;
}

std::optional<cli::argument>
get_positional_argument(const cli::input& args, std::string_view name) noexcept {
    std::optional<cli::argument> ret;

    auto iter = std::find_if(args.arguments.cbegin(), args.arguments.cend(), [&](const auto& arg) {
        return !impl::is_option(arg) && arg.value_name == name;
    });

    if (iter != args.arguments.cend()) {
        ret = *iter;
    }

    return ret;
}

void for_each_positional_argument(
    const cli::input&                                    args,
    std::string_view                                     name,
    const function_ref<void(std::string_view) noexcept>& callback) noexcept {

    auto iter = args.arguments.cbegin();
    while (iter != args.arguments.cend()) {
        iter = std::find_if(iter, args.arguments.cend(), [&](const auto& arg) {
            return !impl::is_option(arg) && arg.value_name == name;
        });

        if (iter != args.arguments.cend()) {
            callback(*iter->value);
            ++iter;
        }
    }
}
} // namespace snitch::cli

#endif

#if defined(SNITCH_IMPLEMENTATION)

#if SNITCH_WITH_STDOUT
#    include <cstdio> // for std::fwrite and stdout
#else
#    include <exception> // for std::terminate
#endif

namespace snitch::impl {
#if SNITCH_WITH_STDOUT
void stdout_print(std::string_view message) noexcept {
    std::fwrite(message.data(), sizeof(char), message.length(), stdout);
}
#else
// No default console; it is expected that the user will use their own
// implementation wherever a console is needed.
void stdout_print(std::string_view) noexcept {
    std::terminate();
}
#endif
} // namespace snitch::impl

#endif

#if defined(SNITCH_IMPLEMENTATION)


#include <exception> // for std::terminate

namespace snitch {
[[noreturn]] void terminate_with(std::string_view msg) noexcept {
    cli::console_print("terminate called with message: ");
    cli::console_print(msg);
    cli::console_print("\n");

    std::terminate();
}

[[noreturn]] void assertion_failed(std::string_view msg) {
    assertion_failed_handler(msg);

    // The assertion handler should either spin, throw, or terminate, but never return.
    // We cannot enforce [[noreturn]] through the function_ref wrapper. So just in case
    // it accidentally returns, we terminate.
    std::terminate();
}

function_ref<void(std::string_view)> assertion_failed_handler = &terminate_with;
} // namespace snitch

#endif

#if defined(SNITCH_IMPLEMENTATION)


#if SNITCH_WITH_STD_FILE_IO
#    include <cstdio> // for std::fopen, std::fwrite, std::fclose
#else
#    include <exception> // for std::terminate
#endif

namespace snitch::impl {
#if SNITCH_WITH_STD_FILE_IO
void stdio_file_open(file_object_storage& storage, std::string_view path) {
    // Unfortunately, fopen() needs a null-terminated string, so need a copy...
    small_string<max_path_length + 1> null_terminated_path;
    if (!append(null_terminated_path, path)) {
        assertion_failed("output file path is too long");
    }

    std::FILE* handle = nullptr;
#    if defined(_MSC_VER)
    // MSVC thinks std::fopen is unsafe.
    fopen_s(&handle, null_terminated_path.data(), "w");
#    else
    handle = std::fopen(null_terminated_path.data(), "w");
#    endif

    if (handle == nullptr) {
        assertion_failed("output file could not be opened for writing");
    }

    storage.emplace<std::FILE*>(handle);
}

void stdio_file_write(const file_object_storage& storage, std::string_view message) noexcept {
    auto handle = storage.get_mutable<std::FILE*>();
    std::fwrite(message.data(), sizeof(char), message.length(), handle);
    std::fflush(handle);
}

void stdio_file_close(file_object_storage& storage) noexcept {
    auto handle = storage.get_mutable<std::FILE*>();
    std::fclose(handle);
    storage.reset();
}
#else
// No default file I/O; it is expected that the user will use
// their own implementation wherever a file is needed.
void stdio_file_open(file_object_storage&, std::string_view) {
    std::terminate();
}

void stdio_file_write(const file_object_storage&, std::string_view) noexcept {
    std::terminate();
}

void stdio_file_close(file_object_storage& storage) noexcept {
    std::terminate();
}
#endif

file_writer::file_writer(std::string_view path) {
    snitch::io::file_open(storage, path);
}

file_writer::file_writer(file_writer&& other) noexcept {
    storage = std::move(other.storage);
}

file_writer& file_writer::operator=(file_writer&& other) noexcept {
    close();
    storage = std::move(other.storage);
    return *this;
}

file_writer::~file_writer() {
    close();
}

void file_writer::write(std::string_view message) noexcept {
    if (!storage.has_value()) {
        return;
    }

    snitch::io::file_write(storage, message);
}

bool file_writer::is_open() noexcept {
    return storage.has_value();
}

void file_writer::close() noexcept {
    if (!storage.has_value()) {
        return;
    }

    snitch::io::file_close(storage);
}
} // namespace snitch::impl

namespace snitch::io {
function_ref<void(file_object_storage& storage, std::string_view path)> file_open =
    &impl::stdio_file_open;

function_ref<void(const file_object_storage& storage, std::string_view message) noexcept>
    file_write = &impl::stdio_file_write;

function_ref<void(file_object_storage& storage) noexcept> file_close = &impl::stdio_file_close;
} // namespace snitch::io

#endif

#if defined(SNITCH_IMPLEMENTATION)


namespace snitch {
SNITCH_EXPORT int main(int argc, char* argv[]) {
    if constexpr (snitch::is_enabled) {
        std::optional<snitch::cli::input> args = snitch::cli::parse_arguments(argc, argv);
        if (!args) {
            return 1;
        }
        snitch::tests.configure(*args);
        return snitch::tests.run_tests(*args) ? 0 : 1;
    } else {
        return 0;
    }
}
} // namespace snitch

#if SNITCH_DEFINE_MAIN
SNITCH_EXPORT int main(int argc, char* argv[]) {
    return snitch::main(argc, argv);
}
#endif

#endif

#if defined(SNITCH_IMPLEMENTATION)

namespace snitch::matchers {
contains_substring::contains_substring(std::string_view pattern) noexcept :
    substring_pattern(pattern) {}

bool contains_substring::match(std::string_view message) const noexcept {
    return message.find(substring_pattern) != message.npos;
}

small_string<max_message_length>
contains_substring::describe_match(std::string_view message, match_status status) const noexcept {
    small_string<max_message_length> description_buffer;
    append_or_truncate(
        description_buffer, (status == match_status::matched ? "found" : "could not find"), " '",
        substring_pattern, "' in '", message, "'");
    return description_buffer;
}

with_what_contains::with_what_contains(std::string_view pattern) noexcept :
    contains_substring(pattern) {}
} // namespace snitch::matchers

#endif

#if defined(SNITCH_IMPLEMENTATION)


#include <algorithm> // for std::sort
#include <optional> // for std::optional

// Testing framework implementation.
// ---------------------------------

namespace snitch::impl {
namespace {
using namespace std::literals;

// Requires: s contains a well-formed list of tags.
template<typename F>
void for_each_raw_tag(std::string_view s, F&& callback) {
    if (s.empty()) {
        return;
    }

    if (s.find_first_of("[") == std::string_view::npos ||
        s.find_first_of("]") == std::string_view::npos) {
        assertion_failed("incorrectly formatted tag; please use \"[tag1][tag2][...]\"");
    }

    std::string_view delim    = "][";
    std::size_t      pos      = s.find(delim);
    std::size_t      last_pos = 0u;

    while (pos != std::string_view::npos) {
        std::size_t cur_size = pos - last_pos;
        if (cur_size != 0) {
            callback(s.substr(last_pos, cur_size + 1));
        }
        last_pos = pos + 1;
        pos      = s.find(delim, last_pos);
    }

    callback(s.substr(last_pos));
}

namespace tags {
struct hidden {};
struct may_fail {};
struct should_fail {};

using parsed_tag = std::variant<std::string_view, hidden, may_fail, should_fail>;
} // namespace tags

// Requires: s contains a well-formed list of tags, each of length <= max_tag_length.
template<typename F>
void for_each_tag(std::string_view s, F&& callback) {
    small_string<max_tag_length> buffer;

    for_each_raw_tag(s, [&](std::string_view t) {
        // Look for "hidden" tags, which is either "[.]"
        // or a tag starting with ".", like "[.integration]".
        if (t == "[.]"sv) {
            // This is a pure "hidden" tag, add this to the list of special tags.
            callback(tags::parsed_tag{tags::hidden{}});
        } else if (t.starts_with("[."sv)) {
            // This is a combined "hidden" + normal tag, add the "hidden" to the list of special
            // tags, and continue with the normal tag.
            callback(tags::parsed_tag{tags::hidden{}});
            callback(tags::parsed_tag{std::string_view("[.]")});

            buffer.clear();
            if (!append(buffer, "[", t.substr(2u))) {
                assertion_failed("tag is too long");
            }

            t = buffer;
        }

        if (t == "[!mayfail]") {
            callback(tags::parsed_tag{tags::may_fail{}});
        }

        if (t == "[!shouldfail]") {
            callback(tags::parsed_tag{tags::should_fail{}});
        }

        callback(tags::parsed_tag(t));
    });
}

// Requires: s contains a well-formed list of tags, each of length <= max_tag_length.
bool has_hidden_tag(std::string_view tags) {
    bool hidden = false;
    impl::for_each_tag(tags, [&](const impl::tags::parsed_tag& s) {
        if (std::holds_alternative<impl::tags::hidden>(s)) {
            hidden = true;
        }
    });

    return hidden;
}

template<typename F>
void list_tests(const registry& r, F&& predicate) noexcept {
    r.report_callback(r, event::list_test_run_started{});

    for (const test_case& t : r.test_cases()) {
        if (!predicate(t.id)) {
            continue;
        }

        r.report_callback(r, event::test_case_listed{t.id, t.location});
    }

    r.report_callback(r, event::list_test_run_ended{});
}

void set_state(test_case& t, impl::test_case_state s) noexcept {
    if (static_cast<std::underlying_type_t<impl::test_case_state>>(t.state) <
        static_cast<std::underlying_type_t<impl::test_case_state>>(s)) {
        t.state = s;
    }
}

snitch::test_case_state convert_to_public_state(impl::test_case_state s) noexcept {
    switch (s) {
    case impl::test_case_state::success: return snitch::test_case_state::success;
    case impl::test_case_state::failed: return snitch::test_case_state::failed;
    case impl::test_case_state::allowed_fail: return snitch::test_case_state::allowed_fail;
    case impl::test_case_state::skipped: return snitch::test_case_state::skipped;
    default: terminate_with("test case state cannot be exposed to the public");
    }
}

small_vector<std::string_view, max_captures>
make_capture_buffer(const capture_state& captures) noexcept {
    small_vector<std::string_view, max_captures> captures_buffer;
    for (const auto& c : captures) {
        captures_buffer.push_back(c);
    }

    return captures_buffer;
}
} // namespace

bool make_full_name(small_string<max_test_name_length>& buffer, const test_id& id) noexcept {
    buffer.clear();

    if (id.type.length() != 0) {
        return append(buffer, id.name, " <", id.type, ">");
    } else {
        return append(buffer, id.name);
    }
}
} // namespace snitch::impl

namespace snitch {
filter_result filter_result_and(filter_result first, filter_result second) noexcept {
    // AND favours exclusion over inclusion, then explicit over implicit.
    if (!first.included && second.included) {
        return first;
    } else if (first.included && !second.included) {
        return second;
    } else if (!first.implicit) {
        return first;
    } else {
        return second;
    }
}

filter_result filter_result_or(filter_result first, filter_result second) noexcept {
    // OR favours inclusion over exclusion, then explicit over implicit.
    if (first.included && !second.included) {
        return first;
    } else if (!first.included && second.included) {
        return second;
    } else if (!first.implicit) {
        return first;
    } else {
        return second;
    }
}

filter_result is_filter_match_name(std::string_view name, std::string_view filter) noexcept {
    filter_result match_action    = {.included = true, .implicit = false};
    filter_result no_match_action = {.included = false, .implicit = true};
    if (filter.starts_with('~')) {
        filter = filter.substr(1);
        std::swap(match_action.included, no_match_action.included);
    }

    return is_match(name, filter) ? match_action : no_match_action;
}

filter_result is_filter_match_tags_single(std::string_view tags, std::string_view filter) noexcept {
    filter_result match_action    = {.included = true, .implicit = false};
    filter_result no_match_action = {.included = false, .implicit = true};
    if (filter.starts_with('~')) {
        filter = filter.substr(1);
        std::swap(match_action.included, no_match_action.included);
    }

    bool match = false;
    impl::for_each_tag(tags, [&](const impl::tags::parsed_tag& v) {
        if (auto* vs = std::get_if<std::string_view>(&v); vs != nullptr) {
            if (is_match(*vs, filter)) {
                match = true;
            }
        }
    });

    return match ? match_action : no_match_action;
}

filter_result is_filter_match_tags(std::string_view tags, std::string_view filter) noexcept {
    // Start with no result.
    std::optional<filter_result> result;

    // Evaluate each tag filter (one after the other, e.g. "[tag1][tag2]").
    std::size_t end_pos = 0;
    do {
        end_pos = find_first_not_escaped(filter, ']');
        if (end_pos != std::string_view::npos) {
            ++end_pos;
        }

        const filter_result sub_result =
            is_filter_match_tags_single(tags, filter.substr(0, end_pos));

        if (!result.has_value()) {
            // The first filter initialises the result.
            result = sub_result;
        } else {
            // Subsequent filters are combined with the current result using AND.
            result = filter_result_and(*result, sub_result);
        }

        if (!result->included) {
            // Optimisation; we can short-circuit at the first exclusion.
            // It does not matter if it is implicit or explicit, they are treated the same.
            break;
        }

        if (end_pos != std::string_view::npos) {
            filter.remove_prefix(end_pos);
        }
    } while (end_pos != std::string_view::npos && !filter.empty());

    return *result;
}

filter_result is_filter_match_id_single(
    std::string_view name, std::string_view tags, std::string_view filter) noexcept {

    if (filter.starts_with('[') || filter.starts_with("~[")) {
        return is_filter_match_tags(tags, filter);
    } else {
        return is_filter_match_name(name, filter);
    }
}

filter_result
is_filter_match_id(std::string_view name, std::string_view tags, std::string_view filter) noexcept {
    // Start with no result.
    std::optional<filter_result> result;

    // Evaluate each filter (comma-separated).
    std::size_t comma_pos = 0;
    do {
        comma_pos = find_first_not_escaped(filter, ',');

        const filter_result sub_result =
            is_filter_match_id_single(name, tags, filter.substr(0, comma_pos));

        if (!result.has_value()) {
            // The first filter initialises the result.
            result = sub_result;
        } else {
            // Subsequent filters are combined with the current result using OR.
            result = filter_result_or(*result, sub_result);
        }

        if (result->included && !result->implicit) {
            // Optimisation; we can short-circuit at the first explicit inclusion.
            // We can't short-circuit on implicit inclusion, because there could still be an
            // explicit inclusion coming, and we want to know (for hidden tests).
            break;
        }

        if (comma_pos != std::string_view::npos) {
            filter.remove_prefix(comma_pos + 1);
        }
    } while (comma_pos != std::string_view::npos);

    return *result;
}
} // namespace snitch

namespace snitch {
std::string_view registry::add_reporter(
    std::string_view                                 name,
    const std::optional<initialize_report_function>& initialize,
    const std::optional<configure_report_function>&  configure,
    const report_function&                           report,
    const std::optional<finish_report_function>&     finish) {

    if (registered_reporters.available() == 0u) {
        using namespace snitch::impl;
        print(
            make_colored("error:", with_color, color::fail),
            " max number of reporters reached; "
            "please increase 'SNITCH_MAX_REGISTERED_REPORTERS' (currently ",
            max_registered_reporters, ").\n");
        assertion_failed("max number of reporters reached");
    }

    if (name.find("::") != std::string_view::npos) {
        using namespace snitch::impl;
        print(
            make_colored("error:", with_color, color::fail),
            " reporter name cannot contains '::' (trying to register '", name, "')\n.");
        assertion_failed("invalid reporter name");
    }

    registered_reporters.push_back(registered_reporter{
        name, initialize.value_or([](registry&) noexcept {}),
        configure.value_or(
            [](registry&, std::string_view, std::string_view) noexcept { return false; }),
        report, finish.value_or([](registry&) noexcept {})});

    return name;
}

void registry::destroy_reporter(registry&) noexcept {
    reporter_storage.reset();
}

void registry::report_default(const registry&, const event::data& e) noexcept {
    using default_reporter = reporter::console::reporter;

    if (reporter_storage.type() != type_id<default_reporter>()) {
        reporter_storage.emplace<default_reporter>(*this);
    }

    reporter_storage.get<default_reporter>().report(*this, e);
}

const char*
registry::add_impl(const test_id& id, const source_location& location, impl::test_ptr func) {
    if (test_list.available() == 0u) {
        using namespace snitch::impl;
        print(
            make_colored("error:", with_color, color::fail),
            " max number of test cases reached; "
            "please increase 'SNITCH_MAX_TEST_CASES' (currently ",
            max_test_cases, ").\n");
        assertion_failed("max number of test cases reached");
    }

    test_list.push_back(impl::test_case{id, location, func});

    small_string<max_test_name_length> buffer;
    if (!impl::make_full_name(buffer, test_list.back().id)) {
        using namespace snitch::impl;
        print(
            make_colored("error:", with_color, color::fail),
            " max length of test name reached; "
            "please increase 'SNITCH_MAX_TEST_NAME_LENGTH' (currently ",
            max_test_name_length, ")\n.");
        assertion_failed("test case name exceeds max length");
    }

    return id.name.data();
}

const char*
registry::add(const impl::name_and_tags& id, const source_location& location, impl::test_ptr func) {
    return add_impl({.name = id.name, .tags = id.tags}, location, func);
}

const char* registry::add_fixture(
    const impl::fixture_name_and_tags& id, const source_location& location, impl::test_ptr func) {

    return add_impl({.name = id.name, .tags = id.tags, .fixture = id.fixture}, location, func);
}

namespace {
void register_assertion(bool success, impl::test_state& state) {
    if (!success) {
        if (state.may_fail || state.should_fail) {
            ++state.asserts;
            ++state.allowed_failures;

            for (auto& section : state.info.sections.current_section) {
                ++section.assertion_count;
                ++section.allowed_assertion_failure_count;
            }

#if SNITCH_WITH_EXCEPTIONS
            if (state.held_info.has_value()) {
                for (auto& section : state.held_info.value().sections.current_section) {
                    ++section.assertion_count;
                    ++section.allowed_assertion_failure_count;
                }
            }
#endif

            impl::set_state(state.test, impl::test_case_state::allowed_fail);
        } else {
            ++state.asserts;
            ++state.failures;

            for (auto& section : state.info.sections.current_section) {
                ++section.assertion_count;
                ++section.assertion_failure_count;
            }

#if SNITCH_WITH_EXCEPTIONS
            if (state.held_info.has_value()) {
                for (auto& section : state.held_info.value().sections.current_section) {
                    ++section.assertion_count;
                    ++section.assertion_failure_count;
                }
            }
#endif

            impl::set_state(state.test, impl::test_case_state::failed);
        }
    } else {
        ++state.asserts;

        for (auto& section : state.info.sections.current_section) {
            ++section.assertion_count;
        }

#if SNITCH_WITH_EXCEPTIONS
        if (state.held_info.has_value()) {
            for (auto& section : state.held_info.value().sections.current_section) {
                ++section.assertion_count;
            }
        }
#endif
    }
}

void report_assertion_impl(
    const registry& r, bool success, impl::test_state& state, const assertion_data& data) noexcept {

    if (state.test.state == impl::test_case_state::skipped) {
        return;
    }

    register_assertion(success, state);

#if SNITCH_WITH_EXCEPTIONS
    const bool use_held_info = (state.unhandled_exception || std::uncaught_exceptions() > 0) &&
                               state.held_info.has_value();

    const auto captures_buffer = impl::make_capture_buffer(
        use_held_info ? state.held_info.value().captures : state.info.captures);

    const auto& current_section = use_held_info ? state.held_info.value().sections.current_section
                                                : state.info.sections.current_section;

    const auto& last_location =
        use_held_info ? state.held_info.value().locations.back() : state.info.locations.back();

    const auto location =
        state.in_check
            ? assertion_location{last_location.file, last_location.line, location_type::exact}
            : last_location;
#else
    const auto  captures_buffer = impl::make_capture_buffer(state.info.captures);
    const auto& current_section = state.info.sections.current_section;
    const auto& last_location   = state.info.locations.back();
    const auto  location =
        assertion_location{last_location.file, last_location.line, location_type::exact};
#endif

    if (success) {
        if (r.verbose >= registry::verbosity::full) {
            r.report_callback(
                r, event::assertion_succeeded{
                       state.test.id, current_section, captures_buffer.span(), location, data});
        }
    } else {
        r.report_callback(
            r, event::assertion_failed{
                   state.test.id, current_section, captures_buffer.span(), location, data,
                   state.should_fail, state.may_fail});
    }
}
} // namespace

void registry::report_assertion(bool success, std::string_view message) noexcept {
    impl::test_state& state = impl::get_current_test();
    report_assertion_impl(state.reg, success, state, message);
}

void registry::report_assertion(
    bool success, std::string_view message1, std::string_view message2) noexcept {

    impl::test_state& state = impl::get_current_test();
    if (state.test.state == impl::test_case_state::skipped) {
        return;
    }

    small_string<max_message_length> message;
    append_or_truncate(message, message1, message2);
    report_assertion_impl(state.reg, success, state, message);
}

void registry::report_assertion(bool success, const impl::expression& exp) noexcept {
    impl::test_state& state = impl::get_current_test();
    if (state.test.state == impl::test_case_state::skipped) {
        return;
    }

    report_assertion_impl(
        state.reg, success, state, expression_info{exp.type, exp.expected, exp.actual});
}

void registry::report_skipped(std::string_view message) noexcept {
    impl::test_state& state = impl::get_current_test();
    impl::set_state(state.test, impl::test_case_state::skipped);

    const auto  captures_buffer = impl::make_capture_buffer(state.info.captures);
    const auto& location        = state.info.locations.back();

    state.reg.report_callback(
        state.reg, event::test_case_skipped{
                       state.test.id,
                       state.info.sections.current_section,
                       captures_buffer.span(),
                       {location.file, location.line, location_type::exact},
                       message});
}

void registry::report_section_started(const section& sec) noexcept {
    const impl::test_state& state = impl::get_current_test();

    if (state.reg.verbose < registry::verbosity::high) {
        return;
    }

    state.reg.report_callback(state.reg, event::section_started{sec.id, sec.location});
}

void registry::report_section_ended(const section& sec) noexcept {
    const impl::test_state& state = impl::get_current_test();

    if (state.reg.verbose < registry::verbosity::high) {
        return;
    }

    const bool skipped = state.test.state == impl::test_case_state::skipped;

#if SNITCH_WITH_TIMINGS
    const auto duration = get_duration_in_seconds(sec.start_time, get_current_time());
    state.reg.report_callback(
        state.reg, event::section_ended{
                       .id                              = sec.id,
                       .location                        = sec.location,
                       .skipped                         = skipped,
                       .assertion_count                 = sec.assertion_count,
                       .assertion_failure_count         = sec.assertion_failure_count,
                       .allowed_assertion_failure_count = sec.allowed_assertion_failure_count,
                       .duration                        = duration});
#else
    state.reg.report_callback(
        state.reg, event::section_ended{
                       .id                              = sec.id,
                       .location                        = sec.location,
                       .skipped                         = skipped,
                       .assertion_count                 = sec.assertion_count,
                       .assertion_failure_count         = sec.assertion_failure_count,
                       .allowed_assertion_failure_count = sec.allowed_assertion_failure_count});
#endif
}

impl::test_state registry::run(impl::test_case& test) noexcept {
    if (verbose >= registry::verbosity::high) {
        report_callback(*this, event::test_case_started{test.id, test.location});
    }

    test.state = impl::test_case_state::success;

    // Fetch special tags for this test case.
    bool may_fail    = false;
    bool should_fail = false;
    impl::for_each_tag(test.id.tags, [&](const impl::tags::parsed_tag& v) {
        if (std::holds_alternative<impl::tags::may_fail>(v)) {
            may_fail = true;
        } else if (std::holds_alternative<impl::tags::should_fail>(v)) {
            should_fail = true;
        }
    });

    impl::test_state state{
        .reg = *this, .test = test, .may_fail = may_fail, .should_fail = should_fail};

    state.info.locations.push_back(
        {test.location.file, test.location.line, location_type::test_case_scope});

    // Store previously running test, to restore it later.
    // This should always be a null pointer, except when testing snitch itself.
    impl::test_state* previous_run = impl::try_get_current_test();
    impl::set_current_test(&state);

#if SNITCH_WITH_TIMINGS
    const auto time_start = get_current_time();
#endif

#if SNITCH_WITH_EXCEPTIONS
    try {
#endif

        do {
            // Reset section state.
            state.info.sections.leaf_executed = false;
            for (std::size_t i = 0; i < state.info.sections.levels.size(); ++i) {
                state.info.sections.levels[i].current_section_id = 0;
            }

            // Run the test case.
            test.func();

            if (state.info.sections.levels.size() == 1) {
                // This test case contained sections; check if there are any more left to evaluate.
                auto& child = state.info.sections.levels[0];
                if (child.previous_section_id == child.max_section_id) {
                    // No more; clear the section state.
                    state.info.sections.levels.clear();
                    state.info.sections.current_section.clear();
                }
            }
        } while (!state.info.sections.levels.empty() &&
                 state.test.state != impl::test_case_state::skipped);

#if SNITCH_WITH_EXCEPTIONS
        state.in_check = true;
        report_assertion(true, "no exception caught");
        state.in_check = false;
    } catch (const impl::abort_exception&) {
        // Test aborted, assume its state was already set accordingly.
        state.unhandled_exception = true;
    } catch (const std::exception& e) {
        state.unhandled_exception = true;
        report_assertion(false, "unexpected std::exception caught; message: ", e.what());
    } catch (...) {
        state.unhandled_exception = true;
        report_assertion(false, "unexpected unknown exception caught");
    }

    if (state.unhandled_exception) {
        notify_exception_handled();
    }

    state.unhandled_exception = false;
#endif

    if (state.should_fail) {
        state.should_fail = false;
        state.in_check    = true;
        report_assertion(
            state.test.state == impl::test_case_state::allowed_fail, "expected test to fail");
        state.in_check    = false;
        state.should_fail = true;
    }

#if SNITCH_WITH_TIMINGS
    state.duration = get_duration_in_seconds(time_start, get_current_time());
#endif

    if (verbose >= registry::verbosity::high) {
#if SNITCH_WITH_TIMINGS
        report_callback(
            *this, event::test_case_ended{
                       .id                              = test.id,
                       .location                        = test.location,
                       .assertion_count                 = state.asserts,
                       .assertion_failure_count         = state.failures,
                       .allowed_assertion_failure_count = state.allowed_failures,
                       .state    = impl::convert_to_public_state(state.test.state),
                       .duration = state.duration});
#else
        report_callback(
            *this, event::test_case_ended{
                       .id                              = test.id,
                       .location                        = test.location,
                       .assertion_count                 = state.asserts,
                       .assertion_failure_count         = state.failures,
                       .allowed_assertion_failure_count = state.allowed_failures,
                       .state = impl::convert_to_public_state(state.test.state)});
#endif
    }

    impl::set_current_test(previous_run);

    return state;
}

bool registry::run_selected_tests(
    std::string_view                                   run_name,
    const filter_info&                                 filter_strings,
    const function_ref<bool(const test_id&) noexcept>& predicate) noexcept {

    if (verbose >= registry::verbosity::normal) {
        report_callback(
            *this, event::test_run_started{.name = run_name, .filters = filter_strings});
    }

    bool        success                         = true;
    std::size_t run_count                       = 0;
    std::size_t fail_count                      = 0;
    std::size_t allowed_fail_count              = 0;
    std::size_t skip_count                      = 0;
    std::size_t assertion_count                 = 0;
    std::size_t assertion_failure_count         = 0;
    std::size_t allowed_assertion_failure_count = 0;

#if SNITCH_WITH_TIMINGS
    const auto time_start = get_current_time();
#endif

    for (impl::test_case& t : this->test_cases()) {
        if (!predicate(t.id)) {
            continue;
        }

        auto state = run(t);

        ++run_count;
        assertion_count += state.asserts;
        assertion_failure_count += state.failures;
        allowed_assertion_failure_count += state.allowed_failures;

        switch (t.state) {
        case impl::test_case_state::success: {
            // Nothing to do
            break;
        }
        case impl::test_case_state::allowed_fail: {
            ++allowed_fail_count;
            break;
        }
        case impl::test_case_state::failed: {
            ++fail_count;
            success = false;
            break;
        }
        case impl::test_case_state::skipped: {
            ++skip_count;
            break;
        }
        case impl::test_case_state::not_run: {
            // Unreachable
            break;
        }
        }
    }

#if SNITCH_WITH_TIMINGS
    const float duration = get_duration_in_seconds(time_start, get_current_time());
#endif

    if (verbose >= registry::verbosity::normal) {
#if SNITCH_WITH_TIMINGS
        report_callback(
            *this, event::test_run_ended{
                       .name                            = run_name,
                       .filters                         = filter_strings,
                       .run_count                       = run_count,
                       .fail_count                      = fail_count,
                       .allowed_fail_count              = allowed_fail_count,
                       .skip_count                      = skip_count,
                       .assertion_count                 = assertion_count,
                       .assertion_failure_count         = assertion_failure_count,
                       .allowed_assertion_failure_count = allowed_assertion_failure_count,
                       .duration                        = duration,
                       .success                         = success,
                   });
#else
        report_callback(
            *this, event::test_run_ended{
                       .name                            = run_name,
                       .filters                         = filter_strings,
                       .run_count                       = run_count,
                       .fail_count                      = fail_count,
                       .allowed_fail_count              = allowed_fail_count,
                       .skip_count                      = skip_count,
                       .assertion_count                 = assertion_count,
                       .assertion_failure_count         = assertion_failure_count,
                       .allowed_assertion_failure_count = allowed_assertion_failure_count,
                       .success                         = success});
#endif
    }

    return success;
}

bool registry::run_tests(std::string_view run_name) noexcept {
    // The default run simply filters out the hidden tests.
    const auto filter = [](const test_id& id) { return !impl::has_hidden_tag(id.tags); };

    const small_vector<std::string_view, 1> filter_strings = {};
    return run_selected_tests(run_name, filter_strings, filter);
}

namespace {
bool run_tests_impl(registry& r, const cli::input& args) noexcept {
    if (get_option(args, "--help")) {
        cli::print_help(args.executable, {.with_color = r.with_color});
        return true;
    }

    if (auto opt = get_option(args, "--list-tests-with-tag")) {
        r.list_tests_with_tag(*opt->value);
        return true;
    }

    if (get_option(args, "--list-tags")) {
        r.list_all_tags();
        return true;
    }

    if (get_option(args, "--list-reporters")) {
        r.list_all_reporters();
        return true;
    }

    if (get_positional_argument(args, "test regex").has_value()) {
        // Gather all filters in a local array (for faster iteration and for event reporting).
        small_vector<std::string_view, max_command_line_args> filter_strings;
        const auto add_filter_string = [&](std::string_view filter) noexcept {
            filter_strings.push_back(filter);
        };
        for_each_positional_argument(args, "test regex", add_filter_string);

        // This buffer will be reused to evaluate the full name of each test.
        small_string<max_test_name_length> buffer;

        const auto filter = [&](const test_id& id) noexcept {
            // Start with no result.
            std::optional<filter_result> result;

            // Evaluate each filter (provided as separate command-line argument).
            for (const auto& filter : filter_strings) {
                impl::make_full_name(buffer, id);

                const filter_result sub_result = is_filter_match_id(buffer.str(), id.tags, filter);

                if (!result.has_value()) {
                    // The first filter initialises the result.
                    result = sub_result;
                } else {
                    // Subsequent filters are combined with the current result using AND.
                    result = filter_result_and(*result, sub_result);
                }

                if (!result->included) {
                    // Optimisation; we can short-circuit at the first exclusion.
                    // It does not matter if it is implicit or explicit, they are treated the same.
                    break;
                }
            }

            if (result->included) {
                if (!result->implicit) {
                    // Explicit inclusion always selects the test.
                    return true;
                } else {
                    // Implicit inclusion only selects non-hidden tests.
                    return !impl::has_hidden_tag(id.tags);
                }
            } else {
                // Exclusion always discards the test, regardless if it is explicit or implicit.
                return false;
            }
        };

        if (get_option(args, "--list-tests")) {
            impl::list_tests(r, filter);
            return true;
        } else {
            return r.run_selected_tests(args.executable, filter_strings, filter);
        }
    } else {
        if (get_option(args, "--list-tests")) {
            r.list_all_tests();
            return true;
        } else {
            return r.run_tests(args.executable);
        }
    }
}
} // namespace

bool registry::run_tests(const cli::input& args) noexcept {
    // Run tests.
    const bool success = run_tests_impl(*this, args);

    // Tell the current reporter we are done.
    finish_callback(*this);

    // Close the output file, if any.
    file_writer.reset();

    return success;
}

namespace impl {
void parse_reporter(
    registry&                                    r,
    small_vector_span<const registered_reporter> reporters,
    std::string_view                             arg) noexcept {

    if (arg.empty() || arg[0] == ':') {
        using namespace snitch::impl;
        cli::print(
            make_colored("warning:", r.with_color, color::warning), " invalid reporter '", arg,
            "', using default\n");
        return;
    }

    // Isolate reporter name and options
    std::string_view reporter_name = arg;
    std::string_view options;
    if (auto option_pos = reporter_name.find("::"); option_pos != std::string_view::npos) {
        options       = reporter_name.substr(option_pos);
        reporter_name = reporter_name.substr(0, option_pos);
    }

    // Locate reporter
    auto iter = std::find_if(reporters.begin(), reporters.end(), [&](const auto& reporter) {
        return reporter.name == reporter_name;
    });

    if (iter == reporters.end()) {
        using namespace snitch::impl;
        cli::print(
            make_colored("warning:", r.with_color, color::warning), " unknown reporter '",
            reporter_name, "', using default\n");
        cli::print(make_colored("note:", r.with_color, color::status), " available reporters:\n");
        for (const auto& reporter : reporters) {
            cli::print(
                make_colored("note:", r.with_color, color::status), "  ", reporter.name, "\n");
        }
        return;
    }

    // Initialise reporter now, so we can configure it.
    iter->initialize(r);

    // Configure reporter
    auto option_pos = options.find("::");
    while (option_pos != std::string_view::npos) {
        option_pos = options.find("::", 2);
        if (option_pos != std::string_view::npos) {
            options = options.substr(option_pos);
        }

        std::string_view option = options.substr(2, option_pos);

        auto equal_pos = option.find("=");
        if (equal_pos == std::string_view::npos || equal_pos == 0) {
            using namespace snitch::impl;
            cli::print(
                make_colored("warning:", r.with_color, color::warning),
                " badly formatted reporter option '", option, "'; expected 'key=value'\n");
            continue;
        }

        std::string_view option_name  = option.substr(0, equal_pos);
        std::string_view option_value = option.substr(equal_pos + 1);

        if (!iter->configure(r, option_name, option_value)) {
            using namespace snitch::impl;
            cli::print(
                make_colored("warning:", r.with_color, color::warning),
                " unknown reporter option '", option_name, "'\n");
        }
    }

    // Register reporter callbacks
    r.report_callback = iter->callback;
    r.finish_callback = iter->finish;
}

bool parse_colour_mode_option(registry& reg, std::string_view color_option) noexcept {
    if (color_option == "ansi") {
        reg.with_color = true;
        return true;
    } else if (color_option == "none") {
        reg.with_color = false;
        return true;
    } else if (color_option == "default") {
        // Nothing to do.
        return false;
    } else {
        using namespace snitch::impl;
        cli::print(
            make_colored("warning:", reg.with_color, color::warning),
            " unknown color directive; please use one of ansi|default|none\n");
        return false;
    }
}

bool parse_color_option(registry& reg, std::string_view color_option) noexcept {
    if (color_option == "always") {
        reg.with_color = true;
        return true;
    } else if (color_option == "never") {
        reg.with_color = false;
        return true;
    } else if (color_option == "default") {
        // Nothing to do.
        return false;
    } else {
        using namespace snitch::impl;
        cli::print(
            make_colored("warning:", reg.with_color, color::warning),
            " unknown color directive; please use one of always|default|never\n");
        return false;
    }
}
} // namespace impl

void registry::configure(const cli::input& args) {
    bool color_override = false;
    if (auto opt = get_option(args, "--colour-mode")) {
        color_override = impl::parse_colour_mode_option(*this, *opt->value);
    }

    if (auto opt = get_option(args, "--color")) {
        color_override = impl::parse_color_option(*this, *opt->value) || color_override;
    }

    if (auto opt = get_option(args, "--verbosity")) {
        if (*opt->value == "quiet") {
            verbose = snitch::registry::verbosity::quiet;
        } else if (*opt->value == "normal") {
            verbose = snitch::registry::verbosity::normal;
        } else if (*opt->value == "high") {
            verbose = snitch::registry::verbosity::high;
        } else if (*opt->value == "full") {
            verbose = snitch::registry::verbosity::full;
        } else {
            using namespace snitch::impl;
            cli::print(
                make_colored("warning:", with_color, color::warning),
                " unknown verbosity level; please use one of quiet|normal|high|full\n");
        }
    }

    if (auto opt = get_option(args, "--out")) {
        file_writer = impl::file_writer{*opt->value};

        if (!color_override) {
            with_color = false;
        }

        print_callback = {*file_writer, snitch::constant<&impl::file_writer::write>{}};
    }

    if (auto opt = get_option(args, "--reporter")) {
        impl::parse_reporter(*this, registered_reporters, *opt->value);
    }
}

void registry::list_all_tags() const {
    small_vector<std::string_view, max_unique_tags> tags;
    for (const auto& t : test_list) {
        impl::for_each_tag(t.id.tags, [&](const impl::tags::parsed_tag& v) {
            if (auto* vs = std::get_if<std::string_view>(&v); vs != nullptr) {
                if (std::find(tags.begin(), tags.end(), *vs) == tags.end()) {
                    if (tags.size() == tags.capacity()) {
                        using namespace snitch::impl;
                        cli::print(
                            make_colored("error:", with_color, color::fail),
                            " max number of tags reached; "
                            "please increase 'SNITCH_MAX_UNIQUE_TAGS' (currently ",
                            max_unique_tags, ").\n");
                        assertion_failed("max number of unique tags reached");
                    }

                    tags.push_back(*vs);
                }
            }
        });
    }

    std::sort(tags.begin(), tags.end());

    for (const auto& t : tags) {
        cli::print("[", t, "]\n");
    }
}

void registry::list_all_tests() const noexcept {
    impl::list_tests(*this, [](const test_id&) { return true; });
}

void registry::list_tests_with_tag(std::string_view tag) const noexcept {
    impl::list_tests(*this, [&](const test_id& id) {
        const auto result = is_filter_match_tags(id.tags, tag);
        return result.included;
    });
}

void registry::list_all_reporters() const noexcept {
    for (const auto& r : registered_reporters) {
        cli::print(r.name, "\n");
    }
}

small_vector_span<impl::test_case> registry::test_cases() noexcept {
    return test_list;
}

small_vector_span<const impl::test_case> registry::test_cases() const noexcept {
    return test_list;
}

small_vector_span<registered_reporter> registry::reporters() noexcept {
    return registered_reporters;
}

small_vector_span<const registered_reporter> registry::reporters() const noexcept {
    return registered_reporters;
}

#if SNITCH_ENABLE
constinit registry tests;
#endif // SNITCH_ENABLE
} // namespace snitch

#endif

#if defined(SNITCH_IMPLEMENTATION)

#if SNITCH_WITH_CATCH2_XML_REPORTER || SNITCH_WITH_ALL_REPORTERS


#    include <initializer_list>

namespace snitch::reporter::catch2_xml {
namespace {
struct key_value {
    std::string_view key;
    std::string_view value;
};

bool escape(small_string_span string) noexcept {
    return escape_all_or_truncate(string, "&", "&amp;") &&
           escape_all_or_truncate(string, "\"", "&quot;") &&
           escape_all_or_truncate(string, "'", "&apos;") &&
           escape_all_or_truncate(string, "<", "&lt;") &&
           escape_all_or_truncate(string, ">", "&gt;");
}

small_string<max_message_length> make_escaped(std::string_view string) noexcept {
    small_string<max_message_length> escaped_string;
    append_or_truncate(escaped_string, string);
    escape(escaped_string);
    return escaped_string;
}

small_string<max_test_name_length> make_full_name(const test_id& id) noexcept {
    small_string<max_test_name_length> name;
    snitch::impl::make_full_name(name, id);
    escape(name);
    return name;
}

small_string<max_message_length> make_filters(const filter_info& filters) noexcept {
    small_string<max_message_length> filter_string;

    bool first = true;
    for (const auto& filter : filters) {
        append_or_truncate(filter_string, (first ? "\"" : " \""), filter, "\"");
        first = false;
    }

    escape(filter_string);
    return filter_string;
}

constexpr std::size_t max_number_length = 32;

template<typename T>
small_string<max_number_length> make_string(T number) noexcept {
    small_string<max_number_length> string;
    append_or_truncate(string, number);
    return string;
}

std::string_view get_indent(const reporter& rep) noexcept {
    constexpr std::string_view spaces            = "                ";
    constexpr std::size_t      spaces_per_indent = 2;
    return spaces.substr(0, std::min(spaces.size(), spaces_per_indent * rep.indent_level));
}

void close(reporter& rep, const registry& r, std::string_view name) noexcept {
    --rep.indent_level;
    r.print(get_indent(rep), "</", name, ">\n");
}

void print(const reporter& rep, const registry& r, std::string_view data) noexcept {
    r.print(get_indent(rep), data, "\n");
}

void open(
    reporter&                        rep,
    const registry&                  r,
    std::string_view                 name,
    std::initializer_list<key_value> args = {}) noexcept {

    r.print(get_indent(rep), "<", name);
    for (const auto& arg : args) {
        r.print(" ", arg.key, "=\"", arg.value, "\"");
    }
    r.print(">\n");
    ++rep.indent_level;
}

void node(
    const reporter&                  rep,
    const registry&                  r,
    std::string_view                 name,
    std::initializer_list<key_value> args = {}) noexcept {

    r.print(get_indent(rep), "<", name);
    for (const auto& arg : args) {
        r.print(" ", arg.key, "=\"", arg.value, "\"");
    }
    r.print("/>\n");
}

void open_close(
    const reporter&  rep,
    const registry&  r,
    std::string_view name,
    std::string_view content) noexcept {

    if (content.empty()) {
        node(rep, r, name);
    } else {
        r.print(get_indent(rep), "<", name, ">", content, "</", name, ">\n");
    }
}

template<typename T>
void report_assertion(reporter& rep, const registry& r, const T& e, bool success) noexcept {
    for (const auto& c : e.captures) {
        open(rep, r, "Info");
        print(rep, r, make_escaped(c));
        close(rep, r, "Info");
    }

    std::visit(
        overload{
            [&](std::string_view message) {
                open(
                    rep, r, success ? "Success" : "Failure",
                    {{"filename", make_escaped(e.location.file)},
                     {"line", make_string(e.location.line)}});
                print(rep, r, make_escaped(message));
                close(rep, r, success ? "Success" : "Failure");
            },
            [&](const snitch::expression_info& exp) {
                open(
                    rep, r, "Expression",
                    {{"success", success ? "true" : "false"},
                     {"type", exp.type},
                     {"filename", make_escaped(e.location.file)},
                     {"line", make_string(e.location.line)}});

                open(rep, r, "Original");
                print(rep, r, make_escaped(exp.expected));
                close(rep, r, "Original");

                open(rep, r, "Expanded");
                if (!exp.actual.empty()) {
                    print(rep, r, make_escaped(exp.actual));
                } else {
                    print(rep, r, make_escaped(exp.expected));
                }
                close(rep, r, "Expanded");

                close(rep, r, "Expression");
            }},
        e.data);
}
} // namespace

reporter::reporter(registry& r) noexcept {
    // The XML reporter needs test_case_started and test_case_ended events, which are only
    // printed on verbosity 'high', so ensure the requested verbosity is at least as much.
    r.verbose = r.verbose < registry::verbosity::high ? registry::verbosity::high : r.verbose;
}

bool reporter::configure(registry&, std::string_view, std::string_view) noexcept {
    // No configuration
    return false;
}

void reporter::report(const registry& r, const snitch::event::data& event) noexcept {
    std::visit(
        snitch::overload{
            [&](const snitch::event::test_run_started& e) {
                print(*this, r, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
                // TODO: missing rng-seed
                open(
                    *this, r, "Catch2TestRun",
                    {{"name", make_escaped(e.name)},
                     {"rng-seed", "0"},
                     {"xml-format-version", "3"},
                     {"catch2-version", SNITCH_FULL_VERSION ".snitch"},
                     {"filters", make_filters(e.filters)}});
            },
            [&](const snitch::event::test_run_ended& e) {
                node(
                    *this, r, "OverallResults",
                    {{"successes", make_string(
                                       e.assertion_count - e.assertion_failure_count -
                                       e.allowed_assertion_failure_count)},
                     {"failures", make_string(e.assertion_failure_count)},
                     {"expectedFailures", make_string(e.allowed_assertion_failure_count)},
                     {"skips", make_string(e.skip_count)}});

                node(
                    *this, r, "OverallResultsCases",
                    {{"successes", make_string(e.run_count - e.fail_count - e.allowed_fail_count)},
                     {"failures", make_string(e.fail_count)},
                     {"expectedFailures", make_string(e.allowed_fail_count)},
                     {"skips", make_string(e.skip_count)}});

                close(*this, r, "Catch2TestRun");
            },
            [&](const snitch::event::test_case_started& e) {
                open(
                    *this, r, "TestCase",
                    {{"name", make_full_name(e.id)},
                     {"tags", make_escaped(e.id.tags)},
                     {"filename", make_escaped(e.location.file)},
                     {"line", make_string(e.location.line)}});
            },
            [&](const snitch::event::test_case_ended& e) {
#    if SNITCH_WITH_TIMINGS
                node(
                    *this, r, "OverallResult",
                    {{"success", e.state == test_case_state::failed ? "false" : "true"},
                     {"skips", e.state == test_case_state::skipped ? "1" : "0"},
                     {"durationInSeconds", make_string(e.duration)}});
#    else
                node(
                    *this, r, "OverallResult",
                    {{"success", e.state == test_case_state::failed ? "false" : "true"},
                     {"skips", e.state == test_case_state::skipped ? "1" : "0"}});
#    endif
                close(*this, r, "TestCase");
            },
            [&](const snitch::event::section_started& e) {
                open(
                    *this, r, "Section",
                    {{"name", make_escaped(e.id.name)},
                     {"filename", make_escaped(e.location.file)},
                     {"line", make_string(e.location.line)}});
            },
            [&](const snitch::event::section_ended& e) {
                node(
                    *this, r, "OverallResults",
                    {{"successes", make_string(
                                       e.assertion_count - e.assertion_failure_count -
                                       e.allowed_assertion_failure_count)},
                     {"failures", make_string(e.assertion_failure_count)},
                     {"expectedFailures", make_string(e.allowed_assertion_failure_count)},
                     {"skipped", e.skipped ? "true" : "false"}
#    if SNITCH_WITH_TIMINGS
                     ,
                     {"durationInSeconds", make_string(e.duration)}
#    endif
                    });
                close(*this, r, "Section");
            },
            [&](const snitch::event::test_case_skipped& e) {
                open(
                    *this, r, "Skip",
                    {{"filename", make_escaped(e.location.file)},
                     {"line", make_string(e.location.line)}});
                print(*this, r, e.message);
                close(*this, r, "Skip");
            },
            [&](const snitch::event::assertion_failed& e) { report_assertion(*this, r, e, false); },
            [&](const snitch::event::assertion_succeeded& e) {
                report_assertion(*this, r, e, true);
            },
            [&](const snitch::event::list_test_run_started&) {
                print(*this, r, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                open(*this, r, "MatchingTests");
            },
            [&](const snitch::event::list_test_run_ended&) { close(*this, r, "MatchingTests"); },
            [&](const snitch::event::test_case_listed& e) {
                open(*this, r, "TestCase");
                open_close(*this, r, "Name", make_full_name(e.id));
                open_close(*this, r, "ClassName", make_escaped(e.id.fixture));
                open_close(*this, r, "Tags", make_escaped(e.id.tags));
                open(*this, r, "SourceInfo");
                open_close(*this, r, "File", make_escaped(e.location.file));
                open_close(*this, r, "Line", make_string(e.location.line));
                close(*this, r, "SourceInfo");
                close(*this, r, "TestCase");
            }},
        event);
}
} // namespace snitch::reporter::catch2_xml

SNITCH_REGISTER_REPORTER("xml", snitch::reporter::catch2_xml::reporter);

#endif

#endif

#if defined(SNITCH_IMPLEMENTATION)


namespace snitch::reporter::console {
namespace {
using namespace std::literals;
using namespace snitch::impl;

std::string_view locatation_label(location_type type) {
    switch (type) {
    case location_type::exact: return "at";
    case location_type::section_scope: return "somewhere inside section at";
    case location_type::test_case_scope: return "somewhere inside test case at";
    case location_type::in_check: return "somewhere inside check at";
    default: return "at";
    }
}

void print_location(
    const registry&           r,
    const test_id&            id,
    const section_info&       sections,
    const capture_info&       captures,
    const assertion_location& location) noexcept {

    r.print("running test case \"", make_colored(id.name, r.with_color, color::highlight1), "\"\n");

    for (auto& section : sections) {
        r.print(
            "          in section \"",
            make_colored(section.id.name, r.with_color, color::highlight1), "\"\n");
    }

    r.print(
        "          ", locatation_label(location.type), " ", location.file, ":", location.line,
        "\n");

    if (!id.type.empty()) {
        r.print(
            "          for type ", make_colored(id.type, r.with_color, color::highlight1), "\n");
    }

    for (auto& capture : captures) {
        r.print("          with ", make_colored(capture, r.with_color, color::highlight1), "\n");
    }
}

void print_message(const registry& r, const assertion_data& data) {
    constexpr auto indent = "          "sv;
    std::visit(
        overload{
            [&](std::string_view message) {
                r.print(indent, make_colored(message, r.with_color, color::highlight2), "\n");
            },
            [&](const expression_info& exp) {
                small_string<max_message_length> message_buffer;
                append_or_truncate(message_buffer, exp.type, "(", exp.expected, ")");
                r.print(
                    indent, make_colored(message_buffer.str(), r.with_color, color::highlight2));

                constexpr std::size_t long_line_threshold = 64;
                if (!exp.actual.empty()) {
                    if (exp.expected.size() + exp.type.size() + 3 > long_line_threshold ||
                        exp.actual.size() + 5 > long_line_threshold) {
                        r.print(
                            "\n", indent,
                            "got: ", make_colored(exp.actual, r.with_color, color::highlight2),
                            "\n");
                    } else {
                        r.print(
                            ", got: ", make_colored(exp.actual, r.with_color, color::highlight2),
                            "\n");
                    }
                } else {
                    r.print("\n");
                }
            }},
        data);
}
} // namespace

reporter::reporter(registry&) noexcept {}

bool reporter::configure(registry& r, std::string_view option, std::string_view value) noexcept {
    if (option == "color") {
        parse_color_option(r, value);
        return true;
    }
    if (option == "colour-mode") {
        parse_colour_mode_option(r, value);
        return true;
    }

    return false;
}

void reporter::report(const registry& r, const event::data& event) noexcept {
    std::visit(
        snitch::overload{
            [&](const snitch::event::test_run_started& e) {
                r.print(
                    make_colored("starting ", r.with_color, color::highlight2),
                    make_colored(e.name, r.with_color, color::highlight1),
                    make_colored(" with ", r.with_color, color::highlight2),
                    make_colored(
                        "snitch v" SNITCH_FULL_VERSION "\n", r.with_color, color::highlight1));
                r.print("==========================================\n");
            },
            [&](const snitch::event::test_run_ended& e) {
                r.print("==========================================\n");

                if (e.success) {
                    r.print(
                        make_colored("success:", r.with_color, color::pass), " all tests passed (",
                        e.run_count, " test cases, ", e.assertion_count, " assertions");
                } else {
                    r.print(
                        make_colored("error:", r.with_color, color::fail), " ",
                        (e.fail_count == e.run_count ? "all" : "some"), " tests failed (",
                        e.fail_count, " out of ", e.run_count, " test cases, ", e.assertion_count,
                        " assertions");
                }

                if (e.skip_count > 0) {
                    r.print(", ", e.skip_count, " test cases skipped");
                }

#if SNITCH_WITH_TIMINGS
                r.print(", ", e.duration, " seconds");
#endif

                r.print(")\n");
            },
            [&](const snitch::event::test_case_started& e) {
                small_string<max_test_name_length> full_name;
                make_full_name(full_name, e.id);

                r.print(
                    make_colored("starting:", r.with_color, color::status), " ",
                    make_colored(full_name, r.with_color, color::highlight1), " at ",
                    e.location.file, ":", e.location.line, "\n");
            },
            [&](const snitch::event::test_case_ended& e) {
                small_string<max_test_name_length> full_name;
                make_full_name(full_name, e.id);

#if SNITCH_WITH_TIMINGS
                r.print(
                    make_colored("finished:", r.with_color, color::status), " ",
                    make_colored(full_name, r.with_color, color::highlight1), " (", e.duration,
                    "s)\n");
#else
                r.print(
                    make_colored("finished:", r.with_color, color::status), " ",
                    make_colored(full_name, r.with_color, color::highlight1), "\n");
#endif
            },
            [&](const snitch::event::section_started& e) {
                r.print(
                    make_colored("entering section:", r.with_color, color::status), " ",
                    make_colored(e.id.name, r.with_color, color::highlight1), " at ",
                    e.location.file, ":", e.location.line, "\n");
            },
            [&](const snitch::event::section_ended& e) {
                r.print(
                    make_colored("leaving section:", r.with_color, color::status), " ",
                    make_colored(e.id.name, r.with_color, color::highlight1), "\n");
            },
            [&](const snitch::event::test_case_skipped& e) {
                r.print(make_colored("skipped: ", r.with_color, color::skipped));
                print_location(r, e.id, e.sections, e.captures, e.location);
                r.print(
                    "          ", make_colored(e.message, r.with_color, color::highlight2), "\n");
            },
            [&](const snitch::event::assertion_failed& e) {
                if (e.expected) {
                    r.print(make_colored("expected failure: ", r.with_color, color::pass));
                } else if (e.allowed) {
                    r.print(make_colored("allowed failure: ", r.with_color, color::pass));
                } else {
                    r.print(make_colored("failed: ", r.with_color, color::fail));
                }
                print_location(r, e.id, e.sections, e.captures, e.location);
                print_message(r, e.data);
            },
            [&](const snitch::event::assertion_succeeded& e) {
                r.print(make_colored("passed: ", r.with_color, color::pass));
                print_location(r, e.id, e.sections, e.captures, e.location);
                print_message(r, e.data);
            },
            [&](const snitch::event::list_test_run_started&) {
                r.print("Matching test cases:\n");
                counter = 0;
            },
            [&](const snitch::event::list_test_run_ended&) {
                r.print(counter, " matching test cases\n");
            },
            [&](const snitch::event::test_case_listed& e) {
                small_string<max_test_name_length> full_name;
                ++counter;
                make_full_name(full_name, e.id);
                r.print("  ", full_name, "\n");
                if (!e.id.tags.empty()) {
                    r.print("      ", e.id.tags, "\n");
                }
            }},
        event);
}
} // namespace snitch::reporter::console

SNITCH_REGISTER_REPORTER("console", snitch::reporter::console::reporter);

#endif

#if defined(SNITCH_IMPLEMENTATION)

#if SNITCH_WITH_TEAMCITY_REPORTER || SNITCH_WITH_ALL_REPORTERS


#    include <initializer_list>

namespace snitch::reporter::teamcity {
namespace {
struct assertion {
    const snitch::assertion_location& location;
    const snitch::section_info&       sections;
    const snitch::capture_info&       captures;
    const snitch::assertion_data&     data;
};

struct key_value {
    std::string_view                          key;
    std::variant<std::string_view, assertion> value;
};

bool escape(small_string_span string) noexcept {
    return escape_all_or_truncate(string, "|", "||") && escape_all_or_truncate(string, "'", "|'") &&
           escape_all_or_truncate(string, "\n", "|n") &&
           escape_all_or_truncate(string, "\r", "|r") &&
           escape_all_or_truncate(string, "[", "|[") && escape_all_or_truncate(string, "]", "|]");
}

template<typename T>
std::string_view make_escaped(small_string_span buffer, const T& value) noexcept {
    buffer.clear();
    append_or_truncate(buffer, value);
    escape(buffer);
    return std::string_view{buffer.data(), buffer.size()};
}

void print_assertion(const registry& r, const assertion& msg) noexcept {
    small_string<max_message_length> buffer;

    r.print("'", make_escaped(buffer, msg.location.file), ":", msg.location.line, "|n");
    for (const auto& c : msg.captures) {
        r.print("with ", make_escaped(buffer, c), "|n");
    }

    constexpr std::string_view indent = "  ";

    std::visit(
        overload{
            [&](std::string_view message) { r.print(indent, make_escaped(buffer, message), "'"); },
            [&](const snitch::expression_info& exp) {
                r.print(indent, exp.type, "(", make_escaped(buffer, exp.expected), ")");

                constexpr std::size_t long_line_threshold = 64;
                if (!exp.actual.empty()) {
                    if (exp.expected.size() + exp.type.size() + 3 > long_line_threshold ||
                        exp.actual.size() + 5 > long_line_threshold) {
                        r.print("|n", indent, "got: ", make_escaped(buffer, exp.actual), "'");
                    } else {
                        r.print(", got: ", make_escaped(buffer, exp.actual), "'");
                    }
                } else {
                    r.print("'");
                }
            }},
        msg.data);
}

void send_message(
    const registry& r, std::string_view message, std::initializer_list<key_value> args) noexcept {
    constexpr std::string_view teamcity_header = "##teamCity[";
    constexpr std::string_view teamcity_footer = "]\n";

    r.print(teamcity_header, message);
    for (const auto& arg : args) {
        r.print(" ", arg.key, "=");
        std::visit(
            snitch::overload{
                [&](std::string_view msg) { r.print("'", msg, "'"); },
                [&](const assertion& msg) { print_assertion(r, msg); }},
            arg.value);
    }
    r.print(teamcity_footer);
}

small_string<max_message_length>
make_suite_name(std::string_view app, const filter_info& filters) noexcept {
    small_string<max_message_length> name;
    append_or_truncate(name, app);
    for (const auto& filter : filters) {
        append_or_truncate(name, " \"", filter, "\"");
    }
    escape(name);
    return name;
}

small_string<max_test_name_length> make_full_name(const test_id& id) noexcept {
    small_string<max_test_name_length> name;
    snitch::impl::make_full_name(name, id);
    escape(name);
    return name;
}

constexpr std::size_t max_duration_length = 32;

#    if SNITCH_WITH_TIMINGS
small_string<max_duration_length> make_duration(float duration) noexcept {
    small_string<max_duration_length> string;
    append_or_truncate(string, static_cast<std::size_t>(duration * 1e6f));
    return string;
}
#    endif
} // namespace

void initialize(registry& r) noexcept {
    // TeamCity needs test_case_started and test_case_ended events, which are only printed on
    // verbosity 'high', so ensure the requested verbosity is at least as much.
    r.verbose = r.verbose < registry::verbosity::high ? registry::verbosity::high : r.verbose;
}

void report(const registry& r, const snitch::event::data& event) noexcept {
    std::visit(
        snitch::overload{
            [&](const snitch::event::test_run_started& e) {
                send_message(r, "testSuiteStarted", {{"name", make_suite_name(e.name, e.filters)}});
            },
            [&](const snitch::event::test_run_ended& e) {
                send_message(
                    r, "testSuiteFinished", {{"name", make_suite_name(e.name, e.filters)}});
            },
            [&](const snitch::event::test_case_started& e) {
                send_message(r, "testStarted", {{"name", make_full_name(e.id)}});
            },
            [&](const snitch::event::test_case_ended& e) {
#    if SNITCH_WITH_TIMINGS
                send_message(
                    r, "testFinished",
                    {{"name", make_full_name(e.id)}, {"duration", make_duration(e.duration)}});
#    else
                send_message(r, "testFinished", {{"name", make_full_name(e.id)}});
#    endif
            },
            [&](const snitch::event::section_started& e) {
                send_message(
                    r, "blockOpened", {{"name", e.id.name}, {"description", e.id.description}});
            },
            [&](const snitch::event::section_ended& e) {
                send_message(r, "blockClosed", {{"name", e.id.name}});
            },
            [&](const snitch::event::test_case_skipped& e) {
                send_message(
                    r, "testIgnored",
                    {{"name", make_full_name(e.id)},
                     {"message", assertion{e.location, e.sections, e.captures, e.message}}});
            },
            [&](const snitch::event::assertion_failed& e) {
                send_message(
                    r, e.expected || e.allowed ? "testStdOut" : "testFailed",
                    {{"name", make_full_name(e.id)},
                     {e.expected || e.allowed ? "out" : "message",
                      assertion{e.location, e.sections, e.captures, e.data}}});
            },
            [&](const snitch::event::assertion_succeeded& e) {
                send_message(
                    r, "testStdOut",
                    {{"name", make_full_name(e.id)},
                     {"out", assertion{e.location, e.sections, e.captures, e.data}}});
            },
            [&](const snitch::event::list_test_run_started&) {},
            [&](const snitch::event::list_test_run_ended&) {},
            [&](const snitch::event::test_case_listed& e) { r.print(make_full_name(e.id), "\n"); }},
        event);
}
} // namespace snitch::reporter::teamcity

SNITCH_REGISTER_REPORTER_CALLBACKS(
    "teamcity",
    &snitch::reporter::teamcity::initialize,
    {},
    &snitch::reporter::teamcity::report,
    {});

#endif

#endif

#if defined(SNITCH_IMPLEMENTATION)


#if SNITCH_WITH_EXCEPTIONS
#    include <exception>
#endif

namespace snitch::impl {
section_entry_checker::~section_entry_checker() {
    auto& sections = state.info.sections;

    if (entered) {
#if SNITCH_WITH_EXCEPTIONS
        if (std::uncaught_exceptions() > 0 && !state.held_info.has_value()) {
            // We are unwinding the stack because an exception has been thrown;
            // keep a copy of the full section state since we will want to preserve the information
            // when reporting the exception.
            state.held_info = state.info;
        }
#endif

        pop_location(state);

        bool last_entry = false;
        if (sections.depth == sections.levels.size()) {
            // We just entered this section, and there was no child section in it.
            // This is a leaf; flag that a leaf has been executed so that no other leaf
            // is executed in this run.
            // Note: don't pop this level from the section state yet, it may have siblings
            // that we don't know about yet. Popping will be done when we exit from the parent,
            // since then we will know if there is any sibling.
            sections.leaf_executed = true;
            last_entry             = true;
        } else {
            // Check if there is any child section left to execute, at any depth below this one.
            bool no_child_section_left = true;
            for (std::size_t c = sections.depth; c < sections.levels.size(); ++c) {
                auto& child = sections.levels[c];
                if (child.previous_section_id != child.max_section_id) {
                    no_child_section_left = false;
                    break;
                }
            }

            if (no_child_section_left) {
                // No more children, we can pop this level and never go back.
                sections.levels.pop_back();
                last_entry = true;
            }
        }

        // Emit the section end event (only on last entry, and only if no exception in flight).
#if SNITCH_WITH_EXCEPTIONS
        if (last_entry && std::uncaught_exceptions() == 0)
#else
        if (last_entry)
#endif
        {
            registry::report_section_ended(sections.current_section.back());
        }

        sections.current_section.pop_back();
    }

    --sections.depth;
}

section_entry_checker::operator bool() {
#if SNITCH_WITH_EXCEPTIONS
    if (std::uncaught_exceptions() == 0) {
        notify_exception_handled();
    }
#endif

    auto& sections = state.info.sections;

    if (sections.depth >= sections.levels.size()) {
        if (sections.depth >= max_nested_sections) {
            using namespace snitch::impl;
            state.reg.print(
                make_colored("error:", state.reg.with_color, color::fail),
                " max number of nested sections reached; "
                "please increase 'SNITCH_MAX_NESTED_SECTIONS' (currently ",
                max_nested_sections, ")\n.");
            assertion_failed("max number of nested sections reached");
        }

        sections.levels.push_back({});
    }

    ++sections.depth;

    auto& level = sections.levels[sections.depth - 1];

    ++level.current_section_id;
    if (level.current_section_id > level.max_section_id) {
        level.max_section_id = level.current_section_id;
    }

    if (sections.leaf_executed) {
        // We have already executed another leaf section; can't execute more
        // on this run, so don't bother going inside this one now.
        return false;
    }

    const bool previous_was_preceeding_sibling =
        level.current_section_id == level.previous_section_id + 1;
    const bool children_remaining_in_self = level.current_section_id == level.previous_section_id &&
                                            sections.depth < sections.levels.size();

    if (!previous_was_preceeding_sibling && !children_remaining_in_self) {
        // Skip this section if:
        //  - The section entered in the previous run was not its immediate previous sibling, and
        //  - This section was not already entered in the previous run with remaining children.
        return false;
    }

    // Entering this section.

    // Push new section on the stack.
    level.previous_section_id = level.current_section_id;
    sections.current_section.push_back(
#if SNITCH_WITH_TIMINGS
        section{.id = id, .location = location, .start_time = get_current_time()}
#else
        section{.id = id, .location = location}
#endif
    );

    push_location(state, {location.file, location.line, location_type::section_scope});
    entered = true;

    // Emit the section start event (only on first entry).
    if (previous_was_preceeding_sibling) {
        registry::report_section_started(sections.current_section.back());
    }

    return true;
}
} // namespace snitch::impl

#endif

#if defined(SNITCH_IMPLEMENTATION)


#include <algorithm> // for std::rotate, std::copy

namespace snitch {
namespace {
std::size_t
replace_same_size(small_string_span string, std::size_t pos, std::string_view replacement) {
    std::copy(replacement.begin(), replacement.end(), string.begin() + pos);
    pos += replacement.size();
    return pos;
}

std::size_t replace_smaller(
    small_string_span string,
    std::size_t       char_diff,
    std::size_t       pos,
    std::string_view  replacement) {

    // Shift data after the replacement to the left to fill the gap
    std::rotate(string.begin() + pos, string.begin() + pos + char_diff, string.end());
    string.resize(string.size() - char_diff);

    // Replace pattern by replacement
    std::copy(replacement.begin(), replacement.end(), string.begin() + pos);
    pos += replacement.size();

    return pos;
}

std::size_t replace_larger(
    small_string_span string,
    std::size_t       char_diff,
    std::size_t       pos,
    std::string_view  replacement) {

    // Shift data after the pattern to the right to make room for the replacement
    const std::size_t char_growth = std::min(char_diff, string.available());
    string.grow(char_growth);

    if (char_diff <= string.size() && string.size() - char_diff > pos) {
        std::rotate(string.begin() + pos, string.end() - char_diff, string.end());
    }

    // Replace pattern by replacement
    const std::size_t max_chars = std::min(replacement.size(), string.size() - pos);
    std::copy(replacement.begin(), replacement.begin() + max_chars, string.begin() + pos);
    pos += max_chars;

    return pos;
}

} // namespace

bool replace_all(
    small_string_span string, std::string_view pattern, std::string_view replacement) noexcept {

    if (replacement.size() == pattern.size()) {
        std::string_view sv(string.begin(), string.size());
        auto             pos = sv.find(pattern);

        while (pos != sv.npos) {
            // Replace pattern by replacement
            pos = replace_same_size(string, pos, replacement);

            // Find next occurrence
            pos = sv.find(pattern, pos);
        }

        return true;
    } else if (replacement.size() < pattern.size()) {
        const std::size_t char_diff = pattern.size() - replacement.size();
        std::string_view  sv(string.begin(), string.size());
        auto              pos = sv.find(pattern);

        while (pos != sv.npos) {
            // Replace pattern by replacement
            pos = replace_smaller(string, char_diff, pos, replacement);

            // Find next occurrence
            sv  = {string.begin(), string.size()};
            pos = sv.find(pattern, pos);
        }

        return true;
    } else {
        const std::size_t char_diff = replacement.size() - pattern.size();
        std::string_view  sv(string.begin(), string.size());
        auto              pos      = sv.find(pattern);
        bool              overflow = false;

        while (pos != sv.npos) {
            if (char_diff > string.available()) {
                overflow = true;
            }

            // Replace pattern by replacement
            pos = replace_larger(string, char_diff, pos, replacement);

            // Find next occurrence
            sv  = {string.begin(), string.size()};
            pos = sv.find(pattern, pos);
        }

        return !overflow;
    }
}

bool escape_all_or_truncate(
    small_string_span string, std::string_view pattern, std::string_view replacement) {

    if (replacement.size() <= pattern.size()) {
        assertion_failed("escape_all() requires a replacement that is longer than the pattern");
    }

    const std::size_t char_diff = replacement.size() - pattern.size();
    std::string_view  sv(string.begin(), string.size());
    auto              pos           = sv.find(pattern);
    auto              last_full_pos = sv.size();
    bool              overflow      = false;

    constexpr std::size_t num_dots = 3u;

    while (pos != sv.npos) {
        if (string.capacity() - pos >= num_dots) {
            last_full_pos = pos;
        }

        if (char_diff > string.available()) {
            overflow = true;
        }

        // Replace pattern by replacement
        pos = replace_larger(string, char_diff, pos, replacement);

        if (string.capacity() - pos >= num_dots) {
            last_full_pos = pos;
        }

        // Find next occurrence
        sv  = {string.begin(), string.size()};
        pos = sv.find(pattern, pos);
    }

    if (overflow) {
        // Truncate to a suitable position, avoiding to truncate the replacement in half
        // (which could result in incorrectly escaped data).
        string.resize(last_full_pos);
        truncate_end(string);
    }

    return !overflow;
}

std::size_t find_first_not_escaped(std::string_view str, char c) noexcept {
    for (std::size_t i = 0; i < str.size(); ++i) {
        bool escaped = false;
        if (str[i] == '\\') {
            // Escaped character, look ahead by one
            ++i;
            if (i >= str.size()) {
                break;
            }

            escaped = true;
        }

        if (!escaped && str[i] == c) {
            return i;
        }
    }

    return std::string_view::npos;
}

bool is_match(std::string_view string, std::string_view regex) noexcept {
    // An empty regex matches any string; early exit.
    // An empty string matches an empty regex (exit here) or any regex containing
    // only wildcards (exit later).
    if (regex.empty()) {
        return true;
    }

    const std::size_t regex_size  = regex.size();
    const std::size_t string_size = string.size();

    // Iterate characters of the regex string and exit at first non-match.
    std::size_t js = 0;
    for (std::size_t jr = 0; jr < regex_size; ++jr, ++js) {
        bool escaped = false;
        if (regex[jr] == '\\') {
            // Escaped character, look ahead ignoring special characters.
            ++jr;
            if (jr >= regex_size) {
                // Nothing left to escape; the regex is ill-formed.
                return false;
            }

            escaped = true;
        }

        if (!escaped && regex[jr] == '*') {
            // Wildcard is found; if this is the last character of the regex
            // then any further content will be a match; early exit.
            if (jr == regex_size - 1) {
                return true;
            }

            // Discard what has already been matched.
            regex = regex.substr(jr + 1);

            // If there are no more characters in the string after discarding, then we only match if
            // the regex contains only wildcards from there on.
            const std::size_t remaining = string_size >= js ? string_size - js : 0u;
            if (remaining == 0u) {
                return regex.find_first_not_of('*') == regex.npos;
            }

            // Otherwise, we loop over all remaining characters of the string and look
            // for a match when starting from each of them.
            for (std::size_t o = 0; o < remaining; ++o) {
                if (is_match(string.substr(js + o), regex)) {
                    return true;
                }
            }

            return false;
        } else if (js >= string_size || regex[jr] != string[js]) {
            // Regular character is found; not a match if not an exact match in the string.
            return false;
        }
    }

    // We have finished reading the regex string and did not find either a definite non-match
    // or a definite match. This means we did not have any wildcard left, hence that we need
    // an exact match. Therefore, only match if the string size is the same as the regex.
    return js == string_size;
}
} // namespace snitch

#endif

#if defined(SNITCH_IMPLEMENTATION)


#if SNITCH_WITH_EXCEPTIONS
#    include <exception>
#endif

namespace snitch::impl {
namespace {
SNITCH_THREAD_LOCAL test_state* thread_current_test = nullptr;
}

test_state& get_current_test() noexcept {
    test_state* current = thread_current_test;
    if (current == nullptr) {
        terminate_with("no test case is currently running on this thread");
    }

    return *current;
}

test_state* try_get_current_test() noexcept {
    return thread_current_test;
}

void set_current_test(test_state* current) noexcept {
    thread_current_test = current;
}

void push_location(test_state& test, const assertion_location& location) noexcept {
    test.info.locations.push_back(location);
}

void pop_location(test_state& test) noexcept {
    test.info.locations.pop_back();
}

scoped_test_check::scoped_test_check(const source_location& location) noexcept :
    test(get_current_test()) {

#if SNITCH_WITH_EXCEPTIONS
    if (std::uncaught_exceptions() == 0) {
        notify_exception_handled();
    }
#endif

    push_location(test, {location.file, location.line, location_type::in_check});
    test.in_check = true;
}

scoped_test_check::~scoped_test_check() noexcept {
    test.in_check = false;

#if SNITCH_WITH_EXCEPTIONS
    if (std::uncaught_exceptions() > 0 && !test.held_info.has_value()) {
        // We are unwinding the stack because an exception has been thrown;
        // keep a copy of the full location state since we will want to preserve the information
        // when reporting the exception.
        test.held_info = test.info;
    }
#endif

    pop_location(test);
}
} // namespace snitch::impl

namespace snitch {
#if SNITCH_WITH_EXCEPTIONS
void notify_exception_handled() noexcept {
    auto& state = impl::get_current_test();
    if (!state.held_info.has_value()) {
        return;
    }

    // Close all sections that were left open by the exception.
    auto&       current_held_section = state.held_info.value().sections.current_section;
    const auto& current_section      = state.info.sections.current_section;
    while (current_held_section.size() > current_section.size()) {
        registry::report_section_ended(current_held_section.back());
        current_held_section.pop_back();
    }

    state.held_info.reset();
}
#endif
} // namespace snitch

#endif

#if defined(SNITCH_IMPLEMENTATION)

#if SNITCH_WITH_TIMINGS
#    include <chrono>

namespace snitch {
namespace impl {
using clock           = std::chrono::steady_clock;
using tick_resolution = std::chrono::nanoseconds;
} // namespace impl

time_point_t get_current_time() noexcept {
    static auto start_time = impl::clock::now();
    return static_cast<time_point_t>(
        std::chrono::duration_cast<impl::tick_resolution>(impl::clock::now() - start_time).count());
}

float get_duration_in_seconds(time_point_t start, time_point_t end) noexcept {
    return std::chrono::duration_cast<std::chrono::duration<float>>(
               impl::tick_resolution(end - start))
        .count();
}
} // namespace snitch
#endif

#endif

#endif
