#pragma once

#include <algorithm>
#include <array>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace flags {
namespace detail {
using argument_map = std::unordered_map<std::string_view, std::optional<std::string_view>>;

// Non-destructively parses the argv tokens.
// * If the token begins with a -, it will be considered an option.
// * If the token does not begin with a -, it will be considered a value for the
// previous option. If there was no previous option, it will be considered a
// positional argument.
struct parser {
    parser(const int argc, char** argv) {
        for (int i = 1; i < argc; ++i) {
            churn(argv[i]);
        }
        // If the last token was an option, it needs to be drained.
        flush();
    }
    parser& operator=(const parser&) = delete;

    const argument_map& options() const { return options_; }
    const std::vector<std::string_view>& positional_arguments() const { return positional_arguments_; }

  private:
    // Advance the state machine for the current token.
    void churn(const std::string_view& item) { item.at(0) == '-' ? on_option(item) : on_value(item); }

    // Consumes the current option if there is one.
    void flush() {
        if (current_option_) on_value();
    }

    void on_option(const std::string_view& option) {
        // Consume the current_option and reassign it to the new option while
        // removing all leading dashes.
        flush();
        current_option_ = option;
        current_option_->remove_prefix(current_option_->find_first_not_of('-'));

        // Handle a packed argument (--arg_name=value).
        const auto delimiter = current_option_->find_first_of('=');
        if (delimiter != std::string_view::npos) {
            auto value = *current_option_;
            value.remove_prefix(delimiter + 1 /* skip '=' */);
            current_option_->remove_suffix(current_option_->size() - delimiter);
            on_value(value);
        }
    }

    void on_value(const std::optional<std::string_view>& value = std::nullopt) {
        // If there's not an option preceding the value, it's a positional argument.
        if (!current_option_) {
            positional_arguments_.emplace_back(*value);
            return;
        }
        // Consume the preceding option and assign its value.
        options_.emplace(*current_option_, value);
        current_option_.reset();
    }

    std::optional<std::string_view> current_option_;
    argument_map options_;
    std::vector<std::string_view> positional_arguments_;
};

// If a key exists, return an optional populated with its value.
static inline std::optional<std::string_view> get_value(const argument_map& options, const std::string_view& option) {
    const auto it = options.find(option);
    return it != options.end() ? make_optional(*it->second) : std::nullopt;
}

// Coerces the string value of the given option into <T>.
// If the value cannot be properly parsed or the key does not exist, returns
// nullopt.
template <class T>
static std::optional<T> get(const argument_map& options, const std::string_view& option) {
    if (const auto view = get_value(options, option)) {
        T value;
        if (std::istringstream(std::string(*view)) >> value) return value;
    }
    return std::nullopt;
}

// Since the values are already stored as strings, there's no need to use `>>`.
template <>
std::optional<std::string_view> get(const argument_map& options, const std::string_view& option) {
    return get_value(options, option);
}

template <>
std::optional<std::string> get(const argument_map& options, const std::string_view& option) {
    if (const auto view = get<std::string_view>(options, option)) {
        return std::string(*view);
    }
    return std::nullopt;
}

// Special case for booleans: if the value is any of the below, the option will
// be considered falsy. Otherwise, it will be considered truthy just for being
// present.
constexpr std::array<const char*, 5> falsities{{"0", "n", "no", "f", "false"}};
template <>
std::optional<bool> get(const argument_map& options, const std::string_view& option) {
    if (const auto value = get_value(options, option)) {
        return std::none_of(falsities.begin(), falsities.end(), [&value](auto falsity) { return *value == falsity; });
    }
    return std::nullopt;
}
}  // namespace detail

struct args {
    args(const int argc, char** argv) : parser_(argc, argv) {}

    template <class T>
    std::optional<T> get(const std::string_view& option) const {
        return detail::get<T>(parser_.options(), option);
    }

    template <class T>
    T get(const std::string_view& option, T&& default_value) const {
        return get<T>(option).value_or(default_value);
    }

    const std::vector<std::string_view>& positional() const { return parser_.positional_arguments(); }

  private:
    const detail::parser parser_;
};

}  // namespace flags
