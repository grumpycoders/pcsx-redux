#pragma once

#include <algorithm>
#include <array>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace CommandLine {
namespace detail {
using argument_map =
    std::multimap<std::string_view, std::optional<std::string_view>>;

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
  const std::vector<std::string_view>& positional_arguments() const {
    return positional_arguments_;
  }

 private:
  // Advance the state machine for the current token.
  void churn(const std::string_view& item) {
    item.at(0) == '-' ? on_option(item) : on_value(item);
  }

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
    if (const auto delimiter = current_option_->find_first_of('=');
        delimiter != std::string_view::npos) {
      auto value = *current_option_;
      value.remove_prefix(delimiter + 1 /* skip '=' */);
      current_option_->remove_suffix(current_option_->size() - delimiter);
      on_value(value);
    }
  }

  void on_value(const std::optional<std::string_view>& value = std::nullopt) {
    // If there's not an option preceding the value, it's a positional argument.
    if (!current_option_) {
      if (value) positional_arguments_.emplace_back(*value);
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
inline std::optional<std::string_view> get_value(
    const argument_map& options, const std::string_view& option) {
  if (const auto it = options.find(option); it != options.end()) {
    return it->second;
  }
  return std::nullopt;
}

// Return a vector of string views.
inline std::vector<std::string_view> get_values(
    const argument_map& options, const std::string_view& option) {
    std::vector<std::string_view> values;
    for (auto & opt : options) {
        if ((opt.first == option) && (opt.second.has_value())) {
            values.emplace_back(opt.second.value());
        }
    }
    return values;
}

// Coerces the string value of the given option into <T>.
// If the value cannot be properly parsed or the key does not exist, returns
// nullopt.
template <class T>
std::optional<T> get(const argument_map& options,
                     const std::string_view& option) {
  if (const auto view = get_value(options, option)) {
    if (T value; std::istringstream(std::string(*view)) >> value) return value;
  }
  return std::nullopt;
}

// Since the values are already stored as strings, there's no need to use `>>`.
template <>
inline std::optional<std::string_view> get(const argument_map& options,
                                    const std::string_view& option) {
  return get_value(options, option);
}

template <>
inline std::optional<std::string> get(const argument_map& options,
                               const std::string_view& option) {
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
inline std::optional<bool> get(const argument_map& options,
                        const std::string_view& option) {
  if (const auto value = get_value(options, option)) {
    return std::none_of(falsities.begin(), falsities.end(),
                        [&value](auto falsity) { return *value == falsity; });
  }
  if (options.find(option) != options.end()) return true;
  return std::nullopt;
}

// Coerces the string value of the given positional index into <T>.
// If the value cannot be properly parsed or the key does not exist, returns
// nullopt.
template <class T>
std::optional<T> get(const std::vector<std::string_view>& positional_arguments,
                     size_t positional_index) {
  if (positional_index < positional_arguments.size()) {
    if (T value; std::istringstream(
                     std::string(positional_arguments[positional_index])) >>
                 value)
      return value;
  }
  return std::nullopt;
}

// Since the values are already stored as strings, there's no need to use `>>`.
template <>
inline std::optional<std::string_view> get(
    const std::vector<std::string_view>& positional_arguments,
    size_t positional_index) {
  if (positional_index < positional_arguments.size()) {
    return positional_arguments[positional_index];
  }
  return std::nullopt;
}

template <>
inline std::optional<std::string> get(
    const std::vector<std::string_view>& positional_arguments,
    size_t positional_index) {
  if (positional_index < positional_arguments.size()) {
    return std::string(positional_arguments[positional_index]);
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

  template <class T>
  std::optional<T> get(size_t positional_index) const {
    return detail::get<T>(parser_.positional_arguments(), positional_index);
  }

  template <class T>
  T get(size_t positional_index, T&& default_value) const {
    return get<T>(positional_index).value_or(default_value);
  }

  const std::vector<std::string_view>& positional() const {
    return parser_.positional_arguments();
  }

  std::vector<std::string_view> values(const std::string_view& option) const {
      return detail::get_values(parser_.options(), option);
  }

 private:
  const detail::parser parser_;
};

}  // namespace CommandLine
