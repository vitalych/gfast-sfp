///
/// Copyright (C) 2025 Vitaly Chipounov
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#ifndef __GFAST_LOG_H__

#define __GFAST_LOG_H__

#include <chrono>
#include <format>
#include <iostream>
#include <istream>
#include <source_location>
#include <string>

namespace log {

enum level_t {
    trace = 0,
    debug,
    info,
    warn,
    error,
};

extern level_t g_log_level;

static const std::array<std::string, 5> s_levels = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR"};

static constexpr std::string level_to_str(level_t level) {
    return s_levels[level];
}

static inline std::optional<level_t> str_to_level(const std::string &token) {
    if (token == "trace") {
        return trace;
    } else if (token == "debug") {
        return debug;
    } else if (token == "info") {
        return info;
    } else if (token == "warn") {
        return warn;
    } else if (token == "error") {
        return error;
    }
    return std::nullopt;
}

struct format_string {
    std::string_view str;
    std::source_location loc;

    format_string(const char *str, const std::source_location &loc = std::source_location::current())
        : str(str), loc(loc) {
    }
};

static std::string truncate(const std::string &str, size_t width) {
    if (str.size() > width) {
        return "..." + str.substr(str.size() - width, str.size());
    }
    return str;
}

static inline void vlog(level_t level, const format_string &format, std::format_args args) {
    auto now = std::chrono::system_clock::now();

    const auto &loc = format.loc;
    std::println("[{0:%F}T{0:%R%z}][{1:5}][{2:16}:{3:3}] {4}", now, level_to_str(level), truncate(loc.file_name(), 16),
                 loc.line(), std::vformat(format.str, args));
}

template <typename... Args> static inline void log(level_t level, const format_string &format, Args &&...args) {
    if (level >= g_log_level) {
        vlog(level, format, std::make_format_args(args...));
    }
}

} // namespace log

#endif
