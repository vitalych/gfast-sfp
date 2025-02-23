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

#ifndef __GFAST_ARGS_H__

#define __GFAST_ARGS_H__

#include <optional>
#include <string>
#include <vector>

#include "log.h"

using raw_args_t = std::vector<std::string>;

struct args_t {
    bool help = false;
    log::level_t log_level = log::debug;
    std::string iface;
    std::string firmware_path;
    std::string hwaddr = "00:0e:ad:33:44:56";
    std::optional<std::string> pcap_path;
};

std::optional<std::string> get_arg(const raw_args_t &args, const std::string &arg_name) {
    for (auto it = args.begin(), end = args.end(); it != end; ++it) {
        if (*it == arg_name) {
            if (it + 1 != end) {
                return *(it + 1);
            }
        }
    }

    return std::nullopt;
}

std::optional<std::string> get_pos_arg(const raw_args_t &args) {
    auto it = args.rbegin();
    if (it == args.rend()) {
        return std::nullopt;
    }
    if ((*it).starts_with("--")) {
        return std::nullopt;
    }
    return *it;
}

static std::optional<args_t> parse_args(const raw_args_t &args) {
    auto ret = args_t();

    ret.help = std::find(args.begin(), args.end(), "--help") != args.end();
    auto log_level = get_arg(args, "--log-level");
    auto iface = get_arg(args, "--iface");
    auto firmware_path = get_pos_arg(args);
    auto hwaddr = get_arg(args, "--hwaddr");
    ret.pcap_path = get_arg(args, "--pcap-path");

    if (log_level.has_value()) {
        auto level = log::str_to_level(log_level.value());
        if (level) {
            ret.log_level = level.value();
        } else {
            log::log(log::error, "invalid level {}", log_level.value());
            return std::nullopt;
        }
    }

    if (hwaddr) {
        ret.hwaddr = hwaddr.value();
    }

    if (!iface) {
        log::log(log::error, "interface name must be specified (e.g., --iface eth0)");
        return std::nullopt;
    }
    ret.iface = iface.value();

    if (!firmware_path) {
        log::log(log::error, "firmware path must be specified");
        return std::nullopt;
    }
    ret.firmware_path = firmware_path.value();

    return ret;
}

#endif
