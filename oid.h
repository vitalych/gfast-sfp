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

#ifndef __GFAST_OID_H__

#define __GFAST_OID_H__

#include <any>
#include <inttypes.h>

namespace mgmt {

enum class oid_type_t : uint32_t {
    oid_uint32 = 0,
    oid_int32 = 1,
    oid_uint16 = 2,
    oid_int16 = 3,
    oid_uint8 = 4,
    oid_int8 = 5,
    oid_string = 6,
    oid_bool = 7,
    oid_invalid = 8
};

template <typename T> bool validate_oid_type(oid_type_t type) {
    switch (type) {
        case oid_type_t::oid_uint32:
            return std::is_same<uint32_t, T>::value;
        case oid_type_t::oid_int32:
            return std::is_same<int32_t, T>::value;
        case oid_type_t::oid_uint16:
            return std::is_same<uint16_t, T>::value;
        case oid_type_t::oid_int16:
            return std::is_same<int16_t, T>::value;
        case oid_type_t::oid_uint8:
            return std::is_same<uint8_t, T>::value;
        case oid_type_t::oid_int8:
            return std::is_same<int8_t, T>::value;
        case oid_type_t::oid_string:
            return std::is_same<std::string, T>::value;
        case oid_type_t::oid_bool:
            return std::is_same<bool, T>::value;
        case oid_type_t::oid_invalid:
            return false;
        default:
            return false;
    }
}

struct __attribute__((packed)) oid_req_t {
    uint32_t oid[3]; // +0*4
    uint32_t offset; // +3*4
    uint32_t length; // +4*4
    oid_type_t type; // +5*4
};

struct __attribute__((packed)) oid_t {
    oid_req_t req; // +0
};

struct oid_result_t {
    oid_req_t req;
    std::any data;
};

static oid_t oid_host_cmd = {
    .req =
        {
            .oid = {0xb, 0x1, 0x0},
            .offset = 0,
            .length = 1,
            .type = oid_type_t::oid_uint8,
        },
};

static oid_t oid_log_control = {
    .req =
        {
            .oid = {0xb, 0x11, 0x4},
            .offset = 0,
            .length = 1,
            .type = oid_type_t::oid_uint32,
        },
};

static oid_t oid_console_control = {
    .req =
        {
            .oid = {0xb, 0x11, 0x3},
            .offset = 0,
            .length = 1,
            .type = oid_type_t::oid_uint32,
        },
};

static oid_t oid_repeat_cmd = {
    .req =
        {
            .oid = {0xb, 0x1, 0x2},
            .offset = 0,
            .length = 1,
            .type = oid_type_t::oid_uint8,
        },
};

static oid_t oid_cmd_status = {
    .req =
        {
            .oid = {0xb, 0xa, 0x0},
            .offset = 0,
            .length = 1,
            .type = oid_type_t::oid_bool,
        },
};

static oid_t oid_ticks = {
    .req =
        {
            .oid = {11, 21, 0},
            .offset = 0,
            .length = 1,
            .type = oid_type_t::oid_uint32,
        },
};

} // namespace mgmt

#endif