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

#ifndef __GFAST_TYPES_H__

#define __GFAST_TYPES_H__

#include <inttypes.h>

static const uint32_t EBM_ETH_TYPE = 0x6120;

// 14 bytes
struct __attribute__((packed)) packet_header_t {
    // 0x00
    uint8_t dest_addr[6];

    // 0x06
    uint8_t source_addr[6];

    // 0x0c
    uint16_t ether_type;
};

struct __attribute__((packed)) packet_header_vlan_t {
    // 0x00
    uint8_t source_addr[6];

    // 0x06
    uint8_t dest_addr[6];

    // 0x0c 0x0d 0xe 0xf
    uint32_t tag;

    // 0x10 0x11
    uint16_t ether_type;
};

// 6 bytes
struct __attribute__((packed)) packet_payload_header_t {
    // 0x0 0x1
    uint16_t seq_no;

    // 0x2 0x3
    uint16_t data_length;

    // 0x4 0x5
    uint16_t type;
};

struct __attribute__((packed)) packet_normal_t {
    // 0x00
    packet_header_t hdr;

    // 0x0e
    packet_payload_header_t payload_hdr;

    // 0x14
};

struct __attribute__((packed)) packet_vlan_t {
    // 0x00
    packet_header_vlan_t hdr;

    // 0x12
    packet_payload_header_t payload_hdr;

    // 0x18
};

struct __attribute__((packed)) packet_t {
    union {
        packet_normal_t norm;
        packet_vlan_t vlan;
    };
};

// 7 bytes
struct __attribute__((packed)) packet_access_header_t {
    // 0x0
    uint8_t type;

    // 0x1
    uint32_t seq_no;

    // 0x5 0x6
    uint16_t length;
};

struct __attribute__((packed)) packet_access_t {
    // 0x00
    packet_header_t hdr;

    // 0x0e
    packet_access_header_t access_hdr;
};

enum packet_type_t {
    ASSOCIATE = 0x01,
    ASSOCIATE_RESPONSE = 0x02,
    DOWNLOAD_BEGIN = 0x11,
    DOWNLOAD_FIRMWARE = 0x12,
    DOWNLOAD_CHECKSUM = 0x13,
    DOWNLOAD_ACK = 0x14
};

enum access_type_t {
    MSG_UNKNOWN = 0,
    MSG_READ_MEMORY = 1,
    MSG_WRITE_MEMORY = 2,
    MSG_READ_MIB = 6,
    MSG_WRITE_MIB = 7,
    MSG_SEARCH_DEVICE = 0x30,
    MSG_CONNECT = 0x31,
    MSG_REBOOT_UPGRADE = 0x33,
    MSG_CONSOLE_INPUT = 0x40,
    MSG_SDP_DISCONNECT = 0x50,
    MSG_CONSOLE_OUTPUT = 0x60,
    MSG_LOGGER_OUTPUT = 0x61,
    MSG_DEVICE_DISCONNECT = 0x70,
    MSG_READ_MEMORY_RESP = 0x81,
    MSG_WRITE_MEMORY_RESP = 0x82,
    MSG_READ_MIB_RESP = 0x86,
    MSG_WRITE_MIB_RESP = 0x87,
    MSG_SEARCH_DEVICE_RESP = 0xb0,
    MSG_CONNECT_RESP = 0xb1,
    MSG_DISCONNECT_RESP = 0xb2
};

struct oid_t {
    uint32_t oid[8];
};

#endif