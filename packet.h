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

#ifndef __GFAST_PACKET_H__

#define __GFAST_PACKET_H__

#include <inttypes.h>
#include <optional>
#include <stddef.h>
#include <vector>

// 14 bytes
struct __attribute__((packed)) eth_header_t {
    // 0x00
    uint8_t dest_addr[6];

    // 0x06
    uint8_t source_addr[6];

    // 0x0c
    uint16_t ether_type;
};

class packet_t {
private:
    std::vector<uint8_t> m_packet;
    mutable size_t m_read_offset = 0;

public:
    packet_t(size_t sz) : m_packet(sz) {
    }
    packet_t() {
    }

    void append(const uint8_t *data, size_t size) {
        m_packet.insert(m_packet.end(), data, data + size);
    }

    void append(uint32_t data) {
        auto bytes = (const uint8_t *) &data;
        m_packet.insert(m_packet.end(), bytes, bytes + sizeof(data));
    }

    void append(uint16_t data) {
        auto bytes = (const uint8_t *) &data;
        m_packet.insert(m_packet.end(), bytes, bytes + sizeof(data));
    }

    void append(uint8_t data) {
        auto bytes = (const uint8_t *) &data;
        m_packet.insert(m_packet.end(), bytes, bytes + sizeof(data));
    }

    void append(bool data) {
        auto byte = (const uint8_t)(data ? 1 : 0);
        m_packet.insert(m_packet.end(), &byte, &byte + sizeof(byte));
    }

    template <typename T> void append(const T *data) {
        auto bytes = (const uint8_t *) data;
        m_packet.insert(m_packet.end(), bytes, bytes + sizeof(T));
    }

    template <typename T> std::optional<T> read(bool do_ntoh) const {
        if ((m_read_offset + sizeof(T)) > m_packet.size()) {
            return std::nullopt;
        }
        auto ret = *(T *) &m_packet[m_read_offset];
        m_read_offset += sizeof(T);

        if (do_ntoh && std::endian::native != std::endian::big) {
            ret = std::byteswap(ret);
        }

        return ret;
    }

    template <typename T> bool read(T *dest, size_t offset) const {
        if ((offset + sizeof(T)) > m_packet.size()) {
            return false;
        }
        memcpy((uint8_t *) dest, m_packet.data() + offset, sizeof(T));
        return true;
    }

    bool read(std::vector<uint8_t> &buffer, size_t size) const {
        if ((m_read_offset + size) > m_packet.size()) {
            return false;
        }

        buffer.insert(buffer.end(), m_packet.begin() + m_read_offset, m_packet.begin() + m_read_offset + size);

        m_read_offset += size;
        return true;
    }

    bool read_str(std::string &str, size_t size) const {
        if ((m_read_offset + size) > m_packet.size()) {
            return false;
        }

        str = std::string(m_packet.begin() + m_read_offset, m_packet.begin() + m_read_offset + size);

        m_read_offset += size;
        return true;
    }

    bool seek(size_t offset) {
        if (offset >= m_packet.size()) {
            return false;
        }

        m_read_offset = offset;
        return true;
    }

    template <typename... Args> bool read(Args &&...args) const {
        bool ret = true;
        auto rd = [this, &ret](auto *arg) {
            ret &= this->read(arg, this->m_read_offset);
            if (ret) {
                this->m_read_offset += sizeof(*arg);
            }
        };

        (rd(args), ...);
        return ret;
    }

    const std::vector<uint8_t> &get() const {
        return m_packet;
    }

    std::vector<uint8_t> &get() {
        return m_packet;
    }

    void resize(size_t new_size) {
        m_packet.resize(new_size);
    }

    void clear() {
        m_packet.clear();
    }

    size_t size() const {
        return m_packet.size();
    }

    uint8_t *data() {
        return m_packet.data();
    }
};

#endif
