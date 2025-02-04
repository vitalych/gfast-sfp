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

#ifndef __GFAST_PCAP_H__

#define __GFAST_PCAP_H__

#include <inttypes.h>
#include <memory.h>
#include <string>

#include <sys/time.h>
#include <unistd.h>

#include "utils.h"

struct pcap_file_header {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;  /* gmt to local correction; this is always 0 */
    uint32_t sigfigs;  /* accuracy of timestamps; this is always 0 */
    uint32_t snaplen;  /* max length saved portion of each pkt */
    uint32_t linktype; /* data link type (LINKTYPE_*) */
};

struct pcap_pkthdr {
    uint32_t sec;
    uint32_t usec;
    uint32_t caplen; /* length of portion present */
    uint32_t len;    /* length of this packet (off wire) */
};

class PCAPWriter;
using PCAPWriterPtr = std::shared_ptr<PCAPWriter>;

class PCAPWriter {
private:
    safefd_ptr_t m_file;

    PCAPWriter(safefd_ptr_t fd) : m_file(fd) {
    }

    int write_header() {
        pcap_file_header hdr;
        hdr.magic = 0xa1b2c3d4;
        hdr.version_major = 2;
        hdr.version_minor = 4;
        hdr.thiszone = 0;
        hdr.sigfigs = 0;
        hdr.snaplen = 65535; //(2^16)
        hdr.linktype = 1;    // Ethernet

        return ::write(m_file.get()->fd, &hdr, sizeof(hdr));
    }

public:
    static PCAPWriterPtr create(const std::string &file_path) {
        auto file = safefd_t::open(file_path.c_str());
        if (!file) {
            return nullptr;
        }

        auto ret = PCAPWriterPtr(new PCAPWriter(file));

        if (ret->write_header() < 0) {
            return nullptr;
        }

        return ret;
    }

    int write_packet(const void *packet, size_t size) {
        pcap_pkthdr pkt;
        pkt.caplen = size;
        pkt.len = size;

        struct timeval ts;
        gettimeofday(&ts, nullptr);

        pkt.sec = ts.tv_sec;
        pkt.usec = ts.tv_usec;

        auto ret = ::write(m_file.get()->fd, &pkt, sizeof(pkt));
        if (ret < 0) {
            return -1;
        }

        return ::write(m_file.get()->fd, packet, size);
    }
};

#endif
