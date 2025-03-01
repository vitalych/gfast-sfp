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

#ifndef __GFAST_NIC_H__

#define __GFAST_NIC_H__

#include <arpa/inet.h>
#include <errno.h>
#include <fstream>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <memory.h>
#include <memory>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "log.h"
#include "packet.h"
#include "pcap.h"
#include "utils.h"

static const uint32_t EBM_ETH_TYPE = 0x6120;

class nic_reader_writer_t;
using nic_reader_writer_ptr_t = std::shared_ptr<nic_reader_writer_t>;

class nic_reader_writer_t {
public:
    enum status_t { ok = 0, error, timeout };

private:
    std::string m_iface;
    macaddr_t m_macaddr;
    struct sockaddr_ll m_sa = {0};
    safefd_ptr_t m_fd;
    PCAPWriterPtr m_pcap;
    uint16_t m_ether_type;

    nic_reader_writer_t(const std::string &iface, uint16_t ether_type) : m_iface(iface), m_ether_type(ether_type) {
    }

    bool init() {
        log::log(log::info, "Opening raw socket for {}", m_iface);

        m_fd = safefd_t::socket(PF_PACKET, SOCK_RAW, m_ether_type);
        if (!m_fd) {
            log::log(log::error, "Could not open socket: {}", errno);
            return false;
        }

        auto fd = m_fd.get()->fd;

        struct ifreq req;

        memset(&req, 0, sizeof(req));
        strncpy(req.ifr_ifrn.ifrn_name, m_iface.c_str(), IFNAMSIZ);

        int res = ioctl(fd, SIOCGIFFLAGS, &req);
        if (res < 0) {
            log::log(log::error, "Could not read mac address: {}", errno);
            return false;
        }

        if (!(req.ifr_flags & IFF_UP)) {
            log::log(log::error, "Interface {} is down: {:#x}", m_iface, req.ifr_flags);
            return false;
        }

        res = ioctl(fd, SIOCGIFINDEX, &req);
        if (res < 0) {
            log::log(log::error, "Could not execute SIOCGIFINDEX: {}", errno);
            return false;
        }

        log::log(log::debug, "iface index={}", req.ifr_ifindex);

        m_sa.sll_family = AF_PACKET;
        m_sa.sll_protocol = htons(EBM_ETH_TYPE);
        m_sa.sll_ifindex = req.ifr_ifindex;

        res = bind(fd, (const struct sockaddr *) &m_sa, sizeof(m_sa));
        if (res < 0) {
            log::log(log::error, "Could not bind: {}", errno);
            return false;
        }

        res = ioctl(fd, SIOCGIFHWADDR, &req);
        if (res < 0) {
            log::log(log::error, "Could not get hw address: {}", errno);
            return false;
        }

        memcpy(m_macaddr.data(), req.ifr_ifru.ifru_hwaddr.sa_data, sizeof(m_macaddr));

        dump_hw_addr(m_macaddr);

        return true;
    }

public:
    static nic_reader_writer_ptr_t create(const std::string &iface, uint16_t ether_type) {
        if (iface.size() > IFNAMSIZ) {
            return nullptr;
        }

        auto ret = nic_reader_writer_ptr_t(new nic_reader_writer_t(iface, ether_type));
        if (!ret->init()) {
            return nullptr;
        }

        return ret;
    }

    void set_pcap_writer(PCAPWriterPtr pcap) {
        m_pcap = pcap;
    }

    bool write_packet(const packet_t &packet) {
        auto data = packet.get();
        return write_packet(data.data(), data.size());
    }

    bool write_packet(const void *buffer, size_t size) {
        if (log::g_log_level <= log::trace) {
            log::log(log::trace, "Sending packet size={:#x}:", size);
            hex_dump(buffer, size);
        }

        int ret = sendto(m_fd->fd, buffer, size, 0, (struct sockaddr *) &m_sa, sizeof(m_sa));
        if (ret < 0) {
            log::log(log::error, "Could not send packet: {}", errno);
            return false;
        }

        if (m_pcap && m_pcap->write_packet(buffer, sizeof(buffer)) < 0) {
            log::log(log::error, "Could not write pcap file");
        }

        return true;
    }

    status_t read_packet(packet_t &packet) {
        fd_set readfds;
        struct timeval timeout_value;

        timeout_value.tv_sec = 1;
        timeout_value.tv_usec = 0;

        FD_ZERO(&readfds);
        FD_SET(m_fd->fd, &readfds);

        int ret = select(m_fd->fd + 1, &readfds, NULL, NULL, &timeout_value);
        if (ret < 0) {
            log::log(log::error, "Wait failed: {}", errno);
            return error;
        } else if (ret == 0) {
            log::log(log::debug, "Wait timed out");
            return timeout;
        }

        socklen_t addrlen = sizeof(m_sa);

        packet.clear();
        packet.resize(1514);
        auto data = packet.data();
        ret = recvfrom(m_fd->fd, data, packet.size(), 0, (struct sockaddr *) &m_sa, &addrlen);
        if (ret < 0) {
            log::log(log::error, "recvfrom failed: {}", errno);
            return error;
        }

        packet.resize(ret);

        if (m_pcap && m_pcap->write_packet(data, ret) < 0) {
            log::log(log::error, "Could not write pcap file");
        }

        if (log::g_log_level <= log::trace) {
            log::log(log::trace, "Received packet size={:x}:", packet.size());
            hex_dump(data, packet.size());
        }

        return ok;
    }

    macaddr_t get_mac_addr() const {
        return m_macaddr;
    }
};

#endif