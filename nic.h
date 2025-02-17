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

#include "packet.h"
#include "pcap.h"
#include "utils.h"

static const uint32_t EBM_ETH_TYPE = 0x6120;

// TODO: use std::array
using macaddr_t = uint8_t[6];

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
        printf("Opening raw socket for %s\n", m_iface.c_str());

        m_fd = safefd_t::socket(PF_PACKET, SOCK_RAW, m_ether_type);
        if (!m_fd) {
            fprintf(stderr, "Could not open socket: %d\n", errno);
            return -1;
        }

        auto fd = m_fd.get()->fd;

        struct ifreq req;

        memset(&req, 0, sizeof(req));
        strncpy(req.ifr_ifrn.ifrn_name, m_iface.c_str(), IFNAMSIZ);

        int res = ioctl(fd, SIOCGIFFLAGS, &req);
        if (res < 0) {
            fprintf(stderr, "Could not read mac address: %d\n", errno);
            return false;
        }

        if (!(req.ifr_flags & IFF_UP)) {
            fprintf(stderr, "Interface %s is down: %#x\n", m_iface.c_str(), req.ifr_flags);
            return false;
        }

        res = ioctl(fd, SIOCGIFINDEX, &req);
        if (res < 0) {
            fprintf(stderr, "Could not execute SIOCGIFINDEX: %d\n", errno);
            return false;
        }

        printf("iface index=%d\n", req.ifr_ifindex);

        m_sa.sll_family = AF_PACKET;
        m_sa.sll_protocol = htons(EBM_ETH_TYPE);
        m_sa.sll_ifindex = req.ifr_ifindex;

        res = bind(fd, (const struct sockaddr *) &m_sa, sizeof(m_sa));
        if (res < 0) {
            fprintf(stderr, "Could not bind: %d\n", errno);
            return false;
        }

        res = ioctl(fd, SIOCGIFHWADDR, &req);
        if (res < 0) {
            fprintf(stderr, "Could not get hw address: %d\n", errno);
            return false;
        }

        memcpy(m_macaddr, req.ifr_ifru.ifru_hwaddr.sa_data, sizeof(m_macaddr));

        dump_hw_addr(m_macaddr);

        return true;
    }

public:
    static nic_reader_writer_ptr_t create(const std::string &iface, uint16_t ether_type) {
        if (iface.size() > IFNAMSIZ) {
            return nullptr;
        }

        auto ret = new nic_reader_writer_t(iface, ether_type);
        if (!ret->init()) {
            return nullptr;
        }

        return nic_reader_writer_ptr_t(ret);
    }

    void set_pcap_writer(PCAPWriterPtr pcap) {
        m_pcap = pcap;
    }

    bool write_packet(const packet_t &packet) {
        auto data = packet.get();
        return write_packet(data.data(), data.size());
    }

    bool write_packet(const void *buffer, size_t size) {
        printf("Sending packet sz=%#lx:\n", size);
        hex_dump(buffer, size);

        int ret = sendto(m_fd->fd, buffer, size, 0, (struct sockaddr *) &m_sa, sizeof(m_sa));
        if (ret < 0) {
            fprintf(stderr, "Could not send packet: %d\n", errno);
            return false;
        }

        if (m_pcap && m_pcap->write_packet(buffer, sizeof(buffer)) < 0) {
            fprintf(stderr, "could not write pcap file\n");
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
            fprintf(stderr, "Wait failed: %d\n", errno);
            return error;
        } else if (ret == 0) {
            fprintf(stderr, "Wait timed out\n");
            return timeout;
        }

        socklen_t addrlen = sizeof(m_sa);

        packet.clear();
        packet.resize(1514);
        auto &data = packet.get();
        ret = recvfrom(m_fd->fd, data.data(), data.size(), 0, (struct sockaddr *) &m_sa, &addrlen);
        if (ret < 0) {
            fprintf(stderr, "recvfrom failed: %d\n", errno);
            return error;
        }

        if (m_pcap && m_pcap->write_packet(data.data(), ret) < 0) {
            fprintf(stderr, "could not write pcap file\n");
        }

        packet.resize(ret);

        printf("Received packet:\n");
        hex_dump(data.data(), ret);

        return ok;
    }

    const macaddr_t *get_mac_addr() const {
        return &m_macaddr;
    }
};

#endif