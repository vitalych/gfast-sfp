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

#include <arpa/inet.h>
#include <errno.h>
#include <fstream>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <memory.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "pcap.h"
#include "types.h"
#include "utils.h"

int size_of_partype(uint32_t a1) {
    if (a1 >= 8) {
        fprintf(stderr, "MIB data type not implemented %#x\n", a1);
        return 0;
    }
    if (((1 << a1) & 3) != 0) {
        return 4;
    }
    if (((1 << a1) & 0xF0) != 0) {
        return 1;
    }

    if (((1 << a1) & 0xC) == 0) {
        fprintf(stderr, "MIB data type not implemented %#x\n", a1);
        return 0;
    }

    return 2;
}

using macaddr_t = uint8_t[6];

class nic_reader_writer_t;
using nic_reader_writer_ptr_t = std::shared_ptr<nic_reader_writer_t>;

class nic_reader_writer_t {
private:
    std::string m_iface;
    macaddr_t m_macaddr;
    struct sockaddr_ll m_sa = {0};
    safefd_ptr_t m_fd;
    PCAPWriterPtr m_pcap;

    nic_reader_writer_t(const std::string &iface) : m_iface(iface) {
    }

    bool init() {
        printf("Opening raw socket for %s\n", m_iface.c_str());

        m_fd = safefd_t::socket(PF_PACKET, SOCK_RAW, EBM_ETH_TYPE);
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
    static nic_reader_writer_ptr_t create(const std::string &iface) {
        if (iface.size() > IFNAMSIZ) {
            return nullptr;
        }

        auto ret = new nic_reader_writer_t(iface);
        if (!ret->init()) {
            return nullptr;
        }

        return nic_reader_writer_ptr_t(ret);
    }

    void set_pcap_writer(PCAPWriterPtr pcap) {
        m_pcap = pcap;
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

    bool read_packet(void *buffer, size_t size) {
        fd_set readfds;
        struct timeval timeout;

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        FD_ZERO(&readfds);
        FD_SET(m_fd->fd, &readfds);

        int ret = select(m_fd->fd + 1, &readfds, NULL, NULL, &timeout);
        if (ret < 0) {
            fprintf(stderr, "Wait failed: %d\n", errno);
            return false;
        } else if (ret == 0) {
            fprintf(stderr, "Wait timed out\n");
            return false;
        }

        socklen_t addrlen = sizeof(m_sa);
        ret = recvfrom(m_fd->fd, buffer, size, 0, (struct sockaddr *) &m_sa, &addrlen);
        if (ret < 0) {
            fprintf(stderr, "recvfrom failed: %d\n", errno);
            return false;
        }

        if (m_pcap && m_pcap->write_packet(buffer, size) < 0) {
            fprintf(stderr, "could not write pcap file\n");
        }

        printf("Received packet:\n");
        hex_dump(buffer, size);

        return true;
    }

    const macaddr_t *get_mac_addr() const {
        return &m_macaddr;
    }
};

class ebm_t;
using ebm_ptr_t = std::shared_ptr<ebm_t>;

class ebm_t {
private:
    nic_reader_writer_ptr_t m_nic;
    uint16_t m_seqno = 1;
    uint16_t m_access_seqno = 1;
    macaddr_t m_sfp_macaddr = {0x0, 0xe, 0xad, 0x33, 0x44, 0x55};

    uint32_t m_signature = 0;
    uint32_t m_checksum = 0;

    ebm_t(nic_reader_writer_ptr_t nic) : m_nic(nic) {
    }

public:
    static ebm_ptr_t create(nic_reader_writer_ptr_t nic) {
        return ebm_ptr_t(new ebm_t(nic));
    }

    struct __attribute__((packed)) associate_t {
        uint32_t magic;    // +0
        macaddr_t new_mac; // +4
        uint32_t magic1;   // +10/+0xa
        uint32_t magic2;   // +14/+0xe
        uint32_t magic3;   // +18/+0x12
    };

    bool associate(const macaddr_t new_mac) {
        uint8_t buffer[0x3c] = {0};

        auto payload = generate_header<associate_t>(buffer, ASSOCIATE, 0x16);
        payload->magic = htonl(0x00020304);
        memcpy(payload->new_mac, new_mac, sizeof(payload->new_mac));
        payload->magic1 = htonl(1);
        payload->magic2 = htonl(2);
        payload->magic3 = htonl(3);

        if (!m_nic->write_packet(buffer, sizeof(buffer))) {
            return false;
        }

        if (!check_response(ASSOCIATE_RESPONSE)) {
            return false;
        }

        memcpy(m_sfp_macaddr, new_mac, sizeof(m_sfp_macaddr));
        m_seqno++;
        return true;
    }

    struct __attribute__((packed)) download_begin_t {
        uint32_t magic;     // +0
        uint8_t unknown[8]; // +4
    };

    bool download_begin() {
        uint8_t buffer[0x3c] = {0};

        auto payload = generate_header<download_begin_t>(buffer, DOWNLOAD_BEGIN, 0xc);
        payload->magic = htonl(0xba000000);
        payload->unknown[0] = 0;
        payload->unknown[1] = 1;
        payload->unknown[2] = 2;
        payload->unknown[3] = 3;
        payload->unknown[4] = 0xa;
        payload->unknown[5] = 0xb;
        payload->unknown[6] = 0xc;
        payload->unknown[7] = 0xd;

        if (!m_nic->write_packet(buffer, sizeof(buffer))) {
            return false;
        }

        if (!check_response(DOWNLOAD_ACK)) {
            return false;
        }

        m_seqno++;

        return true;
    }

    bool download_firmware(const std::string &path) {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.good()) {
            fprintf(stderr, "Could not open %s\n", path.c_str());
            return false;
        }

        ifs.seekg(0, std::ios::beg);
        uint8_t buffer[0x200];
        ifs.read((char *) buffer, sizeof(buffer));

        uint32_t *dbuf = (uint32_t *) buffer;
        int index = -1;
        for (size_t i = 8; i < sizeof(buffer) / sizeof(uint32_t); i += 8) {
            if (ntohl(dbuf[i]) == 0x23210010) {
                index = (i / 8) - 1;
                break;
            }
        }

        if (index == -1) {
            fprintf(stderr, "could not find firmware signature\n");
            return false;
        }

        if (ntohl(dbuf[0]) != 0x61232321) {
            fprintf(stderr, "invalid header signature\n");
            return false;
        }

        if (ntohl(dbuf[4]) != 0x20000) {
            fprintf(stderr, "invalid header version\n");
            return false;
        }

        uint32_t record_number = ntohl(dbuf[0x30 / 4 + index * 8 + 2]); // Seems to be the size of some trailing data
        auto record_vector = std::vector<uint8_t>(record_number * sizeof(uint32_t));
        uint32_t *record_data =
            (uint32_t *) record_vector.data(); // (uint32_t *) malloc(record_number * sizeof(uint32_t));
        if (!record_data) {
            return false;
        }

        uint32_t offset1 = ntohl(dbuf[12 + index * 8]);      // offset
        uint32_t offset2 = ntohl(dbuf[(index + 1) * 8 + 1]); // fw size
        printf("offset1: %#x\n", offset1);
        printf("offset2: %#x\n", offset2);

        ifs.seekg(offset1 + offset2, std::ios::beg);

        for (uint32_t i = 0; i < record_number; ++i) {
            char chr = 0;
            ifs.read(&chr, 1);
            record_data[i] = chr;
        }

        printf("position: %#lx\n", (size_t) ifs.tellg());

        uint32_t fw_size = ntohl(dbuf[(index + 1) * 8 + 1]);
        printf("firmware size: %#x\n", fw_size);
        printf("record number: %#x\n", record_number);

        ifs.seekg(offset1, std::ios::beg);

        uint32_t signature = 0;
        for (int i = 0; i < 4; ++i) {
            char chr = 0;
            ifs.read(&chr, 1);

            signature = signature << 8 | (uint8_t) chr;
        }
        m_signature = signature;
        printf("signature: %#x\n", signature);

        uint32_t checksum = 0;
        for (int i = 0; i < 4; ++i) {
            char chr = 0;
            ifs.read(&chr, 1);

            checksum = checksum << 8 | (uint8_t) chr;
        }
        m_checksum = checksum;
        printf("checksum: %#x\n", checksum);

        auto pkt_hdr_size = 0x14;
        size_t packet_size = 0x5ea - pkt_hdr_size;
        std::vector<uint8_t> packet(packet_size);

        uint32_t size2 = 0;
        for (uint32_t i = 0; i < record_number; ++i) {
            size2 += record_data[i] * 4;
        }
        printf("firmware size2: %#x\n", size2);

        printf("position: %#lx\n", (size_t) ifs.tellg());

        uint32_t total_copied = 0;
        uint32_t size = 0;

        for (uint32_t i = 0; i < record_number; ++i) {
            size = size + record_data[i] * 4;

            if ((i == record_number - 1) || ((int) (packet_size - size)) < (int) (record_data[i + 1] * 4)) {
                packet.clear();
                packet.resize(packet_size);
                ifs.read((char *) packet.data(), size);

                if (!send_download_firmware(packet.data(), size)) {
                    return false;
                }

                m_seqno++;
                total_copied += size;
                size = 0;
            }
        }

        printf("position: %#lx\n", (size_t) ifs.tellg());
        printf("total_copied: %#x\n", total_copied);

        return true;
    }

    struct __attribute__((packed)) download_checksum_t {
        uint32_t checksum; // +0
        uint32_t magic;    // +4
    };

    bool download_checksum() {
        uint8_t buffer[0x3c] = {0};

        auto payload = generate_header<download_checksum_t>(buffer, DOWNLOAD_CHECKSUM, 0x8);
        payload->checksum = htonl(m_checksum);
        payload->magic = htonl(0xf4ee00dd);

        if (!m_nic->write_packet(buffer, sizeof(buffer))) {
            return false;
        }

        if (!check_response(DOWNLOAD_ACK)) {
            return false;
        }

        m_seqno++;

        return true;
    }

    bool read_mib(uint32_t *oid, void *data) {
        uint8_t buffer[1514] = {0};

        auto payload = generate_access_header(buffer, 6, 24);
        payload[0] = -1;

        auto payload_dw = (uint32_t *) (payload + 1);

        for (auto i = 0; i < 6; ++i) {
            payload_dw[i] = htonl(oid[i + 1]);
        }

        if (!m_nic->write_packet(buffer, sizeof(buffer))) {
            return false;
        }

        ++m_access_seqno;

        return true;
    }

    bool write_mib(uint32_t *oid, void *data) {
        uint8_t buffer[1514] = {0};

        auto v8 = size_of_partype(oid[6]);
        auto len = oid[5] * v8 + 24;

        auto payload = generate_access_header(buffer, 7, len);
        payload[0] = -1;

        auto payload_dw = (uint32_t *) (payload + 1);

        for (auto i = 0; i < 6; ++i) {
            payload_dw[i] = htonl(oid[i + 1]);
        }

        auto data_dw = &payload_dw[6];
        auto data_w = (uint16_t *) &payload_dw[6];
        auto data_b = (uint8_t *) &payload_dw[6];

        auto a2_dw = (uint32_t *) data;
        auto a2_w = (uint16_t *) data;
        auto a2_b = (uint8_t *) data;

        if (oid[5]) {
            if (oid[6] < 8) {
                for (auto i = 0; i < oid[5]; ++i) {
                    auto shift_val = 1 << oid[6];
                    if (shift_val & 0xf0) {
                        data_b[i] = a2_b[i];
                    } else if (shift_val & 0x0c) {
                        data_w[i] = a2_w[i];
                    } else if (shift_val & 0x03) {
                        data_dw[i] = a2_dw[i];
                    } else {
                        fprintf(stderr, "MIB data type not implemented\n");
                        return -1;
                    }
                }
            }
        }

        if (!m_nic->write_packet(buffer, sizeof(buffer))) {
            return false;
        }

        ++m_access_seqno;

        return 0;
    }

private:
    template <typename T> T *generate_header(uint8_t *buffer, packet_type_t type, uint16_t payload_size) {
        auto packet = (packet_t *) buffer;
        memcpy(packet->norm.hdr.dest_addr, m_sfp_macaddr, sizeof(macaddr_t));
        memcpy(packet->norm.hdr.source_addr, m_nic->get_mac_addr(), sizeof(macaddr_t));
        packet->norm.hdr.ether_type = htons(EBM_ETH_TYPE);
        packet->norm.payload_hdr.seq_no = htons(m_seqno);
        packet->norm.payload_hdr.type = htons(type);
        packet->norm.payload_hdr.data_length = htons(payload_size);

        return (T *) (buffer + sizeof(packet->norm));
    }

    uint8_t *generate_access_header(uint8_t *buffer, uint8_t type, uint16_t payload_size) {
        packet_access_t *packet = (packet_access_t *) buffer;

        memcpy(packet->hdr.dest_addr, m_sfp_macaddr, sizeof(macaddr_t));
        memcpy(packet->hdr.source_addr, m_nic->get_mac_addr(), sizeof(macaddr_t));
        packet->hdr.ether_type = htons(EBM_ETH_TYPE);
        packet->access_hdr.seq_no = htonl(m_access_seqno);
        packet->access_hdr.type = type;
        packet->access_hdr.length = htons(payload_size);
        return buffer + sizeof(*packet);
    }

    bool send_download_firmware(const uint8_t *data, size_t size) {
        uint8_t buffer[1514] = {0};

        auto payload = generate_header<uint8_t>(buffer, DOWNLOAD_FIRMWARE, size);
        memcpy(payload, data, size);

        if (!m_nic->write_packet(buffer, sizeof(buffer))) {
            return false;
        }

        if (!check_response(DOWNLOAD_ACK)) {
            return false;
        }

        return true;
    }

    bool check_response(packet_type_t expected_type) {
        uint8_t buffer[0x3c] = {0};
        auto packet = (packet_t *) buffer;

        if (!m_nic->read_packet(buffer, sizeof(buffer))) {
            return false;
        }

        uint16_t received_seqno = ntohs(packet->norm.payload_hdr.seq_no);
        packet_type_t received_type = (packet_type_t) ntohs(packet->norm.payload_hdr.type);
        uint8_t *payload_data = buffer + sizeof(packet->norm);
        uint8_t received_status = *payload_data;

        if (received_type != expected_type) {
            fprintf(stderr, "Unexpected response type: %#x\n", received_type);
            return false;
        }

        if (received_status != 0) {
            fprintf(stderr, "Unexpected status: %#x\n", received_status);
            return false;
        }

        if (received_seqno != m_seqno) {
            fprintf(stderr, "Unexpected sequence number, expected %x but got %x\n", m_seqno, received_seqno);
            return false;
        }

        return true;
    }
};

bool parse_mac(const char *str, macaddr_t mac) {
    auto ret = sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

    if (ret != 6) {
        fprintf(stderr, "Invalid mac: %s\n", str);
        return false;
    }

    return true;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s eth0 00:0e:ad:33:44:56 /path/to/firmware\n", argv[0]);
        return -1;
    }

    const char *iface = argv[1];
    const char *new_macaddr = argv[2];
    const char *firmware_path = argv[3];
    macaddr_t new_mac = {0};
    if (!parse_mac(new_macaddr, new_mac)) {
        return -1;
    }

    auto nic = nic_reader_writer_t::create(iface);
    if (!nic) {
        fprintf(stderr, "Could not init %s\n", iface);
    }

    // Write a pcap trace for debugging.
    auto pcap = PCAPWriter::create("data.pcap");
    nic->set_pcap_writer(pcap);

    auto ebm = ebm_t::create(nic);

#if 1
    if (!ebm->associate(new_mac)) {
        fprintf(stderr, "Could not associate\n");
        return -1;
    }

    if (!ebm->download_begin()) {
        fprintf(stderr, "Could not start uploading firmware\n");
        return -1;
    }

    if (!ebm->download_firmware(firmware_path)) {
        fprintf(stderr, "Could not download firmware\n");
        return -1;
    }

    if (!ebm->download_checksum()) {
        fprintf(stderr, "Could not download checksum\n");
        return -1;
    }
#endif

#if false

    uint32_t oid_TICKS[] = {0xffffffff, 0xb, 0x15, 0x0, 0x0, 0x1, 0x0, 0x0};
    ebm->read_mib(oid_TICKS, nullptr);


    uint8_t itu_vendor_id[] = {0x3D, 0x00, 0x53, 0x4C, 0x47, 0x4E, 0x00, 0x00};
    uint32_t oid_NT_VENDOR[] = {0xffffffff, 0xa, 0xc, 0x7, 0x0, 0x8, 0x6, 0x0};
    ebm->write_mib(oid_NT_VENDOR, (uint32_t *)itu_vendor_id);

    uint32_t oid_HOST_CMD[] = {0xffffffff, 0xb, 0x1, 0x0, 0x0, 0x1, 0x4, 0x1};
    uint32_t unk[64] = {0};
    ebm->write_mib(oid_HOST_CMD, (uint32_t *)unk);

#endif

    return 0;
}
