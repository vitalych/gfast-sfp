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

#ifndef __GFAST_BOOT_H__

#define __GFAST_BOOT_H__

#include <inttypes.h>
#include <memory>

#include "nic.h"
#include "packet.h"
#include "tasks.h"

namespace boot {

// 6 bytes
struct __attribute__((packed)) ebm_header_t {
    // 0x0 0x1
    uint16_t seq_no;

    // 0x2 0x3
    uint16_t data_length;

    // 0x4 0x5
    uint16_t type; // packet_type_t
};

enum packet_type_t {
    ASSOCIATE = 0x01,
    ASSOCIATE_RESPONSE = 0x02,
    DOWNLOAD_BEGIN = 0x11,
    DOWNLOAD_FIRMWARE = 0x12,
    DOWNLOAD_CHECKSUM = 0x13,
    DOWNLOAD_ACK = 0x14
};

class ebm_boot_t;
using ebm_boot_ptr_t = std::shared_ptr<ebm_boot_t>;

class ebm_boot_t : public task_processor_t {
private:
    struct task_t {
        packet_t packet;
        packet_type_t expected_response;
        std::promise<bool> success;
    };

    nic_reader_writer_ptr_t m_nic;
    std::atomic<uint16_t> m_seqno = 1;
    macaddr_t m_sfp_macaddr = {0x0, 0xe, 0xad, 0x33, 0x44, 0x55};

    uint32_t m_signature = 0;
    uint32_t m_checksum = 0;

    std::shared_ptr<task_t> m_current_task;

    ebm_boot_t(nic_reader_writer_ptr_t nic) : task_processor_t(nic), m_nic(nic) {
    }

protected:
    virtual void process_task(std::shared_ptr<packet_t> packet) {
        auto task = m_current_task;
        if (!task) {
            fprintf(stderr, "received packet without task\n");
            return;
        }

        auto ret = check_response(*packet, task->expected_response);
        task->success.set_value(ret);

        m_current_task = nullptr;
    }

private:
    bool execute_task(std::shared_ptr<task_t> task) {
        auto future = task->success.get_future();
        m_current_task = task;
        if (!m_nic->write_packet(m_current_task->packet)) {
            return false;
        }

        bool ret = false;
        auto status = future.wait_for(std::chrono::seconds(1));
        switch (status) {
            case std::future_status::deferred:
                fprintf(stderr, "deferred\n");
                return false;
            case std::future_status::timeout:
                fprintf(stderr, "timeout\n");
                return false;
            case std::future_status::ready:
                ret = future.get();
                break;
            default:
                fprintf(stderr, "unknown status from future\n");
                return false;
        }

        if (ret) {
            m_seqno++;
        }

        return ret;
    }

public:
    static ebm_boot_ptr_t create(nic_reader_writer_ptr_t nic) {
        return ebm_boot_ptr_t(new ebm_boot_t(nic));
    }

    struct __attribute__((packed)) associate_t {
        uint32_t magic;    // +0
        macaddr_t new_mac; // +4
        uint32_t magic1;   // +10/+0xa
        uint32_t magic2;   // +14/+0xe
        uint32_t magic3;   // +18/+0x12
    };

    bool associate(const macaddr_t new_mac) {
        auto eth_header = generate_eth_header();
        auto boot_header = generate_header(ASSOCIATE, 0x16);
        auto payload = associate_t{};

        payload.magic = htonl(0x00020304);
        memcpy(payload.new_mac, new_mac, sizeof(payload.new_mac));
        payload.magic1 = htonl(1);
        payload.magic2 = htonl(2);
        payload.magic3 = htonl(3);

        auto task = std::make_shared<task_t>();
        task->packet.append(&eth_header);
        task->packet.append(&boot_header);
        task->packet.append(&payload);
        task->expected_response = ASSOCIATE_RESPONSE;

        if (!execute_task(task)) {
            return false;
        }

        memcpy(m_sfp_macaddr, new_mac, sizeof(m_sfp_macaddr));
        return true;
    }

    struct __attribute__((packed)) download_begin_t {
        uint32_t magic;     // +0
        uint8_t unknown[8]; // +4
    };

    bool download_begin() {
        auto eth_header = generate_eth_header();
        auto boot_header = generate_header(DOWNLOAD_BEGIN, sizeof(download_begin_t));
        auto payload = download_begin_t{};

        payload.magic = htonl(0xba000000);
        payload.unknown[0] = 0;
        payload.unknown[1] = 1;
        payload.unknown[2] = 2;
        payload.unknown[3] = 3;
        payload.unknown[4] = 0xa;
        payload.unknown[5] = 0xb;
        payload.unknown[6] = 0xc;
        payload.unknown[7] = 0xd;

        auto task = std::make_shared<task_t>();
        task->packet.append(&eth_header);
        task->packet.append(&boot_header);
        task->packet.append(&payload);
        task->expected_response = DOWNLOAD_ACK;

        return execute_task(task);
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
        auto eth_header = generate_eth_header();
        auto boot_header = generate_header(DOWNLOAD_CHECKSUM, sizeof(download_checksum_t));
        auto payload = download_checksum_t{};

        payload.checksum = htonl(m_checksum);
        payload.magic = htonl(0xf4ee00dd);

        auto task = std::make_shared<task_t>();
        task->packet.append(&eth_header);
        task->packet.append(&boot_header);
        task->packet.append(&payload);
        task->expected_response = DOWNLOAD_ACK;

        return execute_task(task);
    }

private:
    eth_header_t generate_eth_header() {
        eth_header_t ret;
        memcpy(ret.dest_addr, m_sfp_macaddr, sizeof(macaddr_t));
        memcpy(ret.source_addr, m_nic->get_mac_addr(), sizeof(macaddr_t));
        ret.ether_type = htons(EBM_ETH_TYPE);
        return ret;
    }

    ebm_header_t generate_header(packet_type_t type, uint16_t payload_size) {
        ebm_header_t ret;
        ret.seq_no = htons(m_seqno);
        ret.type = htons(type);
        ret.data_length = htons(payload_size);
        return ret;
    }

    bool send_download_firmware(const uint8_t *data, size_t size) {
        auto eth_header = generate_eth_header();
        auto boot_header = generate_header(DOWNLOAD_FIRMWARE, size);

        auto task = std::make_shared<task_t>();
        task->packet.append(&eth_header);
        task->packet.append(&boot_header);
        task->packet.append(data, size);
        task->expected_response = DOWNLOAD_ACK;

        return execute_task(task);
    }

    bool check_response(const packet_t &packet, packet_type_t expected_type) {
        eth_header_t eth;
        ebm_header_t ebm;
        uint8_t received_status;

        auto ret = packet.read(&eth, &ebm, &received_status);
        if (!ret) {
            return false;
        }

        uint16_t received_seqno = ntohs(ebm.seq_no);
        packet_type_t received_type = (packet_type_t) ntohs(ebm.type);

        if (received_type != expected_type) {
            fprintf(stderr, "Unexpected response type: %#x\n", received_type);
            return false;
        }

        if (received_status != 0) {
            fprintf(stderr, "Unexpected status: %#x\n", received_status);
            return false;
        }

        if (received_seqno != m_seqno) {
            fprintf(stderr, "Unexpected sequence number, expected %x but got %x\n", m_seqno.load(), received_seqno);
            return false;
        }

        return true;
    }
};

} // namespace boot

#endif
