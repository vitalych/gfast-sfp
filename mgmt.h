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

#ifndef __GFAST_MGMT_H__

#define __GFAST_MGMT_H__

#include <any>
#include <inttypes.h>
#include <memory>
#include <mutex>
#include <variant>

#include "nic.h"
#include "oid.h"
#include "packet.h"
#include "tasks.h"

namespace mgmt {

enum class access_status_type_t : uint8_t {
    OK = 0x00,
    GTPI_NOT_FOUND = 0x01,
    INVALID_ACCESSING = 0x02,
    LENGTH_MISMATCH = 0x03,
    INVALID_VALUE = 0x04,
    PSD_ERROR = 0x05,
    RMSC_ERROR = 0x06,
    CONNECTED = 0x07,
    LENGTH_EXCEEDS_PAYLOAD_SIZE = 0x10,
    INCOMPLETE_CMD = 0x11,
    ACCESS_DENIED = 0x12,
    DISCONNECTED = 0xB1,
    QUESTION = 0xE0,
    ANSWER_CORRECT = 0xE1,
    ANSWER_WRONG = 0xE2,
    OCCUPIED = 0xE3,
    FORCED_CONNECT = 0xE4,
    DEFAULT_STATUS = 0xFF,
};

enum class access_type_t : uint8_t {
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

// 7 bytes
struct __attribute__((packed)) access_header_t {
    // 0x0
    access_type_t type;

    // 0x1
    uint32_t seq_no;

    // 0x5 0x6
    uint16_t length;

    // 0x7
    access_status_type_t status;

    std::string to_string() const {
        std::string ret;
        std::format_to(std::back_inserter(ret), "[access_header_t type={:#x} seq_no={:#x} length={:#x} status={:#x}]",
                       (uint32_t) type, seq_no, length, (uint32_t) status);
        return ret;
    }
};

struct __attribute__((packed)) challenge_t {
    uint32_t f1;
    uint32_t f2;
};

class ebm_t;
using ebm_ptr_t = std::shared_ptr<ebm_t>;

class ebm_t : public task_processor_t {
private:
    struct task_result_t {
        using payload_t = std::variant<challenge_t, std::string, oid_result_t>;
        access_header_t header;
        std::optional<payload_t> payload;
    };

    struct task_t {
        packet_t request_packet;
        access_type_t expected_response_type;
        std::promise<std::optional<task_result_t>> success;
    };

    nic_reader_writer_ptr_t m_nic;
    std::atomic<uint16_t> m_seqno = 1;
    macaddr_t m_sfp_macaddr = {0x0, 0xe, 0xad, 0x33, 0x44, 0x55};

    std::mutex m_task_mutex;
    std::shared_ptr<task_t> m_current_task;

    ebm_t(nic_reader_writer_ptr_t nic, macaddr_t macaddr) : task_processor_t(nic), m_nic(nic) {
        m_sfp_macaddr = macaddr;
    }

public:
    virtual ~ebm_t() {
        stop();
    }

protected:
    virtual void process_task(std::shared_ptr<packet_t> packet) {
        auto parsed = parse_packet(*packet);
        if (!parsed) {
            log::log(log::error, "Could not parse packet");
            return;
        }

        std::lock_guard<std::mutex> lock(m_task_mutex);

        switch (parsed->header.type) {
            case access_type_t::MSG_CONNECT_RESP:
                check_response(parsed.value());
                break;
            case access_type_t::MSG_CONSOLE_OUTPUT:
            case access_type_t::MSG_LOGGER_OUTPUT: {
                auto str = std::get<std::string>(parsed->payload.value());
                log::log(log::debug, "LOG: {}", str);
            } break;

            case access_type_t::MSG_READ_MIB_RESP:
            case access_type_t::MSG_WRITE_MIB_RESP:
                check_response(parsed.value());
                break;
            default:
                log::log(log::error, "Unsupported packet type: {:#x}", (uint8_t) parsed->header.type);
        }
    }

private:
    std::optional<task_result_t> execute_task(std::shared_ptr<task_t> task) {
        auto future = task->success.get_future();

        {
            std::lock_guard<std::mutex> lock(m_task_mutex);

            m_current_task = task;
            if (!m_nic->write_packet(m_current_task->request_packet)) {
                return std::nullopt;
            }
        }

        std::optional<task_result_t> ret;
        auto status = future.wait_for(std::chrono::seconds(1));
        switch (status) {
            case std::future_status::deferred:
                log::log(log::error, "Task deferred");
                return std::nullopt;
            case std::future_status::timeout:
                log::log(log::error, "Timeout executing task");
                return std::nullopt;
            case std::future_status::ready:
                log::log(log::debug, "Task completed resp_type={:#x} seq_no={:#x}",
                         (uint32_t) task->expected_response_type, m_seqno.load());
                ret = future.get();
                break;
            default:
                log::log(log::error, "Unknown status from future");
                return std::nullopt;
        }

        if (ret.has_value()) {
            m_seqno++;
        }

        return ret;
    }

public:
    static ebm_ptr_t create(nic_reader_writer_ptr_t nic, macaddr_t mac_addr) {
        return ebm_ptr_t(new ebm_t(nic, mac_addr));
    }

    std::optional<task_result_t> connect1(const challenge_t &payload) {
        log::log(log::debug, "Connect command f1={:#x} f2={:x}", payload.f1, payload.f2);
        auto eth_header = generate_eth_header();
        auto access_header = generate_access_header(access_type_t::MSG_CONNECT, access_status_type_t::DEFAULT_STATUS,
                                                    sizeof(challenge_t));

        auto task = std::make_shared<task_t>();
        task->request_packet.append(&eth_header);
        task->request_packet.append(&access_header);
        task->request_packet.append(&payload);
        task->expected_response_type = access_type_t::MSG_CONNECT_RESP;

        return execute_task(task);
    }

    bool connect() {
        auto payload = challenge_t{.f1 = htonl(0xffffffff), .f2 = htonl(0x3c)};

        auto tries = 3;
        do {
            auto res = connect1(payload);

            if (!res.has_value()) {
                return false;
            }

            auto ret = res.value();

            switch (ret.header.status) {
                case access_status_type_t::FORCED_CONNECT:
                case access_status_type_t::ANSWER_CORRECT:
                    return true;
                case access_status_type_t::QUESTION: {
                    auto challenge = std::get<challenge_t>(ret.payload.value());
                    if (challenge.f2 != 0x95743926) {
                        return false;
                    }

                    payload = challenge_t{.f1 = htonl(0x6e6f6961), .f2 = htonl(0x0)};

                } break;
                default:
                    log::log(log::error, "Unknown status while connecting: {}", (uint8_t) ret.header.status);
                    return false;
            }
        } while (tries-- > 0);

        return false;
    }

    oid_req_t hton(const oid_req_t &req) {
        return oid_req_t{
            .oid = {htonl(req.oid[0]), htonl(req.oid[1]), htonl(req.oid[2])},
            .offset = htonl(req.offset),
            .length = htonl(req.length),
            .type = (oid_type_t) htonl((uint32_t) req.type),
        };
    }

    // data must be in network byte order for primitive types.
    template <typename T> bool write_mib(const oid_t &oid, T data) {
        if (!validate_oid_type<T>(oid.req.type)) {
            log::log(log::error, "Invalid mib type");
            return false;
        }

        auto eth_header = generate_eth_header();
        auto access_header = generate_access_header(access_type_t::MSG_WRITE_MIB, access_status_type_t::DEFAULT_STATUS,
                                                    sizeof(challenge_t));

        auto req = hton(oid.req);

        auto task = std::make_shared<task_t>();
        task->request_packet.append(&eth_header);
        task->request_packet.append(&access_header);
        task->request_packet.append(&req);
        task->expected_response_type = access_type_t::MSG_WRITE_MIB_RESP;

        task->request_packet.append(data);

        auto ret = execute_task(task);
        return ret->header.status == access_status_type_t::OK;
    }

    template <typename T> std::optional<T> read_mib(const oid_t &oid) {
        if (!validate_oid_type<T>(oid.req.type)) {
            log::log(log::error, "Invalid mib type");
            return false;
        }

        auto eth_header = generate_eth_header();
        auto access_header = generate_access_header(access_type_t::MSG_READ_MIB, access_status_type_t::DEFAULT_STATUS,
                                                    sizeof(challenge_t));

        auto req = hton(oid.req);

        auto task = std::make_shared<task_t>();
        task->request_packet.append(&eth_header);
        task->request_packet.append(&access_header);
        task->request_packet.append(&req);
        task->expected_response_type = access_type_t::MSG_READ_MIB_RESP;

        auto ret = execute_task(task);
        if (!ret || !ret->payload) {
            return std::nullopt;
        }

        auto oid_result = std::get<oid_result_t>(ret->payload.value());
        log::log(log::trace, "read_mib type:{}", oid_result.data.type().name());
        return std::any_cast<std::optional<T>>(oid_result.data);
    }

private:
    eth_header_t generate_eth_header() {
        eth_header_t ret;
        ret.dest_addr = m_sfp_macaddr;
        ret.source_addr = m_nic->get_mac_addr();
        ret.ether_type = htons(EBM_ETH_TYPE);
        return ret;
    }

    access_header_t generate_access_header(access_type_t type, access_status_type_t status, uint16_t payload_size) {
        auto seqno = m_seqno.load();
        log::log(log::debug, "Generating access header seqno={} type={:#x} status={:#x} payload_size={:#x}", seqno,
                 (uint32_t) type, (uint32_t) status, payload_size);
        access_header_t ret;
        ret.seq_no = htonl(seqno);
        ret.type = type;
        ret.length = htons(payload_size);
        ret.status = status;
        return ret;
    }

    std::optional<oid_result_t> parse_mib(const packet_t &packet) {
        oid_req_t oid;
        if (!packet.read(&oid)) {
            return std::nullopt;
        }

        std::any value;
        switch (oid.type) {
            case oid_type_t::oid_uint32:
                value = packet.read<uint32_t>(true);
                break;
            case oid_type_t::oid_int32:
                value = packet.read<int32_t>(true);
                break;
            case oid_type_t::oid_uint16:
                value = packet.read<uint16_t>(true);
                break;
            case oid_type_t::oid_int16:
                value = packet.read<int16_t>(true);
                break;
            case oid_type_t::oid_uint8:
                value = packet.read<uint8_t>(true);
                break;
            case oid_type_t::oid_int8:
                value = packet.read<int8_t>(true);
                break;
            case oid_type_t::oid_bool:
                value = packet.read<uint8_t>(true);
                break;
            case oid_type_t::oid_string:
            default:
                return std::nullopt;
        }

        if (!value.has_value()) {
            return std::nullopt;
        }

        return oid_result_t{.req = oid, .data = value};
    }

    std::optional<task_result_t> parse_packet(const packet_t &packet) {
        eth_header_t eth;
        access_header_t access_hdr;
        challenge_t challenge;
        task_result_t ret;

        if (!packet.read(&eth, &access_hdr)) {
            return std::nullopt;
        }

        ret.header = {.type = access_hdr.type,
                      .seq_no = ntohl(access_hdr.seq_no),
                      .length = ntohs(access_hdr.length),
                      .status = access_hdr.status};

        switch (ret.header.type) {
            case access_type_t::MSG_CONNECT_RESP:
                if (!packet.read(&challenge)) {
                    return std::nullopt;
                }
                challenge.f1 = ntohl(challenge.f1);
                challenge.f2 = ntohl(challenge.f2);
                ret.payload = challenge;
                break;
            case access_type_t::MSG_CONSOLE_OUTPUT:
            case access_type_t::MSG_LOGGER_OUTPUT: {
                std::string str;
                if (!packet.read_str(str, ret.header.length)) {
                    return std::nullopt;
                }
                ret.payload = str;
            } break;
            case access_type_t::MSG_WRITE_MIB_RESP:
                break;
            case access_type_t::MSG_READ_MIB_RESP: {
                if (ret.header.status != access_status_type_t::OK) {
                    return std::nullopt;
                }

                auto oid_result = parse_mib(packet);
                if (!oid_result) {
                    return std::nullopt;
                }
                ret.payload = oid_result.value();
            } break;

            default:
                log::log(log::error, "Unsupported packet type: {:x}", (uint8_t) ret.header.type);
        }

        log::log(log::debug, "Got packet {}", access_hdr.to_string());
        return ret;
    }

    void check_response(const task_result_t &result) {
        auto task = m_current_task;
        if (!task) {
            log::log(log::error, "Received packet without task");
            return;
        }

        if (result.header.type != task->expected_response_type) {
            log::log(log::error, "Unexpected response type: {:#x}", (uint8_t) result.header.type);
            return;
        }

        if (result.header.seq_no != m_seqno) {
            log::log(log::error, "Unexpected sequence number, expected {:#x} but got {:#x}", m_seqno.load(),
                     result.header.seq_no);
            return;
        }

        task->success.set_value(result);
        m_current_task = nullptr;
    }
};

} // namespace mgmt

#endif