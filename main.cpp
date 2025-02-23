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
#include <functional>
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

#include "args.h"
#include "boot.h"
#include "log.h"
#include "mgmt.h"
#include "nic.h"
#include "pcap.h"
#include "tasks.h"
#include "utils.h"

std::optional<macaddr_t> parse_mac(const std::string &str) {
    macaddr_t mac;
    auto ret =
        sscanf(str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

    if (ret != 6) {
        log::log(log::error, "Invalid mac: {}", str);
        return std::nullopt;
    }

    return mac;
}

bool retry(std::function<bool()> func) {
    for (int i = 0; i < 3; ++i) {
        if (func()) {
            return true;
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return false;
}

bool upload_firmware(nic_reader_writer_ptr_t nic, const std::string &firmware_path, macaddr_t new_mac) {
    // Check if firmware is already uploaded.
    auto mgmt = mgmt::ebm_t::create(nic, new_mac);
    mgmt->start();

    if (retry([&]() -> bool { return mgmt->connect(); })) {
        log::log(log::info, "Firmware appears to be already loaded");
        return true;
    }

    // Connect failed, assume no firmware.
    auto boot = boot::ebm_boot_t::create(nic);
    boot->start();

    log::log(log::info, "associating...");

    if (!retry([&]() -> bool { return boot->associate(new_mac); })) {
        log::log(log::error, "Could not associate");
        return false;
    }

    log::log(log::info, "initing firmware download...");
    if (!boot->download_begin()) {
        log::log(log::error, "Could not start uploading firmware");
        return false;
    }

    log::log(log::info, "initing downloading firmware...");
    if (!boot->download_firmware(firmware_path)) {
        log::log(log::error, "Could not download firmware");
        return false;
    }

    log::log(log::info, "downloading checksum...");
    if (!boot->download_checksum()) {
        log::log(log::error, "Could not download checksum");
        return false;
    }

    log::log(log::info, "done.");
    boot->stop();

    return true;
}

mgmt::ebm_ptr_t init_sfp(nic_reader_writer_ptr_t nic, macaddr_t new_mac) {
    auto mgmt = mgmt::ebm_t::create(nic, new_mac);
    mgmt->start();

    if (!mgmt->connect()) {
        log::log(log::error, "Could not connect");
        return nullptr;
    }

    if (!mgmt->write_mib<uint32_t>(mgmt::oid_log_control, htonl(0xfe))) {
        log::log(log::error, "Could not write oid_log_control");
        return nullptr;
    }

    if (!mgmt->write_mib<uint32_t>(mgmt::oid_console_control, htonl(2))) {
        log::log(log::error, "Could not write oid_console_control");
        return nullptr;
    }

    if (!mgmt->write_mib<uint8_t>(mgmt::oid_host_cmd, 1)) {
        log::log(log::error, "Could not write oid_host_cmd");
        return nullptr;
    }

    if (!mgmt->write_mib<uint8_t>(mgmt::oid_repeat_cmd, 1)) {
        log::log(log::error, "Could not write oid_repeat_cmd");
        return nullptr;
    }

    if (!mgmt->write_mib<bool>(mgmt::oid_cmd_status, true)) {
        log::log(log::error, "Could not write oid_cmd_status");
        return nullptr;
    }

    return mgmt;
}

int main(int argc, char **argv) {
    auto args = raw_args_t(argv + 1, argv + argc);
    auto parsed_args = parse_args(args);

    if (!parsed_args || parsed_args->help) {
        std::println("Usage: {} --iface eth0 /path/to/firmware", argv[0]);
        std::println("Optional args:");
        std::println("  --help");
        std::println("  --log-level trace|debug|info|warn|error");
        std::println("  --pcap-path /path/to/file.pcap           location of packet capture file");
        std::println("  --hwaddr 00:0e:ad:33:44:56               new mac address for the sfp module");
        return -1;
    }

    log::g_log_level = parsed_args->log_level;

    auto new_mac = parse_mac(parsed_args->hwaddr);
    if (!new_mac) {
        return -1;
    }

    auto nic = nic_reader_writer_t::create(parsed_args->iface, EBM_ETH_TYPE);
    if (!nic) {
        log::log(log::error, "Could not init {}", parsed_args->iface);
        return -1;
    }

    // Write a pcap trace for debugging.
    if (parsed_args->pcap_path) {
        auto pcap = PCAPWriter::create(parsed_args->pcap_path.value());
        nic->set_pcap_writer(pcap);
    }

    if (!upload_firmware(nic, parsed_args->firmware_path, new_mac.value())) {
        log::log(log::error, "could not upload firmware {}", parsed_args->firmware_path);
        return -1;
    }

    sleep(2);

    auto mgmt = init_sfp(nic, new_mac.value());
    if (!mgmt) {
        log::log(log::error, "could not init sfp");
        return -1;
    }

    while (true) {
        auto ticks = mgmt->read_mib<uint32_t>(mgmt::oid_ticks);
        if (ticks) {
            log::log(log::info, "ticks: {}", ticks.value());
        } else {
            log::log(log::error, "could not read oid_ticks");
        }
        sleep(1);
    }

    return 0;
}
