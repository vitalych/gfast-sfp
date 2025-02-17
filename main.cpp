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

#include "boot.h"
#include "mgmt.h"
#include "nic.h"
#include "pcap.h"
#include "tasks.h"
#include "utils.h"

bool parse_mac(const char *str, macaddr_t mac) {
    auto ret = sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

    if (ret != 6) {
        fprintf(stderr, "Invalid mac: %s\n", str);
        return false;
    }

    return true;
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

    auto nic = nic_reader_writer_t::create(iface, EBM_ETH_TYPE);
    if (!nic) {
        fprintf(stderr, "Could not init %s\n", iface);
    }

    // Write a pcap trace for debugging.
    auto pcap = PCAPWriter::create("data.pcap");
    nic->set_pcap_writer(pcap);

    auto boot = boot::ebm_boot_t::create(nic);
    boot->start();

    fprintf(stdout, "associating...\n");

    if (!retry([&]() -> bool { return boot->associate(new_mac); })) {
        fprintf(stderr, "Could not associate\n");
        return -1;
    }

    fprintf(stdout, "initing firmware download...\n");
    if (!boot->download_begin()) {
        fprintf(stderr, "Could not start uploading firmware\n");
        return -1;
    }

    fprintf(stdout, "initing downloading firmware...\n");
    if (!boot->download_firmware(firmware_path)) {
        fprintf(stderr, "Could not download firmware\n");
        return -1;
    }

    fprintf(stdout, "downloading checksum...\n");
    if (!boot->download_checksum()) {
        fprintf(stderr, "Could not download checksum\n");
        return -1;
    }

    fprintf(stdout, "done.\n");
    boot->stop();

    sleep(2);

    auto mgmt = mgmt::ebm_t::create(nic, new_mac);
    mgmt->start();

    if (!mgmt->connect()) {
        fprintf(stderr, "Could not connect\n");
        return -1;
    }

    if (!mgmt->write_mib<uint32_t>(mgmt::oid_log_control, htonl(0xfe))) {
        fprintf(stderr, "Could not write oid_log_control\n");
        return -1;
    }

    if (!mgmt->write_mib<uint32_t>(mgmt::oid_console_control, htonl(2))) {
        fprintf(stderr, "Could not write oid_console_control\n");
        return -1;
    }

    if (!mgmt->write_mib<uint8_t>(mgmt::oid_host_cmd, 1)) {
        fprintf(stderr, "Could not write oid_host_cmd\n");
        return -1;
    }

    if (!mgmt->write_mib<uint8_t>(mgmt::oid_repeat_cmd, 1)) {
        fprintf(stderr, "Could not write oid_repeat_cmd\n");
        return -1;
    }

    if (!mgmt->write_mib<bool>(mgmt::oid_cmd_status, true)) {
        fprintf(stderr, "Could not write oid_cmd_status\n");
        return -1;
    }

    while (true) {
        auto ticks = mgmt->read_mib<uint32_t>(mgmt::oid_ticks);
        if (ticks) {
            fprintf(stdout, "ticks: %#08x\n", ticks.value());
        } else {
            fprintf(stderr, "could not read oid_ticks\n");
        }
        sleep(1);
    }

    return 0;
}
