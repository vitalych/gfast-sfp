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

#ifndef __GFAST_UTILS_H__

#define __GFAST_UTILS_H__

#include <fcntl.h>
#include <inttypes.h>
#include <memory>
#include <stdio.h>

__attribute__((unused)) static void hex_dump(const void *data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char *) data)[i]);
        if (((unsigned char *) data)[i] >= ' ' && ((unsigned char *) data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *) data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

static void dump_hw_addr(const uint8_t *addr) {
    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

struct safefd_t;
using safefd_ptr_t = std::shared_ptr<safefd_t>;

struct safefd_t {
    int fd;
    safefd_t(int fd) : fd(fd) {
    }
    ~safefd_t() {
        if (fd >= 0) {
            close(fd);
        }
    }

    static safefd_ptr_t socket(int domain, int type, int protocol) {
        auto ret = ::socket(domain, type, protocol);
        if (ret < 0) {
            return nullptr;
        }

        return safefd_ptr_t(new safefd_t(ret));
    }

    static safefd_ptr_t open(const char *file_path) {
        auto ret = ::open(file_path, O_CREAT | O_TRUNC | O_WRONLY);
        if (ret < 0) {
            return nullptr;
        }

        return safefd_ptr_t(new safefd_t(ret));
    }
};

#endif