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

#ifndef __GFAST_TASKS_H__
#define __GFAST_TASKS_H__

#include <future>
#include <memory>
#include <optional>
#include <thread>

#include "log.h"

class task_processor_t {
private:
    nic_reader_writer_ptr_t m_nic;

    void task_processor_thread() {
        while (!m_stop) {
            auto packet = std::make_shared<packet_t>();
            switch (m_nic->read_packet(*packet)) {
                case nic_reader_writer_t::status_t::timeout:
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                case nic_reader_writer_t::status_t::error:
                    log::log(log::error, "could not read packet");
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                case nic_reader_writer_t::status_t::ok:
                    break;
            }

            process_task(packet);
        }
    }

protected:
    std::thread m_processor_thread;
    std::atomic<bool> m_stop;

    virtual void process_task(std::shared_ptr<packet_t> packet) = 0;

    task_processor_t(nic_reader_writer_ptr_t nic) : m_nic(nic) {
    }

public:
    virtual ~task_processor_t() {
        stop();
    }

    void start() {
        m_processor_thread = std::thread(&task_processor_t::task_processor_thread, this);
    }

    void stop() {
        if (!m_stop) {
            m_stop = true;
            m_processor_thread.join();
        }
    }
};

#endif
