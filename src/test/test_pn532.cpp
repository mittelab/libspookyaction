//
// Created by spak on 3/17/21.
//

#include "test_pn532.hpp"
#include <pn532/hsu.hpp>
#include <pn532/i2c.hpp>
#include <pn532/msg.hpp>
#include <unity.h>

#define TEST_TAG "UT"

#ifndef PN532_SERIAL_RX
#define PN532_SERIAL_RX (GPIO_NUM_16)
#endif
#ifndef PN532_SERIAL_TX
#define PN532_SERIAL_TX (GPIO_NUM_17)
#endif

#ifndef PN532_I2C_SCL
#define PN532_I2C_SCL (GPIO_NUM_16)
#endif
#ifndef PN532_I2C_SDA
#define PN532_I2C_SDA (GPIO_NUM_17)
#endif

#ifndef PN532_SPI_MISO
#define PN532_SPI_MISO (GPIO_NUM_27)
#endif
#ifndef PN532_SPI_MOSI
#define PN532_SPI_MOSI (GPIO_NUM_25)
#endif
#ifndef PN532_SPI_SCK
#define PN532_SPI_SCK (GPIO_NUM_14)
#endif
#ifndef PN532_SPI_SS
#define PN532_SPI_SS (GPIO_NUM_26)
#endif

#ifndef PN532_I0
#define PN532_I0 (GPIO_NUM_18)
#endif
#ifndef PN532_I1
#define PN532_I1 (GPIO_NUM_19)
#endif
#ifndef PN532_RSTN
#define PN532_RSTN (GPIO_NUM_21)
#endif

#ifndef PN532_IRQ
#define PN532_IRQ (GPIO_NUM_13)
#endif

namespace test::pn532 {
    namespace {
        using namespace ::pn532;
        using ::pn532::to_string;

        constexpr uart_config_t uart_config = {
                .baud_rate = 115200,
                .data_bits = UART_DATA_8_BITS,
                .parity = UART_PARITY_DISABLE,
                .stop_bits = UART_STOP_BITS_1,
                .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
                .rx_flow_ctrl_thresh = 122,
                .source_clk = UART_SCLK_REF_TICK};

        constexpr i2c_config_t i2c_config = {
                .mode = I2C_MODE_MASTER,
                .sda_io_num = PN532_I2C_SDA,
                .scl_io_num = PN532_I2C_SCL,
                .sda_pullup_en = GPIO_PULLUP_ENABLE,
                .scl_pullup_en = GPIO_PULLUP_ENABLE,
                .master = {.clk_speed = 400000}};


        /**
         * Current test instance, only one at a time. Unfortunately Unity does not take parameters.
         */
        std::shared_ptr<instance> _current_instance = nullptr;
        bool *_wake_test_result = nullptr;

        /**
         * Makes sure that @ref _current_instance is non-nullptr at the beginning and released at the end.
         */
        struct auto_cleanup_test : auto_cleanup {
            auto_cleanup_test() {
                TEST_ASSERT_NOT_EQUAL_MESSAGE(nullptr, _current_instance, "Instance was not set up or test was already run.");
            }
        };

        [[nodiscard]] bool ok_and_true(nfc::r<bool> const &r) {
            return r and *r;
        }

        /**
         * @addtogroup ActualTestMethods
         * @{
         */
        void test_wake_channel() {
            if (_wake_test_result != nullptr) {
                *_wake_test_result = false;
            }

            auto_cleanup_test clear{};
            if (_current_instance == nullptr) {
                return;
            }
            auto &[channel, tag_reader] = **_current_instance;

            TEST_ASSERT(channel.wake())
            const auto r_sam = tag_reader.sam_configuration(sam_mode::normal, 1s);
            TEST_ASSERT(r_sam)

            if (_wake_test_result != nullptr) {
                *_wake_test_result = true;
            }
        }

        void test_get_fw() {
            auto_cleanup_test clear{};
            if (_current_instance == nullptr) {
                return;
            }
            auto &[channel, tag_reader] = **_current_instance;

            const auto r_fw = tag_reader.get_firmware_version();
            TEST_ASSERT(r_fw)
            ESP_LOGI(TEST_TAG, "IC version %u, version: %u.%u", r_fw->ic, r_fw->version, r_fw->revision);
        }

        void test_diagnostics() {
            auto_cleanup_test clear{};
            if (_current_instance == nullptr) {
                return;
            }
            auto &[channel, tag_reader] = **_current_instance;

            TEST_ASSERT(ok_and_true(tag_reader.diagnose_rom()))
            TEST_ASSERT(ok_and_true(tag_reader.diagnose_ram()))
            TEST_ASSERT(ok_and_true(tag_reader.diagnose_comm_line()))
            TEST_ASSERT(
                    ok_and_true(tag_reader.diagnose_self_antenna(low_current_thr::mA_25, high_current_thr::mA_150)))
        }

        void test_scan_mifare() {
            auto_cleanup_test clear{};
            if (_current_instance == nullptr) {
                return;
            }
            auto &[channel, tag_reader] = **_current_instance;

            ESP_LOGI(TEST_TAG, "Please bring card close now (searching for one passive 106 kbps target)...");
            const auto r_scan = tag_reader.initiator_list_passive_kbps106_typea();
            TEST_ASSERT(r_scan)
            ESP_LOGI(TEST_TAG, "Found %u targets (passive, 106 kbps, type A).", r_scan->size());
            if (r_scan) {
                for (target_kbps106_typea const &target : *r_scan) {
                    ESP_LOGI(TEST_TAG, "Logical index %u; NFC ID:", target.logical_index);
                    ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, target.info.nfcid.data(), target.info.nfcid.size(), ESP_LOG_INFO);
                }
            }
        }

        void test_scan_all() {
            auto_cleanup_test clear{};
            if (_current_instance == nullptr) {
                return;
            }
            auto &[channel, tag_reader] = **_current_instance;

            ESP_LOGI(TEST_TAG, "Please bring card close now (searching for any target)...");
            const auto r_scan = tag_reader.initiator_auto_poll();
            TEST_ASSERT(r_scan)
            ESP_LOGI(TEST_TAG, "Found %u targets.", r_scan->size());
            if (r_scan) {
                for (std::size_t i = 0; i < r_scan->size(); ++i) {
                    ESP_LOGI(TEST_TAG, "%u. %s", i + 1, to_string(r_scan->at(i).type()));
                }
            }
        }

        void test_pn532_cycle_rf() {
            auto_cleanup_test clear{};
            if (_current_instance == nullptr) {
                return;
            }
            auto &[channel, tag_reader] = **_current_instance;

            const auto r_status = tag_reader.get_general_status();
            TEST_ASSERT(r_status)
            for (auto const &target : r_status->targets) {
                TEST_ASSERT(tag_reader.initiator_deselect(target.logical_index))
            }
            TEST_ASSERT(tag_reader.rf_configuration_field(true, false))
        }

        void test_data_exchange() {
            auto_cleanup_test clear{};
            if (_current_instance == nullptr) {
                return;
            }
            auto &[channel, tag_reader] = **_current_instance;

            ESP_LOGI(TEST_TAG, "Please bring card close now (searching for one passive 106 kbps target)...");
            const auto r_scan = tag_reader.initiator_list_passive_kbps106_typea(1, 10s);
            if (not r_scan or r_scan->empty()) {
                TEST_FAIL_MESSAGE("Could not find a suitable card for testing.");
                return;
            }
            ESP_LOGI(TEST_TAG, "Found one target:");
            auto const &nfcid = r_scan->front().info.nfcid;
            ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, nfcid.data(), nfcid.size(), ESP_LOG_INFO);
            ESP_LOGI(TEST_TAG, "Exchanging data.");
            const auto idx = r_scan->front().logical_index;
            const auto r_exchange = tag_reader.initiator_data_exchange(idx, {0x5a, 0x00, 0x00, 0x00});
            if (not r_exchange) {
                TEST_FAIL_MESSAGE("Exchange failed.");
                return;
            }
            ESP_LOGI(TEST_TAG, "Exchange successful, received:");
            ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, r_exchange->second.data(), r_exchange->second.size(), ESP_LOG_INFO);
            TEST_ASSERT_EQUAL(r_exchange->first.error, controller_error::none);
            TEST_ASSERT_EQUAL(r_exchange->second.size(), 1);
            TEST_ASSERT_EQUAL(r_exchange->second.front(), 0x0);
        }

        /**
         * @}
         */

    }// namespace

    instance::instance(std::unique_ptr<::pn532::channel> channel) : _channel{std::move(channel)}, _tag_reader{*_channel} {
        if (_channel == nullptr) {
            ESP_LOGE(TEST_TAG, "A PN532 test instance was constructed with an empty channel!");
        }
    }

    ::pn532::nfc &instance::tag_reader() const {
        return _tag_reader;
    }

    std::pair<::pn532::channel &, ::pn532::nfc &> const instance::operator*() const {
        return {*_channel, _tag_reader};
    }

    ut::test_fn get_test_wake_channel(std::shared_ptr<instance> instance, bool *store_success) {
        _current_instance = std::move(instance);
        return &test_wake_channel;
    }

    ut::test_fn get_test_get_fw(std::shared_ptr<instance> instance) {
        _current_instance = std::move(instance);
        return &test_get_fw;
    }

    ut::test_fn get_test_diagnostics(std::shared_ptr<instance> instance) {
        _current_instance = std::move(instance);
        return &test_diagnostics;
    }

    ut::test_fn get_test_scan_mifare(std::shared_ptr<instance> instance) {
        _current_instance = std::move(instance);
        return &test_scan_mifare;
    }

    ut::test_fn get_test_scan_all(std::shared_ptr<instance> instance) {
        _current_instance = std::move(instance);
        return &test_scan_all;
    }

    ut::test_fn get_test_pn532_cycle_rf(std::shared_ptr<instance> instance) {
        _current_instance = std::move(instance);
        return &test_pn532_cycle_rf;
    }

    ut::test_fn get_test_data_exchange(std::shared_ptr<instance> instance) {
        _current_instance = std::move(instance);
        return &test_data_exchange;
    }

    void cleanup() {
        _current_instance = nullptr;
    }

    std::shared_ptr<instance> activate_channel(channel_type type) {
#ifdef KEYCARD_CI_CD_MACHINE
        gpio_set_direction(PN532_RSTN, GPIO_MODE_OUTPUT);
        gpio_set_direction(PN532_I0, GPIO_MODE_OUTPUT);
        gpio_set_direction(PN532_I1, GPIO_MODE_OUTPUT);
        // Power cycle the pn532
        gpio_set_level(PN532_RSTN, 0);
        vTaskDelay(pdMS_TO_TICKS(500));
#else
        ESP_LOGW(TEST_TAG, "Not running on multi-channel CI/CD machine, the PN532 will not be power-cycled.");
#endif
        // Check which channels are allowed
#ifndef KEYCARD_HSU
        if (type == channel_type::hsu) {
            return nullptr;
        }
#endif
#ifndef KEYCARD_I2C
        if (type == channel_type::i2c) {
            return nullptr;
        }
#endif
#ifndef KEYCARD_I2C_IRQ
        if (type == channel_type::i2c_irq) {
            return nullptr;
        }
#endif
#ifndef KEYCARD_SPI
        if (type == channel_type::spi) {
            return nullptr;
        }
#endif
        ESP_LOGI(TEST_TAG, "Activating channel %s...", to_string(type));
#ifdef KEYCARD_CI_CD_MACHINE
        // Configure I0/I1 for the selected mode
        switch (type) {
            case channel_type::hsu:
                gpio_set_level(PN532_I0, 0);
                gpio_set_level(PN532_I1, 0);
                break;
            case channel_type::i2c:
                [[fallthrough]];
            case channel_type::i2c_irq:
                gpio_set_level(PN532_I0, 1);
                gpio_set_level(PN532_I1, 0);
                break;
            case channel_type::spi:
                gpio_set_level(PN532_I0, 0);
                gpio_set_level(PN532_I1, 1);
                break;
        }
        // Release reset line to power cycle
        gpio_set_level(PN532_RSTN, 1);
        vTaskDelay(pdMS_TO_TICKS(500));
#endif
        std::unique_ptr<pn532::channel> channel = nullptr;
        switch (type) {
            case channel_type::hsu:
                channel = std::make_unique<pn532::hsu_channel>(UART_NUM_1, uart_config, PN532_SERIAL_TX, PN532_SERIAL_RX);
                break;
            case channel_type::i2c:
                channel = std::make_unique<pn532::i2c_channel>(I2C_NUM_0, i2c_config);
                break;
            case channel_type::i2c_irq:
                channel = std::make_unique<pn532::i2c_channel>(I2C_NUM_0, i2c_config, PN532_IRQ, true);
                break;
            case channel_type::spi:
                ESP_LOGE(TEST_TAG, "SPI is not yet supported.");
                return nullptr;
                break;
        }
        ESP_LOGI(TEST_TAG, "Channel %s ready.", to_string(type));
        return std::make_shared<instance>(std::move(channel));
    }

    const char *to_string(channel_type type) {
        switch (type) {
            case channel_type::i2c:
                return "I2C";
            case channel_type::i2c_irq:
                return "I2C with IRQ";
            case channel_type::hsu:
                return "HSU";
            case channel_type::spi:
                return "SPI";
            default:
                return "UNKNOWN";
        }
    }

}// namespace test::pn532