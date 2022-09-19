//
// Created by spak on 3/17/21.
//

#include "test_pn532.hpp"
#include <pn532/esp32/hsu.hpp>
#include <pn532/esp32/i2c.hpp>
#include <pn532/esp32/spi.hpp>
#include <pn532/msg.hpp>
#include <unity.h>

#define TEST_TAG "UT"

namespace ut::pn532 {

    namespace {
        constexpr const char *missing_instance_msg = "PN532 test instance was not set up.";

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
                .sda_io_num = pinout::pn532_i2c_sda,
                .scl_io_num = pinout::pn532_i2c_scl,
                .sda_pullup_en = GPIO_PULLUP_ENABLE,
                .scl_pullup_en = GPIO_PULLUP_ENABLE,
                .master = {.clk_speed = 400000},
                .clk_flags = I2C_SCLK_SRC_FLAG_FOR_NOMAL};

        constexpr spi_bus_config_t spi_bus_config = {
                .mosi_io_num = pinout::pn532_spi_mosi,
                .miso_io_num = pinout::pn532_spi_miso,
                .sclk_io_num = pinout::pn532_spi_sck,
                .quadwp_io_num = GPIO_NUM_NC,
                .quadhd_io_num = GPIO_NUM_NC,
                .data4_io_num = -1,
                .data5_io_num = -1,
                .data6_io_num = -1,
                .data7_io_num = -1,
                .max_transfer_sz = 0,
                .flags = SPICOMMON_BUSFLAG_MASTER,
                .intr_flags = 0};

        constexpr spi_device_interface_config_t spi_device_config = {
                .command_bits = 0,
                .address_bits = 0,
                .dummy_bits = 0,
                .mode = 0,
                .duty_cycle_pos = 0,
                .cs_ena_pretrans = 0,
                .cs_ena_posttrans = 0,
                .clock_speed_hz = 1'000'000 /** @note Max supported 5MHz by PN532, but it will not pass comm tests o/w. **/,
                .input_delay_ns = 0,
                .spics_io_num = pinout::pn532_spi_ss,
                .flags = 0,
                .queue_size = 1,
                .pre_cb = nullptr,
                .post_cb = nullptr};


        [[nodiscard]] bool ok_and_true(controller::result<bool> const &r) {
            return r and *r;
        }


    }// namespace

    test_data::test_data(std::unique_ptr<pn532::channel> channel) : _channel{std::move(channel)}, _tag_reader{*_channel}, _channel_did_wake{false} {
        if (_channel == nullptr) {
            ESP_LOGE(TEST_TAG, "Null PN532 channel used in test!");
        }
    }

    pn532::channel &test_data::channel() {
        return *_channel;
    }
    pn532::controller &test_data::tag_reader() {
        return _tag_reader;
    }


    /**
     * @addtogroup ActualTestMethods
     * @{
     */
    void test_wake_channel() {
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &channel = instance->channel();
        auto &tag_reader = instance->tag_reader();

        TEST_ASSERT(channel.wake())
        const auto r_sam = tag_reader.sam_configuration(sam_mode::normal, 1s);
        TEST_ASSERT(r_sam)

        instance->mark_channel_did_wake();
    }

    void test_get_fw() {
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &tag_reader = instance->tag_reader();

        const auto r_fw = tag_reader.get_firmware_version();
        TEST_ASSERT(r_fw)
        ESP_LOGI(TEST_TAG, "IC version %u, version: %u.%u", r_fw->ic, r_fw->version, r_fw->revision);
    }

    void test_diagnostics() {
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &tag_reader = instance->tag_reader();

        TEST_ASSERT(ok_and_true(tag_reader.diagnose_rom()))
        TEST_ASSERT(ok_and_true(tag_reader.diagnose_ram()))
        TEST_ASSERT(ok_and_true(tag_reader.diagnose_comm_line()))
        TEST_ASSERT(
                ok_and_true(tag_reader.diagnose_self_antenna(low_current_thr::mA_25, high_current_thr::mA_150)))
    }

    void test_scan_mifare() {
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &tag_reader = instance->tag_reader();

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
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &tag_reader = instance->tag_reader();

        using ::pn532::to_string;

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
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &tag_reader = instance->tag_reader();

        const auto r_status = tag_reader.get_general_status();
        TEST_ASSERT(r_status)
        for (auto const &target : r_status->targets) {
            TEST_ASSERT(tag_reader.initiator_deselect(target.logical_index))
        }
        TEST_ASSERT(tag_reader.rf_configuration_field(true, false))
    }

    void test_data_exchange() {
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &tag_reader = instance->tag_reader();

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

    std::shared_ptr<test_instance> try_activate_channel(channel_type type) {
        if constexpr (supports_cicd_machine) {
            gpio_set_direction(pinout::pn532_cicd_rstn, GPIO_MODE_OUTPUT);
            gpio_set_direction(pinout::pn532_cicd_i0, GPIO_MODE_OUTPUT);
            gpio_set_direction(pinout::pn532_cicd_i1, GPIO_MODE_OUTPUT);
            // Power cycle the pn532
            gpio_set_level(pinout::pn532_cicd_rstn, 0);
            vTaskDelay(pdMS_TO_TICKS(500));
        } else {
            ESP_LOGW(TEST_TAG, "Not running on multi-channel CI/CD machine, the PN532 will not be power-cycled.");
        }

        // Check which channels are allowed
        if (not channel_is_supported(type)) {
            return nullptr;
        }
        ESP_LOGI(TEST_TAG, "Activating channel %s...", to_string(type));

        if constexpr (supports_cicd_machine) {
            // Configure I0/I1 for the selected mode
            switch (type) {
                case channel_type::hsu:
                    gpio_set_level(pinout::pn532_cicd_i0, 0);
                    gpio_set_level(pinout::pn532_cicd_i1, 0);
                    break;
                case channel_type::i2c:
                    [[fallthrough]];
                case channel_type::i2c_irq:
                    gpio_set_level(pinout::pn532_cicd_i0, 1);
                    gpio_set_level(pinout::pn532_cicd_i1, 0);
                    break;
                case channel_type::spi:
                    [[fallthrough]];
                case channel_type::spi_irq:
                    gpio_set_level(pinout::pn532_cicd_i0, 0);
                    gpio_set_level(pinout::pn532_cicd_i1, 1);
                    break;
            }
            // Release reset line to power cycle
            gpio_set_level(pinout::pn532_cicd_rstn, 1);
            vTaskDelay(pdMS_TO_TICKS(500));
        }

        std::unique_ptr<pn532::channel> channel = nullptr;
        switch (type) {
            case channel_type::hsu:
                channel = std::make_unique<pn532::esp32::hsu_channel>(UART_NUM_1, uart_config, pinout::pn532_hsu_tx, pinout::pn532_hsu_rx);
                break;
            case channel_type::i2c:
                channel = std::make_unique<pn532::esp32::i2c_channel>(I2C_NUM_0, i2c_config);
                break;
            case channel_type::i2c_irq:
                channel = std::make_unique<pn532::esp32::i2c_channel>(I2C_NUM_0, i2c_config, pinout::pn532_irq, true);
                break;
            case channel_type::spi:
                channel = std::make_unique<pn532::esp32::spi_channel>(SPI2_HOST, spi_bus_config, spi_device_config, SPI_DMA_CH1);
                break;
            case channel_type::spi_irq:
                channel = std::make_unique<pn532::esp32::spi_channel>(SPI2_HOST, spi_bus_config, spi_device_config, SPI_DMA_CH1, pinout::pn532_irq, true);
                break;
        }
        ESP_LOGI(TEST_TAG, "Channel %s ready.", to_string(type));
        return std::make_shared<test_instance>(std::move(channel));
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
            case channel_type::spi_irq:
                return "SPI with IRQ";
            default:
                return "UNKNOWN";
        }
    }
}// namespace ut::pn532
