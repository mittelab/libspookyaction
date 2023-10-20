//
// Created by spak on 3/17/21.
//

#include "test_pn532.hpp"
#include <catch.hpp>
#include <desfire/esp32/utils.hpp>
#include <mlab/strutils.hpp>
#include <pn532/esp32/hsu.hpp>
#include <pn532/esp32/i2c.hpp>
#include <pn532/esp32/spi.hpp>
#include <pn532/msg.hpp>

#define TEST_TAG "UT"

namespace ut::pn532 {

    namespace {

        namespace pinout {

#ifndef PN532_SERIAL_RX
            constexpr gpio_num_t pn532_hsu_rx = GPIO_NUM_NC;
#else
            constexpr gpio_num_t pn532_hsu_rx = static_cast<gpio_num_t>(PN532_SERIAL_RX);
#endif

#ifndef PN532_SERIAL_TX
            constexpr gpio_num_t pn532_hsu_tx = GPIO_NUM_NC;
#else
            constexpr gpio_num_t pn532_hsu_tx = static_cast<gpio_num_t>(PN532_SERIAL_TX);
#endif

#ifndef PN532_I2C_SCL
            constexpr gpio_num_t pn532_i2c_scl = GPIO_NUM_NC;
#else
            constexpr gpio_num_t pn532_i2c_scl = static_cast<gpio_num_t>(PN532_I2C_SCL);
#endif

#ifndef PN532_I2C_SDA
            constexpr gpio_num_t pn532_i2c_sda = GPIO_NUM_NC;
#else
            constexpr gpio_num_t pn532_i2c_sda = static_cast<gpio_num_t>(PN532_I2C_SDA);
#endif

#ifndef PN532_SPI_MISO
            constexpr gpio_num_t pn532_spi_miso = GPIO_NUM_NC;
#else
            constexpr gpio_num_t pn532_spi_miso = static_cast<gpio_num_t>(PN532_SPI_MISO);
#endif

#ifndef PN532_SPI_MOSI
            constexpr gpio_num_t pn532_spi_mosi = GPIO_NUM_NC;
#else
            constexpr gpio_num_t pn532_spi_mosi = static_cast<gpio_num_t>(PN532_SPI_MOSI);
#endif

#ifndef PN532_SPI_SCK
            constexpr gpio_num_t pn532_spi_sck = GPIO_NUM_NC;
#else
            constexpr gpio_num_t pn532_spi_sck = static_cast<gpio_num_t>(PN532_SPI_SCK);
#endif

#ifndef PN532_SPI_SS
            constexpr gpio_num_t pn532_spi_ss = GPIO_NUM_NC;
#else
            constexpr gpio_num_t pn532_spi_ss = static_cast<gpio_num_t>(PN532_SPI_SS);
#endif

#ifndef PN532_I0
            constexpr gpio_num_t pn532_cicd_i0 = GPIO_NUM_NC;
#else
            constexpr gpio_num_t pn532_cicd_i0 = static_cast<gpio_num_t>(PN532_I0);
#endif

#ifndef PN532_I1
            constexpr gpio_num_t pn532_cicd_i1 = GPIO_NUM_NC;
#else
            constexpr gpio_num_t pn532_cicd_i1 = static_cast<gpio_num_t>(PN532_I1);
#endif

#ifndef PN532_RSTN
            constexpr gpio_num_t pn532_cicd_rstn = GPIO_NUM_NC;
#else
            constexpr gpio_num_t pn532_cicd_rstn = static_cast<gpio_num_t>(PN532_RSTN);
#endif

#ifndef PN532_IRQ
            constexpr gpio_num_t pn532_irq = GPIO_NUM_NC;
#else
            constexpr gpio_num_t pn532_irq = static_cast<gpio_num_t>(PN532_IRQ);
#endif
        }// namespace pinout

#ifdef SPOOKY_I2C
        constexpr bool supports_i2c = true;
#else
        constexpr bool supports_i2c = false;
#endif
#ifdef SPOOKY_I2C_IRQ
        constexpr bool supports_i2c_irq = true;
#else
        constexpr bool supports_i2c_irq = false;
#endif

#ifdef SPOOKY_SPI
        constexpr bool supports_spi = true;
#else
        constexpr bool supports_spi = false;
#endif
#ifdef SPOOKY_SPI_IRQ
        constexpr bool supports_spi_irq = true;
#else
        constexpr bool supports_spi_irq = false;
#endif


#ifdef SPOOKY_HSU
        constexpr bool supports_hsu = true;
#else
        constexpr bool supports_hsu = false;
#endif

#define PN532_ASSERT_DEFINED_PIN(PIN_MACRO) \
    static_assert(PIN_MACRO > GPIO_NUM_NC and PIN_MACRO < GPIO_NUM_MAX, "You did not define macro " #PIN_MACRO " (must be a valid GPIO pin).")

#if defined(SPOOKY_I2C) || defined(SPOOKY_I2C_IRQ)
        PN532_ASSERT_DEFINED_PIN(PN532_I2C_SCL);
        PN532_ASSERT_DEFINED_PIN(PN532_I2C_SDA);
#endif

#if defined(SPOOKY_SPI) || defined(SPOOKY_SPI_IRQ)
        PN532_ASSERT_DEFINED_PIN(PN532_SPI_MISO);
        PN532_ASSERT_DEFINED_PIN(PN532_SPI_MOSI);
        PN532_ASSERT_DEFINED_PIN(PN532_SPI_SCK);
        PN532_ASSERT_DEFINED_PIN(PN532_SPI_SS);
#endif

#if defined(SPOOKY_SPI_IRQ) || defined(SPOOKY_I2C_IRQ)
        PN532_ASSERT_DEFINED_PIN(PN532_IRQ);
#endif

#if defined(SPOOKY_HSU)
        PN532_ASSERT_DEFINED_PIN(PN532_SERIAL_TX);
        PN532_ASSERT_DEFINED_PIN(PN532_SERIAL_RX);
#endif

#if defined(SPOOKY_CI_CD_MACHINE)
        PN532_ASSERT_DEFINED_PIN(PN532_I0);
        PN532_ASSERT_DEFINED_PIN(PN532_I1);
        PN532_ASSERT_DEFINED_PIN(PN532_RSTN);
#endif

#undef PN532_ASSERT_DEFINED_PIN
        constexpr uart_config_t uart_config = {
                .baud_rate = 115200,
                .data_bits = UART_DATA_8_BITS,
                .parity = UART_PARITY_DISABLE,
                .stop_bits = UART_STOP_BITS_1,
                .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
                .rx_flow_ctrl_thresh = 122,
                .source_clk = UART_SCLK_DEFAULT};

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
                .isr_cpu_id = ESP_INTR_CPU_AFFINITY_AUTO,
                .intr_flags = 0};

        constexpr spi_device_interface_config_t spi_device_config = {
                .command_bits = 0,
                .address_bits = 0,
                .dummy_bits = 0,
                .mode = 0,
                .clock_source = SPI_CLK_SRC_DEFAULT,
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


        [[nodiscard]] bool ok_and_true(pn532::result<bool> const &r) {
            return r and *r;
        }


    }// namespace

    status::status()
        : _channel{nullptr},
          _controller{nullptr},
          _active_channel{channel_type::none} {
#ifdef SPOOKY_CI_CD_MACHINE
        gpio_set_direction(pinout::pn532_cicd_rstn, GPIO_MODE_OUTPUT);
        gpio_set_direction(pinout::pn532_cicd_i0, GPIO_MODE_OUTPUT);
        gpio_set_direction(pinout::pn532_cicd_i1, GPIO_MODE_OUTPUT);
        gpio_set_level(pinout::pn532_cicd_rstn, 0);
#endif
    }

    status::~status() {
        deactivate();
    }

    void status::power_down() {
        if (_controller) {
            desfire::esp32::suppress_log suppress{PN532_TAG};
            _controller->power_down({wakeup_source::i2c, wakeup_source::hsu, wakeup_source::spi});
        }
#ifdef SPOOKY_CI_CD_MACHINE
        gpio_set_level(pinout::pn532_cicd_rstn, 0);
#endif
        std::this_thread::sleep_for(200ms);
    }

    void status::power_up() {
#ifdef SPOOKY_CI_CD_MACHINE
        gpio_set_level(pinout::pn532_cicd_rstn, 1);
#endif
        std::this_thread::sleep_for(200ms);
    }

    bool status::try_wake_and_sam_configure() {
        if (_channel == nullptr) {
            return false;
        }
        _controller = std::make_shared<controller>(*_channel);
        for (std::size_t i = 0; i < 3; ++i) {
            power_up();
            if (_channel->wake()) {
                if (const auto r = _controller->sam_configuration(pn532::sam_mode::normal, 1s); r) {
                    return true;
                } else {
                    ESP_LOGW(TEST_TAG, "SAM not responding over %s, retrying...", to_string(active_channel()));
                }
            } else {
                ESP_LOGW(TEST_TAG, "Unable to wake channel %s, retrying...", to_string(active_channel()));
            }
            // Try to power down and retry
            power_down();
        }
        ESP_LOGE(TEST_TAG, "Failed contacting PN532.");
        _controller = nullptr;
        return false;
    }

    channel_type status::active_channel() const {
        return _active_channel;
    }

    std::shared_ptr<controller> status::ctrl() const {
        return _controller;
    }

    status &status::instance() {
        static status _instance{};
        return _instance;
    }

    bool status::activate_internal(ut::pn532::channel_type ct) {
#ifdef SPOOKY_CI_CD_MACHINE
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
            case channel_type::none:
                return true;
                break;
        }
#endif

        switch (ct) {
            case channel_type::hsu:
                _channel = std::make_unique<pn532::esp32::hsu_channel>(UART_NUM_1, uart_config, pinout::pn532_hsu_tx, pinout::pn532_hsu_rx);
                break;
            case channel_type::i2c:
                _channel = std::make_unique<pn532::esp32::i2c_channel>(I2C_NUM_0, i2c_config);
                break;
            case channel_type::i2c_irq:
                _channel = std::make_unique<pn532::esp32::i2c_channel>(I2C_NUM_0, i2c_config, pinout::pn532_irq, true);
                break;
            case channel_type::spi:
                _channel = std::make_unique<pn532::esp32::spi_channel>(SPI2_HOST, spi_bus_config, spi_device_config, SPI_DMA_CH_AUTO);
                break;
            case channel_type::spi_irq:
                _channel = std::make_unique<pn532::esp32::spi_channel>(SPI2_HOST, spi_bus_config, spi_device_config, SPI_DMA_CH_AUTO, pinout::pn532_irq, true);
                break;
            case channel_type::none:
                break;
        }

        if (try_wake_and_sam_configure()) {
            _active_channel = ct;
            return true;
        }

        _channel = nullptr;
        return false;
    }

    bool status::supports(channel_type ct) const {
        switch (ct) {
            case channel_type::i2c_irq:
                return supports_i2c_irq;
            case channel_type::i2c:
                return supports_i2c;
            case channel_type::hsu:
                return supports_hsu;
            case channel_type::spi:
                return supports_spi;
            case channel_type::spi_irq:
                return supports_spi_irq;
            case channel_type::none:
                return true;
        }
        return false;
    }

    bool status::activate(ut::pn532::channel_type ct) {
        if (active_channel() == ct) {
            return true;
        }
        if (not supports(ct)) {
            return false;
        }
        deactivate();
        return activate_internal(ct);
    }

    void status::deactivate() {
        if (active_channel() == channel_type::none) {
            return;
        }
        power_down();
        _channel = nullptr;
        _controller = nullptr;
        _active_channel = channel_type::none;
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

    std::unique_ptr<::pn532::channel> try_activate_channel(channel_type type) {
#ifdef SPOOKY_CI_CD_MACHINE
        gpio_set_direction(pinout::pn532_cicd_rstn, GPIO_MODE_OUTPUT);
        gpio_set_direction(pinout::pn532_cicd_i0, GPIO_MODE_OUTPUT);
        gpio_set_direction(pinout::pn532_cicd_i1, GPIO_MODE_OUTPUT);
        // Power cycle the pn532
        gpio_set_level(pinout::pn532_cicd_rstn, 0);
        vTaskDelay(pdMS_TO_TICKS(500));
#endif

        // Check which channels are allowed
        if (not status::instance().supports(type)) {
            return nullptr;
        }
        ESP_LOGI(TEST_TAG, "Activating channel %s...", to_string(type));

#ifdef SPOOKY_CI_CD_MACHINE
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
#endif

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
                channel = std::make_unique<pn532::esp32::spi_channel>(SPI2_HOST, spi_bus_config, spi_device_config, SPI_DMA_CH_AUTO);
                break;
            case channel_type::spi_irq:
                channel = std::make_unique<pn532::esp32::spi_channel>(SPI2_HOST, spi_bus_config, spi_device_config, SPI_DMA_CH_AUTO, pinout::pn532_irq, true);
                break;
            case channel_type::none:
                break;
        }
        ESP_LOGI(TEST_TAG, "Channel %s ready.", to_string(type));
        return channel;
    }

    bool try_activate_controller(channel &chn, controller &ctrl) {
        bool pass = false;
        for (std::size_t i = 0; i < 3; ++i) {
            if (chn.wake()) {
                if (const auto r = ctrl.sam_configuration(pn532::sam_mode::normal, 1s); r) {
                    pass = true;
                    break;
                } else {
                    ESP_LOGW(TEST_TAG, "Unable to configure SAM, %s. Retrying.", ::pn532::to_string(r.error()));
                }
            } else {
                ESP_LOGW(TEST_TAG, "Unable to wake channel. Retrying.");
            }
            // Try to power down and retry
            ctrl.power_down({pn532::wakeup_source::i2c, pn532::wakeup_source::spi, pn532::wakeup_source::hsu});
            std::this_thread::sleep_for(50ms);
        }
        if (not pass) {
            ESP_LOGE(TEST_TAG, "PN532 did not respond.");
        }
        return pass;
    }

    TEST_CASE("0020 PN532") {
        const auto chn = GENERATE(channel_type::hsu, channel_type::i2c, channel_type::i2c_irq, channel_type::spi, channel_type::spi_irq);
        SECTION(to_string(chn)) {
            if (not status::instance().supports(chn)) {
                SKIP();
            }
            REQUIRE(status::instance().activate(chn));
            auto &ctrl = *status::instance().ctrl();

            SECTION("Diagnostics") {
                const auto r_fw = ctrl.get_firmware_version();
                REQUIRE(r_fw);
                ESP_LOGI(TEST_TAG, "IC version %u, version: %u.%u", r_fw->ic, r_fw->version, r_fw->revision);

                CHECK(ok_and_true(ctrl.diagnose_rom()));
                CHECK(ok_and_true(ctrl.diagnose_ram()));
                CHECK(ok_and_true(ctrl.diagnose_comm_line()));
                CHECK(ok_and_true(ctrl.diagnose_self_antenna(low_current_thr::mA_25, high_current_thr::mA_150)));

                const auto r_status = ctrl.get_general_status();
                CHECKED_IF_FAIL(r_status) {
                    for (auto const &target : r_status->targets) {
                        CHECK(ctrl.initiator_deselect(target.logical_index));
                    }
                }
                CHECK(ctrl.rf_configuration_field(true, false));
            }

            SECTION("Scan for any target") {
                ESP_LOGI(TEST_TAG, "Please bring card close now (searching for %s)...", "any target");
                const auto r_scan = ctrl.initiator_auto_poll();
                ESP_LOGI(TEST_TAG, "Found %u targets.", r_scan->size());
                CHECKED_IF_FAIL(r_scan) {
                    for (std::size_t i = 0; i < r_scan->size(); ++i) {
                        ESP_LOGI(TEST_TAG, "%u. %s", i + 1, to_string(r_scan->at(i).type()));
                    }
                }
            }

            SECTION("Mifare scan and communicate") {
                ESP_LOGI(TEST_TAG, "Please bring card close now (searching for %s)...", "one passive 106 kbps target");
                const auto r_scan = ctrl.initiator_list_passive_kbps106_typea();
                ESP_LOGI(TEST_TAG, "Found %u targets (passive, 106 kbps, type A).", r_scan->size());
                CHECKED_IF_FAIL(r_scan) {
                    CHECK(not r_scan->empty());
                    for (target_kbps106_typea const &target : *r_scan) {
                        ESP_LOGI(TEST_TAG, "Logical index %u; NFC ID:", target.logical_index);
                        ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, target.nfcid.data(), target.nfcid.size(), ESP_LOG_INFO);

                        const auto r_exchange = ctrl.initiator_data_exchange(target.logical_index, {0x5a, 0x00, 0x00, 0x00});
                        CHECKED_IF_FAIL(r_exchange) {
                            ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, r_exchange->second.data(), r_exchange->second.size(), ESP_LOG_INFO);
                            CHECKED_IF_FAIL(r_exchange->first.error == internal_error_code::none) {
                                CHECKED_IF_FAIL(r_exchange->second.size() == 1) {
                                    CHECK(r_exchange->second.front() == 0x0);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

}// namespace ut::pn532
