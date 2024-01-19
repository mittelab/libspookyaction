//
// Created by spak on 26/10/23.
//

#include "facility.hpp"
#include <desfire/esp32/cipher_provider.hpp>
#include <desfire/esp32/utils.hpp>
#include <driver/gpio.h>
#include <driver/i2c.h>
#include <driver/spi_master.h>
#include <driver/uart.h>
#include <mlab/result_macro.hpp>
#include <pn532/desfire_pcd.hpp>
#include <pn532/esp32/hsu.hpp>
#include <pn532/esp32/i2c.hpp>
#include <pn532/esp32/spi.hpp>
#include <thread>

#define TAG "UT"

// Make sure macros are all defined:
static_assert(GPIO_NUM_NC == -1, "Macro fallback code relies on GPIO_NUM_NC == -1");

#ifndef CONFIG_PN532_HSU_TX_I2C_SDA
#define CONFIG_PN532_HSU_TX_I2C_SDA -1
#else
static_assert(CONFIG_PN532_HSU_TX_I2C_SDA >= GPIO_NUM_NC and CONFIG_PN532_HSU_TX_I2C_SDA <= GPIO_NUM_MAX);
#endif

#ifndef CONFIG_PN532_HSU_RX_I2C_SCL
#define CONFIG_PN532_HSU_RX_I2C_SCL -1
#else
static_assert(CONFIG_PN532_HSU_RX_I2C_SCL >= GPIO_NUM_NC and CONFIG_PN532_HSU_RX_I2C_SCL <= GPIO_NUM_MAX);
#endif

#ifndef CONFIG_PN532_SPI_MISO
#define CONFIG_PN532_SPI_MISO -1
#else
static_assert(CONFIG_PN532_SPI_MISO >= GPIO_NUM_NC and CONFIG_PN532_SPI_MISO <= GPIO_NUM_MAX);
#endif

#ifndef CONFIG_PN532_SPI_MOSI
#define CONFIG_PN532_SPI_MOSI -1
#else
static_assert(CONFIG_PN532_SPI_MOSI >= GPIO_NUM_NC and CONFIG_PN532_SPI_MOSI <= GPIO_NUM_MAX);
#endif

#ifndef CONFIG_PN532_SPI_SCK
#define CONFIG_PN532_SPI_SCK -1
#else
static_assert(CONFIG_PN532_SPI_SCK >= GPIO_NUM_NC and CONFIG_PN532_SPI_SCK <= GPIO_NUM_MAX);
#endif

#ifndef CONFIG_PN532_SPI_SS
#define CONFIG_PN532_SPI_SS -1
#else
static_assert(CONFIG_PN532_SPI_SS >= GPIO_NUM_NC and CONFIG_PN532_SPI_SS <= GPIO_NUM_MAX);
#endif

#ifndef CONFIG_PN532_I0
#define CONFIG_PN532_I0 -1
#else
static_assert(CONFIG_PN532_I0 >= GPIO_NUM_NC and CONFIG_PN532_I0 <= GPIO_NUM_MAX);
#endif

#ifndef CONFIG_PN532_I1
#define CONFIG_PN532_I1 -1
#else
static_assert(CONFIG_PN532_I1 >= GPIO_NUM_NC and CONFIG_PN532_I1 <= GPIO_NUM_MAX);
#endif

#ifndef CONFIG_PN532_RSTN
#define CONFIG_PN532_RSTN -1
#else
static_assert(CONFIG_PN532_RSTN >= GPIO_NUM_NC and CONFIG_PN532_RSTN <= GPIO_NUM_MAX);
#endif

#ifndef CONFIG_PN532_IRQ
#define CONFIG_PN532_IRQ -1
#else
static_assert(CONFIG_PN532_IRQ >= GPIO_NUM_NC and CONFIG_PN532_IRQ <= GPIO_NUM_MAX);
#endif

#ifndef CONFIG_SPOOKY_SINGLE_CHANNEL_HSU
#define CONFIG_SPOOKY_SINGLE_CHANNEL_HSU 0
#endif

#ifndef CONFIG_SPOOKY_SINGLE_CHANNEL_I2C
#define CONFIG_SPOOKY_SINGLE_CHANNEL_I2C 0
#endif

#ifndef CONFIG_SPOOKY_SINGLE_CHANNEL_I2C_IRQ
#define CONFIG_SPOOKY_SINGLE_CHANNEL_I2C_IRQ 0
#endif

#ifndef CONFIG_SPOOKY_SINGLE_CHANNEL_SPI
#define CONFIG_SPOOKY_SINGLE_CHANNEL_SPI 0
#endif

#ifndef CONFIG_SPOOKY_SINGLE_CHANNEL_SPI_IRQ
#define CONFIG_SPOOKY_SINGLE_CHANNEL_SPI_IRQ 0
#endif

#ifndef CONFIG_SPOOKY_MULTI_CHANNEL
#define CONFIG_SPOOKY_MULTI_CHANNEL 0
#endif

#ifndef CONFIG_SPOOKY_MULTI_CHANNEL_HSU
#define CONFIG_SPOOKY_MULTI_CHANNEL_HSU 0
#endif

#ifndef CONFIG_SPOOKY_MULTI_CHANNEL_I2C
#define CONFIG_SPOOKY_MULTI_CHANNEL_I2C 0
#endif

#ifndef CONFIG_SPOOKY_MULTI_CHANNEL_I2C_IRQ
#define CONFIG_SPOOKY_MULTI_CHANNEL_I2C_IRQ 0
#endif

#ifndef CONFIG_SPOOKY_MULTI_CHANNEL_SPI
#define CONFIG_SPOOKY_MULTI_CHANNEL_SPI 0
#endif

#ifndef CONFIG_SPOOKY_MULTI_CHANNEL_SPI_IRQ
#define CONFIG_SPOOKY_MULTI_CHANNEL_SPI_IRQ 0
#endif

#define SPOOKY_ANY_MULTI_CHANNEL (CONFIG_SPOOKY_MULTI_CHANNEL_HSU ||     \
                                  CONFIG_SPOOKY_MULTI_CHANNEL_I2C ||     \
                                  CONFIG_SPOOKY_MULTI_CHANNEL_I2C_IRQ || \
                                  CONFIG_SPOOKY_MULTI_CHANNEL_SPI ||     \
                                  CONFIG_SPOOKY_MULTI_CHANNEL_SPI_IRQ)

#define SPOOKY_ANY_SINGLE_CHANNEL (CONFIG_SPOOKY_SINGLE_CHANNEL_HSU ||     \
                                   CONFIG_SPOOKY_SINGLE_CHANNEL_I2C ||     \
                                   CONFIG_SPOOKY_SINGLE_CHANNEL_I2C_IRQ || \
                                   CONFIG_SPOOKY_SINGLE_CHANNEL_SPI ||     \
                                   CONFIG_SPOOKY_SINGLE_CHANNEL_SPI_IRQ)

#define SPOOKY_SINGLE_CHANNEL_COUNT (CONFIG_SPOOKY_SINGLE_CHANNEL_HSU +     \
                                     CONFIG_SPOOKY_SINGLE_CHANNEL_I2C +     \
                                     CONFIG_SPOOKY_SINGLE_CHANNEL_I2C_IRQ + \
                                     CONFIG_SPOOKY_SINGLE_CHANNEL_SPI +     \
                                     CONFIG_SPOOKY_SINGLE_CHANNEL_SPI_IRQ)

#if (CONFIG_SPOOKY_MULTI_CHANNEL && !SPOOKY_ANY_MULTI_CHANNEL) || (!CONFIG_SPOOKY_MULTI_CHANNEL && !SPOOKY_ANY_SINGLE_CHANNEL)
#error "You must define at least one communication channel."!
#endif

#if CONFIG_SPOOKY_MULTI_CHANNEL != (SPOOKY_ANY_MULTI_CHANNEL && !SPOOKY_ANY_SINGLE_CHANNEL)
#error "You must either select some multi channel options, or one single channel option."
#endif

#if SPOOKY_SINGLE_CHANNEL_COUNT > 1
#error "You can define at most one single-channel option"
#endif

#undef SPOOKY_ANY_MULTI_CHANNEL
#undef SPOOKY_ANY_SINGLE_CHANNEL
#undef SPOOKY_SINGLE_CHANNEL_COUNT

#if CONFIG_SPOOKY_MULTI_CHANNEL_HSU || CONFIG_SPOOKY_SINGLE_CHANNEL_HSU ||     \
        CONFIG_SPOOKY_MULTI_CHANNEL_I2C || CONFIG_SPOOKY_SINGLE_CHANNEL_I2C || \
        CONFIG_SPOOKY_MULTI_CHANNEL_I2C_IRQ || CONFIG_SPOOKY_SINGLE_CHANNEL_I2C_IRQ
#if CONFIG_PN532_HSU_RX_I2C_SCL <= -1 || CONFIG_PN532_HSU_TX_I2C_SDA <= -1
#error "You must specify valid HSU TX, RX/I2C SDA, SCL pins to use HSU/I2C, respectively."
#endif
#endif

#if CONFIG_SPOOKY_MULTI_CHANNEL_SPI || CONFIG_SPOOKY_SINGLE_CHANNEL_SPI || \
        CONFIG_SPOOKY_MULTI_CHANNEL_SPI_IRQ || CONFIG_SPOOKY_SINGLE_CHANNEL_SPI_IRQ
#if CONFIG_PN532_SPI_MISO <= -1 || CONFIG_PN532_SPI_MOSI <= -1 || \
        CONFIG_PN532_SPI_SCK <= -1 || CONFIG_PN532_SPI_SS <= -1
#error "You must specify valid SPI MOSI, MISO, SCK and SS pins to use SPI."
#endif
#endif

#if CONFIG_SPOOKY_MULTI_CHANNEL_I2C_IRQ || CONFIG_SPOOKY_SINGLE_CHANNEL_I2C_IRQ || \
        CONFIG_SPOOKY_MULTI_CHANNEL_SPI_IRQ || CONFIG_SPOOKY_SINGLE_CHANNEL_SPI_IRQ
#if CONFIG_PN532_IRQ <= -1
#error "You must specify valid IRQ line to use HSU, I2C or SPI with IRQ."
#endif
#endif

#if CONFIG_SPOOKY_MULTI_CHANNEL
#if CONFIG_PN532_I0 <= -1 || CONFIG_PN532_I1 <= -1 || CONFIG_PN532_RSTN <= -1
#error "You must control the I0, I1 and RSTN lines of the PN532 to enable switching between channels."
#endif
#endif

namespace ut {

    using pn532::wakeup_source;
    using namespace std::chrono_literals;

    namespace {

        namespace pinout {
            constexpr gpio_num_t pn532_hsu_rx_i2c_scl = static_cast<gpio_num_t>(CONFIG_PN532_HSU_RX_I2C_SCL);
            constexpr gpio_num_t pn532_hsu_tx_i2c_sda = static_cast<gpio_num_t>(CONFIG_PN532_HSU_TX_I2C_SDA);
            constexpr gpio_num_t pn532_spi_miso = static_cast<gpio_num_t>(CONFIG_PN532_SPI_MISO);
            constexpr gpio_num_t pn532_spi_mosi = static_cast<gpio_num_t>(CONFIG_PN532_SPI_MOSI);
            constexpr gpio_num_t pn532_spi_sck = static_cast<gpio_num_t>(CONFIG_PN532_SPI_SCK);
            constexpr gpio_num_t pn532_spi_ss = static_cast<gpio_num_t>(CONFIG_PN532_SPI_SS);
            constexpr gpio_num_t pn532_cicd_i0 = static_cast<gpio_num_t>(CONFIG_PN532_I0);
            constexpr gpio_num_t pn532_cicd_i1 = static_cast<gpio_num_t>(CONFIG_PN532_I1);
            constexpr gpio_num_t pn532_cicd_rstn = static_cast<gpio_num_t>(CONFIG_PN532_RSTN);
            constexpr gpio_num_t pn532_irq = static_cast<gpio_num_t>(CONFIG_PN532_IRQ);
        }// namespace pinout

        constexpr bool supports_hsu = static_cast<bool>(CONFIG_SPOOKY_MULTI_CHANNEL_HSU || CONFIG_SPOOKY_SINGLE_CHANNEL_HSU);
        constexpr bool supports_i2c = static_cast<bool>(CONFIG_SPOOKY_MULTI_CHANNEL_I2C || CONFIG_SPOOKY_SINGLE_CHANNEL_I2C);
        constexpr bool supports_i2c_irq = static_cast<bool>(CONFIG_SPOOKY_MULTI_CHANNEL_I2C_IRQ || CONFIG_SPOOKY_SINGLE_CHANNEL_I2C_IRQ);
        constexpr bool supports_spi = static_cast<bool>(CONFIG_SPOOKY_MULTI_CHANNEL_SPI || CONFIG_SPOOKY_SINGLE_CHANNEL_SPI);
        constexpr bool supports_spi_irq = static_cast<bool>(CONFIG_SPOOKY_MULTI_CHANNEL_SPI_IRQ || CONFIG_SPOOKY_SINGLE_CHANNEL_SPI_IRQ);

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
                .sda_io_num = pinout::pn532_hsu_tx_i2c_sda,
                .scl_io_num = pinout::pn532_hsu_rx_i2c_scl,
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
                .isr_cpu_id = INTR_CPU_ID_AUTO,
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

    }// namespace


    facility::facility()
        : _channel{nullptr},
          _controller{nullptr},
          _active_channel{channel_type::none} {
#if CONFIG_SPOOKY_MULTI_CHANNEL
        gpio_set_direction(pinout::pn532_cicd_rstn, GPIO_MODE_OUTPUT);
        gpio_set_direction(pinout::pn532_cicd_i0, GPIO_MODE_OUTPUT);
        gpio_set_direction(pinout::pn532_cicd_i1, GPIO_MODE_OUTPUT);
        gpio_set_level(pinout::pn532_cicd_rstn, 0);
#endif
    }

    facility::~facility() {
        deactivate();
    }

    void facility::power_down() {
        if (_controller) {
            desfire::esp32::suppress_log suppress{PN532_TAG};
            _controller->power_down({wakeup_source::i2c, wakeup_source::hsu, wakeup_source::spi});
        }
#if CONFIG_SPOOKY_MULTI_CHANNEL
        gpio_set_level(pinout::pn532_cicd_rstn, 0);
#endif
        std::this_thread::sleep_for(200ms);
    }

    void facility::power_up() {
#if CONFIG_SPOOKY_MULTI_CHANNEL
        gpio_set_level(pinout::pn532_cicd_rstn, 1);
#endif
        std::this_thread::sleep_for(200ms);
    }

    bool facility::try_wake_and_sam_configure() {
        if (_channel == nullptr) {
            return false;
        }
        _controller = std::make_shared<pn532::controller>(*_channel);
        for (std::size_t i = 0; i < 3; ++i) {
            power_up();
            if (_channel->wake()) {
                if (const auto r = _controller->sam_configuration(pn532::sam_mode::normal, 1s); r) {
                    return true;
                } else {
                    ESP_LOGW(TAG, "SAM not responding over %s, retrying...", to_string(active_channel()));
                }
            } else {
                ESP_LOGW(TAG, "Unable to wake channel %s, retrying...", to_string(active_channel()));
            }
            // Try to power down and retry
            power_down();
        }
        ESP_LOGE(TAG, "Failed contacting PN532.");
        _controller = nullptr;
        return false;
    }

    channel_type facility::active_channel() const {
        return _active_channel;
    }

    facility &facility::instance() {
        static facility _instance{};
        return _instance;
    }

    bool facility::activate_internal(ut::channel_type ct) {
#if CONFIG_SPOOKY_MULTI_CHANNEL
        // Configure I0/I1 for the selected mode
        switch (ct) {
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
                _channel = std::make_unique<pn532::esp32::hsu_channel>(UART_NUM_1, uart_config, pinout::pn532_hsu_tx_i2c_sda, pinout::pn532_hsu_rx_i2c_scl);
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

        _active_channel = ct;
        if (try_wake_and_sam_configure()) {
            return true;
        } else {
            _active_channel = channel_type::none;
        }

        _channel = nullptr;
        return false;
    }

    std::shared_ptr<desfire::tag> facility::get_card() {
        if (_tag) {
            return _tag;
        }
        if (active_channel() == channel_type::none) {
            ESP_LOGE(TAG, "No channel is active.");
            return nullptr;
        }

        [this]() -> pn532::result<> {
            // Is a target already activated?
            TRY_RESULT(_controller->get_general_status()) {
                if (r->rf_field_present and not r->targets.empty()) {
                    // Search for a compatible target
                    for (auto const &target : r->targets) {
                        if (target.modulation_type == pn532::modulation::mifare_iso_iec_14443_3_type_ab_iso_iec_18092_passive_kbps106 and
                            target.baudrate_tx == pn532::baudrate::kbps106 and
                            target.baudrate_rx == pn532::baudrate::kbps106) {
                            // Ok this works:
                            _tag = std::make_shared<desfire::tag>(
                                    std::make_shared<pn532::desfire_pcd>(*_controller, target.logical_index),
                                    std::make_unique<desfire::esp32::default_cipher_provider>());
                            return mlab::result_success;
                        }
                    }
                }
            }
            // No? Well search for one. Power-cycle the RF field in case some stray target was deactivated and is still
            // in the field
            TRY(_controller->rf_configuration_field(false, false));
            std::this_thread::sleep_for(200ms);
            TRY(_controller->rf_configuration_field(false, true));

            ESP_LOGI(TAG, "Please bring close a Mifare card…");
            TRY_RESULT(_controller->initiator_list_passive_kbps106_typea(1)) {
                if (not r->empty()) {
                    _tag = std::make_shared<desfire::tag>(
                            std::make_shared<pn532::desfire_pcd>(*_controller, r->front().logical_index),
                            std::make_unique<desfire::esp32::default_cipher_provider>());
                    return mlab::result_success;
                }
            }
            ESP_LOGE(TAG, "No target found.");
            return pn532::channel_error::timeout;
        }();

        return _tag;
    }

    bool facility::supports(channel_type ct) const {
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

    std::shared_ptr<pn532::controller> facility::activate_channel(ut::channel_type ct) {
        if (active_channel() == ct) {
            return _controller;
        }
        if (not supports(ct)) {
            return nullptr;
        }
        deactivate();
        if (activate_internal(ct)) {
            return _controller;
        }
        return nullptr;
    }

    void facility::deactivate() {
        if (active_channel() == channel_type::none) {
            return;
        }
        power_down();
        _tag = nullptr;
        _controller = nullptr;
        _channel = nullptr;
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

}// namespace ut