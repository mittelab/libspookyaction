#include <desfire/esp32/cipher_provider.hpp>
#include <desfire/tag.hpp>
#include <pn532/controller.hpp>
#include <pn532/desfire_pcd.hpp>
#include <pn532/esp32/hsu.hpp>
#include <thread>

#define TAG "EXAMPLE"

using namespace std::chrono_literals;

pn532::desfire_pcd find_desfire(pn532::controller &pn532) {
    static constexpr auto retry_time = 3s;
    ESP_LOGI(TAG, "Please bring card close now (searching for one passive 106 kbps target)...");
    while (true) {
        if (auto res = pn532.initiator_list_passive_kbps106_typea(); res) {
            if (not res->empty()) {
                ESP_LOGI(TAG, "Found one target:");
                auto const &nfcid = res->front().info.nfcid;
                ESP_LOG_BUFFER_HEX_LEVEL(TAG, nfcid.data(), nfcid.size(), ESP_LOG_INFO);
                return {pn532, res->front().logical_index};
            }
            ESP_LOGW(TAG, "No target found.");
        } else {
            ESP_LOGE(TAG, "Failed to scan for any target, error: %s", pn532::to_string(res.error()));
        }
        ESP_LOGI(TAG, "Retrying in %lld seconds.", retry_time.count());
        std::this_thread::sleep_for(retry_time);
    }
}

bool authenticate_to_root_app(desfire::tag &tag) {
    static const auto default_key = desfire::key<desfire::cipher_type::des>{/* all zero */};

    ESP_LOGI(TAG, "Attempting at authenticating to card using a default key.");
    if (const auto res = tag.select_application(); not res) {
        ESP_LOGE(TAG, "Failed to select the root app, error: %s.", desfire::to_string(res.error()));
        return false;
    }
    if (const auto res = tag.authenticate(default_key); not res) {
        ESP_LOGE(TAG, "Authentication failure, error: %s.", desfire::to_string(res.error()));
        return false;
    }
    return true;
}

void print_card_info(desfire::tag &tag) {
    // Make sure we are authenticated
    assert(tag.active_app() == desfire::root_app);
    assert(tag.active_key_type() != desfire::cipher_type::none);

    if (const auto res = tag.get_info(); not res) {
        ESP_LOGE(TAG, "Could not retrieve card info, error: %s.", desfire::to_string(res.error()));
    } else {
        ESP_LOGI(TAG, "Card info:");
        ESP_LOGI(TAG, "    vendor id: %02x", res->hardware.vendor_id);
        ESP_LOGI(TAG, "   hw version: %d.%d", res->hardware.version_major, res->hardware.version_minor);
        ESP_LOGI(TAG, "   sw version: %d.%d", res->software.version_major, res->software.version_minor);
        ESP_LOGI(TAG, "  storage [B]: %s%u",
                 (res->hardware.size.bytes_upper_bound() > res->hardware.size.bytes_lower_bound() ? "> " : ""),
                 res->hardware.size.bytes_lower_bound());
        ESP_LOGI(TAG, "    serial no: %02x %02x %02x %02x %02x %02x %02x",
                 res->serial_no[0], res->serial_no[1], res->serial_no[2], res->serial_no[3],
                 res->serial_no[4], res->serial_no[5], res->serial_no[6]);
    }
}

void list_apps(desfire::tag &tag) {
    // Make sure we are authenticated
    assert(tag.active_app() == desfire::root_app);
    assert(tag.active_key_type() != desfire::cipher_type::none);

    if (const auto res = tag.get_application_ids(); not res) {
        ESP_LOGE(TAG, "Failed to retrieve the list of applications, error: %s.", desfire::to_string(res.error()));
    } else {
        if (res->empty()) {
            ESP_LOGI(TAG, "The card has no application.");
        } else {
            ESP_LOGI(TAG, "Listing %d applications:", res->size());
            for (std::size_t i = 0; i < res->size(); ++i) {
                const auto &app_id = res->at(i);
                ESP_LOGI(TAG, "%4d. %02x %02x %02x", i + 1, app_id[0], app_id[1], app_id[2]);
            }
        }
    }
}


void demo_app_and_file(desfire::tag &tag) {
    static const auto demo_app_id = desfire::app_id{0x00, 0xbe, 0xef};
    static const auto demo_app_key = desfire::key<desfire::cipher_type::aes128>{/* all zero */};
    static const auto demo_app_settings = desfire::app_settings{desfire::cipher_type::aes128};

    static constexpr std::size_t demo_file_size = 0x10;// 16 bytes

    static const auto demo_file_id = desfire::file_id{0x00};
    static const auto demo_file_settings = desfire::file_settings<desfire::file_type::standard>{
            // The file is stored encrypted
            desfire::file_security::encrypted,
            // The file is accessible only by the demo app key
            desfire::access_rights{demo_app_key.key_number()},
            // The file size is going to be 16 bytes
            demo_file_size};


    static const auto demo_file_data = desfire::bin_data{{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0a, 0x0b, 0x0c, 0xd, 0xe, 0xf}};

    // Make sure we are authenticated
    assert(tag.active_app() == desfire::root_app);
    assert(tag.active_key_type() != desfire::cipher_type::none);

    // Attempt at creating a new app. First check if it exists
    bool app_exists = false;
    if (const auto res = tag.get_application_ids(); res and not res->empty()) {
        // Try to find the demo app id
        app_exists = std::find(std::begin(*res), std::end(*res), demo_app_id) != std::end(*res);
    }

    // If it exists, delete it
    if (app_exists) {
        ESP_LOGW(TAG, "Demo app exists, will try to delete and recreate.");
        if (const auto res = tag.delete_application(demo_app_id); not res) {
            ESP_LOGE(TAG, "Failed to delete app, error: %s.", desfire::to_string(res.error()));
            return;
        }
        ESP_LOGI(TAG, "Old app deleted successfully.");
    }

    // Attempt at creating the app
    ESP_LOGI(TAG, "Creating demo app...");
    if (const auto res = tag.create_application(demo_app_id, demo_app_settings); not res) {
        ESP_LOGE(TAG, "Failed to create app, error: %s.", desfire::to_string(res.error()));
        return;
    }

    // Now try to authenticate to the app. First select
    if (const auto res = tag.select_application(demo_app_id); not res) {
        ESP_LOGE(TAG, "Failed to select the demo app, error: %s.", desfire::to_string(res.error()));
        return;
    }
    // Then provide the password
    if (const auto res = tag.authenticate(demo_app_key); not res) {
        ESP_LOGE(TAG, "Authentication to demo app failure, error: %s.", desfire::to_string(res.error()));
        return;
    }

    ESP_LOGI(TAG, "Authenticated. Creating file.");
    if (const auto res = tag.create_file(demo_file_id, demo_file_settings); not res) {
        ESP_LOGE(TAG, "Failed to create file, error: %s.", desfire::to_string(res.error()));
        return;
    }

    ESP_LOGI(TAG, "File created, writing some data on it.");
    // If the file settings are known, they can be used, otherwise we could specify `desfire::trust_card`
    const auto write_mode = desfire::tag::determine_operation_mode(desfire::file_access::write, demo_file_settings);
    if (const auto res = tag.write_data(demo_file_id, demo_file_data, write_mode, 0); not res) {
        ESP_LOGE(TAG, "Failed to write to file, error: %s.", desfire::to_string(res.error()));
        return;
    }

    ESP_LOGI(TAG, "Data written. Reading back.");
    // If the file settings are known, they can be used, otherwise we could specify `desfire::trust_card`
    const auto read_mode = desfire::tag::determine_operation_mode(desfire::file_access::read, demo_file_settings);
    if (const auto res = tag.read_data(demo_file_id, read_mode, 0, demo_file_size); not res) {
        ESP_LOGE(TAG, "Failed to read from file, error: %s.", desfire::to_string(res.error()));
        return;
    } else {
        auto const view = res->data_view();
        ESP_LOGI(TAG, "Read %d bytes.", res->size());
        ESP_LOG_BUFFER_HEX_LEVEL(TAG, view.data(), view.size(), ESP_LOG_INFO);
    }
}

extern "C" void app_main() {
    /**
     * @note This is mostly identical to the example in @ref initialize.cpp, except the final part of the body.
     */
    static constexpr gpio_num_t gpio_serial_tx = GPIO_NUM_17;
    static constexpr gpio_num_t gpio_serial_rx = GPIO_NUM_16;
    static constexpr uart_config_t uart_config = {
            .baud_rate = 115200,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
            .rx_flow_ctrl_thresh = 122,
            .source_clk = UART_SCLK_REF_TICK};
    auto hsu_chn = pn532::esp32::hsu_channel(UART_NUM_1, uart_config, gpio_serial_tx, gpio_serial_rx);
    auto pn532 = pn532::controller(hsu_chn);
    if (not hsu_chn.wake()) {
        ESP_LOGE(TAG, "HSU did not wake!");
        return;
    }
    if (not pn532.sam_configuration(pn532::sam_mode::normal, 1s)) {
        ESP_LOGE(TAG, "Failed to initialize SAM");
        return;
    }
    if (not pn532.rf_configuration_field(false, true)) {
        ESP_LOGE(TAG, "Failed to switch RF field on");
        return;
    }

    /**
     * @note The following code is specific to this example.
     */

    // Find any compatible target and onstruct the default cipher provider for an ESP32 and initialize the tag.
    auto tag = desfire::tag::make<desfire::esp32::default_cipher_provider>(find_desfire(pn532));

    if (authenticate_to_root_app(tag)) {
        print_card_info(tag);
        list_apps(tag);
        demo_app_and_file(tag);
        ESP_LOGI(TAG, "Desfire demo complete.");
    }
}
