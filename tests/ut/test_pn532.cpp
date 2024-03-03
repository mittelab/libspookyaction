//
// Created by spak on 3/17/21.
//

#include "facility.hpp"
#include <catch.hpp>
#include <thread>

#define TAG "UT"

namespace ut {
    using namespace std::chrono_literals;

    namespace {
        [[nodiscard]] bool ok_and_true(pn532::result<bool> const &r) {
            return r and *r;
        }
    }// namespace

    TEST_CASE("0020 PN532") {
        const auto chn = GENERATE(channel_type::hsu, channel_type::i2c, channel_type::i2c_irq, channel_type::spi, channel_type::spi_irq);
        SECTION(to_string(chn)) {
            if (not facility::instance().supports(chn)) {
                SKIP();
            }

            auto ctrl = facility::instance().activate_channel(chn);
            REQUIRE(ctrl);

            SECTION("Diagnostics") {
                const auto r_fw = ctrl->get_firmware_version();
                REQUIRE(r_fw);
                ESP_LOGI(TAG, "IC version %u, version: %u.%u", r_fw->ic, r_fw->version, r_fw->revision);

                if (const auto r = ctrl->diagnose_rom(); not r or not *r) {
                    ESP_LOGW(TAG, "ROM diagnose fail (%s), is it a genuine PN532?",
                             r ? "false" : pn532::to_string(r.error()));
                }
                CHECK(ok_and_true(ctrl->diagnose_ram()));
                CHECK(ok_and_true(ctrl->diagnose_comm_line()));
                CHECK(ok_and_true(ctrl->diagnose_self_antenna(pn532::low_current_thr::mA_25, pn532::high_current_thr::mA_150)));

                const auto r_status = ctrl->get_general_status();
                CHECKED_IF_FAIL(r_status) {
                    for (auto const &target : r_status->targets) {
                        CHECK(ctrl->initiator_deselect(target.logical_index));
                    }
                }
                CHECK(ctrl->rf_configuration_field(true, false));
            }

            SECTION("Scan for any target") {
                ESP_LOGI(TAG, "Please bring card close now (searching for %s)...", "any target");
                const auto r_scan = ctrl->initiator_auto_poll();
                ESP_LOGI(TAG, "Found %u targets.", r_scan->size());
                CHECKED_IF_FAIL(r_scan) {
                    for (std::size_t i = 0; i < r_scan->size(); ++i) {
                        ESP_LOGI(TAG, "%u. %s", i + 1, to_string(r_scan->at(i).type()));
                    }
                }
            }

            SECTION("Mifare scan and communicate") {
                // Deactivate all preexisting targets
                auto r_gs = ctrl->get_general_status();
                REQUIRE(r_gs);
                for (auto const &target : r_gs->targets) {
                    REQUIRE(ctrl->initiator_deselect(target.logical_index));
                }

                // Power cycle the field so that we are sure all the targets are not powered
                REQUIRE(ctrl->rf_configuration_field(false, false));
                std::this_thread::sleep_for(200ms);
                REQUIRE(ctrl->rf_configuration_field(false, true));

                ESP_LOGI(TAG, "Please bring card close now (searching for %s)...", "one passive 106 kbps target");
                const auto r_scan = ctrl->initiator_list_passive_kbps106_typea();
                ESP_LOGI(TAG, "Found %u targets (passive, 106 kbps, type A).", r_scan->size());
                CHECKED_IF_FAIL(r_scan) {
                    CHECK(not r_scan->empty());
                    for (auto const &target : *r_scan) {
                        ESP_LOGI(TAG, "Logical index %u; NFC ID:", target.logical_index);
                        ESP_LOG_BUFFER_HEX_LEVEL(TAG, target.nfcid.data(), target.nfcid.size(), ESP_LOG_INFO);

                        const auto r_exchange = ctrl->initiator_data_exchange(target.logical_index, {0x5a, 0x00, 0x00, 0x00});
                        CHECKED_IF_FAIL(r_exchange) {
                            ESP_LOG_BUFFER_HEX_LEVEL(TAG, r_exchange->second.data(), r_exchange->second.size(), ESP_LOG_INFO);
                            CHECKED_IF_FAIL(r_exchange->first.error == pn532::internal_error_code::none) {
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
}// namespace ut