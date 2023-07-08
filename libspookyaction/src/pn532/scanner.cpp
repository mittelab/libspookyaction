//
// Created by spak on 1/18/23.
//

#include <desfire/esp32/utils.hpp>
#include <pn532/scanner.hpp>

namespace pn532 {
    bool scanned_target::operator==(scanned_target const &other) const {
        return type == other.type and nfcid == other.nfcid;
    }

    bool scanned_target::operator!=(scanned_target const &other) const {
        return type != other.type or nfcid != other.nfcid;
    }

    bool scanned_target::operator<(scanned_target const &other) const {
        return type < other.type or
               (type == other.type and std::lexicographical_compare(
                                               std::begin(nfcid), std::end(nfcid),
                                               std::begin(other.nfcid), std::end(other.nfcid)));
    }

    bool scanned_target::operator>(scanned_target const &other) const {
        return other.operator<(*this);
    }

    bool scanned_target::operator<=(scanned_target const &other) const {
        return not other.operator<(*this);
    }

    bool scanned_target::operator>=(scanned_target const &other) const {
        return not operator<(other);
    }

    bool scanner::is_in_rejection_list(scanned_target const &target) const {
        return std::find(std::begin(_rejection_list), std::end(_rejection_list), target) != std::end(_rejection_list);
    }

    void scanner::update_rejection_list(scanner_responder &responder) {
        std::vector<scanned_target> new_rejection_list;
        new_rejection_list.reserve(std::max(2u, _rejection_list.size()));
        for (scanned_target &st : _rejection_list) {
            const bool not_in_rf_anymore = std::find(std::begin(in_rf()), std::end(in_rf()), st) == std::end(in_rf());
            if (not_in_rf_anymore) {
                responder.on_leaving_rf(*this, st);
            } else {
                new_rejection_list.emplace_back(std::move(st));
            }
        }
        std::swap(_rejection_list, new_rejection_list);
    }

    scanned_target::scanned_target(std::uint8_t index_, const any_poll_target &entry) : scanned_target{} {
        switch (entry.type()) {
            case target_type::generic_passive_106kbps:
                *this = scanned_target{index_, entry.get<target_type::generic_passive_106kbps>()};
                break;
            case target_type::generic_passive_212kbps:
                *this = scanned_target{index_, entry.get<target_type::generic_passive_212kbps>()};
                break;
            case target_type::generic_passive_424kbps:
                *this = scanned_target{index_, entry.get<target_type::generic_passive_424kbps>()};
                break;
            case target_type::passive_106kbps_iso_iec_14443_4_typeb:
                *this = scanned_target{index_, entry.get<target_type::passive_106kbps_iso_iec_14443_4_typeb>()};
                break;
            case target_type::innovision_jewel_tag:
                *this = scanned_target{index_, entry.get<target_type::innovision_jewel_tag>()};
                break;
            case target_type::mifare_classic_ultralight:
                *this = scanned_target{index_, entry.get<target_type::mifare_classic_ultralight>()};
                break;
            case target_type::felica_212kbps_card:
                *this = scanned_target{index_, entry.get<target_type::felica_212kbps_card>()};
                break;
            case target_type::felica_424kbps_card:
                *this = scanned_target{index_, entry.get<target_type::felica_424kbps_card>()};
                break;
            case target_type::passive_106kbps_iso_iec_14443_4_typea:
                *this = scanned_target{index_, entry.get<target_type::passive_106kbps_iso_iec_14443_4_typea>()};
                break;
            case target_type::passive_106kbps_iso_iec_14443_4_typeb_alt:
                *this = scanned_target{index_, entry.get<target_type::passive_106kbps_iso_iec_14443_4_typeb_alt>()};
                break;
            case target_type::dep_passive_106kbps:
                *this = scanned_target{index_, entry.get<target_type::dep_passive_106kbps>()};
                break;
            case target_type::dep_passive_212kbps:
                *this = scanned_target{index_, entry.get<target_type::dep_passive_212kbps>()};
                break;
            case target_type::dep_passive_424kbps:
                *this = scanned_target{index_, entry.get<target_type::dep_passive_424kbps>()};
                break;
            case target_type::dep_active_106kbps:
                *this = scanned_target{index_, entry.get<target_type::dep_active_106kbps>()};
                break;
            case target_type::dep_active_212kbps:
                *this = scanned_target{index_, entry.get<target_type::dep_active_212kbps>()};
                break;
            case target_type::dep_active_424kbps:
                *this = scanned_target{index_, entry.get<target_type::dep_active_424kbps>()};
                break;
        }
    }

    void scanner::update_in_rf_list(std::vector<any_poll_target> const &targets) {
        _in_rf.clear();
        for (std::size_t i = 0; i < targets.size(); ++i) {
            // Logical index is the 1-based index of the array
            _in_rf.emplace_back(std::uint8_t(i + 1), targets[i]);
        }
    }

    void scanner::stop() {
        _stop = true;
    }

    scanner::scanner(controller &ctrl, ms max_scan_interval) : _ctrl{&ctrl}, _timeout{max_scan_interval}, _stop{false} {}

    controller &scanner::ctrl() {
        return const_cast<controller &>(static_cast<scanner const *>(this)->ctrl());
    }

    controller const &scanner::ctrl() const {
        if (_ctrl == nullptr) {
            ESP_LOGE(PN532_TAG, "Called pn532::scanner::ctrl with a default-constructed scanner, I will now abort.");
            std::abort();
        }
        return *_ctrl;
    }

    void scanner::loop(scanner_responder &responder, bool init_and_test) {
        if (_ctrl == nullptr) {
            return;
        }
        // Perform some basic assessment
        if (init_and_test and not _ctrl->init_and_test()) {
            return;
        }
        ESP_LOGI(PN532_TAG, "Entered scanning loop.");
        _in_rf.clear();
        _rejection_list.clear();
        _stop = false;
        while (not _stop) {
            std::vector<target_type> tt = responder.get_scan_target_types(*this);
            if (tt.empty()) {
                return;
            }
            desfire::esp32::suppress_log suppress{ESP_LOG_ERROR, {PN532_TAG}};
            if (auto r = ctrl().initiator_auto_poll(tt, 3_b, poll_period::ms_150, max_scan_interval()); r) {
                update_in_rf_list(*r);
                update_rejection_list(responder);
                for (scanned_target const &st : in_rf()) {
                    if (is_in_rejection_list(st)) {
                        // Release
                        ctrl().initiator_release(st.index);
                    } else if (not responder.should_interact(*this, st)) {
                        // Put in rejection list and release
                        _rejection_list.emplace_back(st);
                        ctrl().initiator_release(st.index);
                    } else {
                        // Trigger events
                        suppress.restore();
                        responder.on_activation(*this, st);
                        const auto action = responder.interact(*this, st);
                        if (action == post_interaction::retain) {
                            continue;
                        }
                        if (action == post_interaction::abort) {
                            stop();
                        }
                        if (action == post_interaction::reject) {
                            _rejection_list.emplace_back(st);
                        }
                        responder.on_release(*this, st);
                        suppress.suppress();
                        ctrl().initiator_release(st.index);
                    }
                }
            } else {
                update_in_rf_list({});
                update_rejection_list(responder);
                responder.on_failed_scan(*this, r.error());
            }
        }
    }
}// namespace pn532