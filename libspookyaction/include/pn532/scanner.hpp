//
// Created by spak on 1/18/23.
//

#ifndef PN532_SCANNER_HPP
#define PN532_SCANNER_HPP

#include <pn532/controller.hpp>

namespace pn532 {

    /**
     * @brief Action to perform after the scanner has interacted with the tag.
     */
    enum struct post_interaction {
        reject, ///@< Releases the target and prevents re-reading until out of the RF field
        release, ///@< Releases the target, but will re-activate if not removed
        retain, ///@< Does not deactivate the target
        abort ///<@ Aborts the scan
    };

    /**
     * @brief Lightweight wrapper for a generic target detected by @ref controller.
     */
    struct scanned_target {
        /**
         * @brief Logical index to use e.g. in @ref controller::initiator_data_exchange.
         */
        std::uint8_t index = std::numeric_limits<std::uint8_t>::max();
        /**
         * @brief Type of detected tareget.
         */
        target_type type = target_type::generic_passive_106kbps;
        /**
         * @brief Some sort of unique NFC identifier.
         * @note This is not always available for all types of targets. When possible, a NFCID3t will be used.
         *  Otherwise it falls back to NFCID2t, NFCID1t, Jewel ID (for jewel tags), PUPI (Pseudo-Unique PICC
         *  Identifier, part of the ATQB response) and eventually, the ATQB response itself.
         */
        std::vector<std::uint8_t> nfcid{};

        scanned_target() = default;

        template <target_type Type>
        scanned_target(std::uint8_t index_, poll_entry<Type> const &entry);

        scanned_target(std::uint8_t index_, any_target const &entry);

        [[nodiscard]] bool operator==(scanned_target const &other) const;
        [[nodiscard]] bool operator!=(scanned_target const &other) const;
    };

    class scanner;

    /**
     * @brief Abstract class that reacts and controls a scanner routine.
     */
    struct scanner_responder {
        /**
         * @brief Called before interaction with @p target begins.
         * The target has been activated and was not rejected.
         * @note Rejected targets will not trigger this call.
         */
        virtual void on_activation(scanner &scanner, scanned_target const &target) {}

        /**
         * @brief Called immediately before the release of @p target.
         * The target has been interacted with, and now it about to be released.
         * @note Targets that have been not interacted with (e.g. because rejected) will not trigger this call.
         */
        virtual void on_release(scanner &scanner, scanned_target const &target) {}

        /**
         * @brief Called when @p target has provably left the RF field.
         * This happens e.g. because it was not present in another scan, or the scan timed out.
         * @note Stopping with @ref stop the loop might cause this call to be skipped.
         */
        virtual void on_leaving_rf(scanner &scanner, scanned_target const &target) {}

        /**
         * @brief Called when @ref controller::in_auto_poll fails, e.g. due to timeout.
         * This is a normal condition as a scan with no tags will time out.
         */
        virtual void on_failed_scan(scanner &scanner, channel::error err) {}

        /**
         * @brief Selects which targets the scanner should check.
         * @warning The implementor should fill @p targets with at least one target type, otherwise the loop will exit.
         */
        virtual void get_scan_target_types(scanner &scanner, std::vector<target_type> &targets) const {
            targets = controller::poll_all_targets;
        }

        /**
         * @brief Extra filter deciding whether a given target should be interacted with or not.
         * All rejected targets are automatically marked as "should not interact" until when they leave the RF
         * field. This is used e.g. to mark blocklisted tokens.
         */
        [[nodiscard]] virtual bool should_interact(scanner &scanner, scanned_target const &target) const {
            return true;
        }

        /**
         * @brief Core routine that interacts with the target.
         */
        [[nodiscard]] virtual post_interaction interact(scanner &scanner, scanned_target const &target) {
            return post_interaction::reject;
        }

        virtual ~scanner_responder() = default;
    };

    /**
     * @brief Helper class that continuously scans for targets and calls @ref scanner_responder methods in response.
     * This class can automatically track rejected targets and ignore them until they have left the RF field.
     */
    class scanner {
        controller *_ctrl = nullptr;
        ms _timeout = 5s;
        bool _stop = false;
        std::vector<scanned_target> _rejection_list{};
        std::vector<scanned_target> _in_rf{};

        /**
         * Remove all targets that are not in RF from the rejection list.
         * Trigger @ref on_leaving_rf on targets that are not found anymore.
         */
        void update_rejection_list(scanner_responder &responder);

        /**
         * Rebuilds the @ref in_rf list starting from the current targets.
         */
        void update_in_rf_list(std::vector<any_target> const &targets);

        /**
         * Tests whether a given target is in the rejection list.
         */
        [[nodiscard]] bool is_in_rejection_list(scanned_target const &target) const;

    public:
        scanner() = default;
        explicit scanner(controller &ctrl, ms max_scan_interval = 5s);

        scanner(scanner const &) = delete;
        scanner &operator=(scanner const &) = delete;
        scanner(scanner &&) noexcept = default;
        scanner &operator=(scanner &&) noexcept = default;

        /**
         * @brief List of targets currently in the RF field.
         */
        [[nodiscard]] inline std::vector<scanned_target> const &in_rf() const;

        /**
         * Maximum interval of time after which @ref loop is guaranteed to check any @ref stop condition.
         * This corresponds to the timeout time of @ref controller::initiator_auto_poll
         */
        [[nodiscard]] inline ms max_scan_interval() const;
        inline void set_max_scan_interval(ms timeout);

        /**
         * @brief Main loop scanning for tags.
         */
        void loop(scanner_responder &responder);

        /**
         * @warning Calling this with a default-constructed @ref scanner will abort.
         */
        [[nodiscard]] controller &ctrl();
        [[nodiscard]] controller const &ctrl() const;

        /**
         * @brief Aborts @ref loop.
         * This will only take effect at the next scan attempt, thus it will take @ref max_scan_interval ms
         * before @ref loop actually exits. This function returns immediately.
         */
        void stop();
    };
}


namespace pn532 {

    ms scanner::max_scan_interval() const {
        return _timeout;
    }

    void scanner::set_max_scan_interval(ms timeout) {
        _timeout = timeout;
    }

    std::vector<scanned_target> const &scanner::in_rf() const {
        return _in_rf;
    }

    template <target_type Type>
    scanned_target::scanned_target(std::uint8_t index_, poll_entry<Type> const &entry) : index{index_}, type{Type} {
        static constexpr auto BM = bits::baudrate_modulation_of_target<Type>;
        if constexpr (std::is_base_of_v<poll_entry_dep_passive<BM>, poll_entry<Type>>) {
            // Obtain NFCID3t from the atr_res_info, and the index from the target bit
            index = entry.logical_index;
            nfcid.resize(entry.atr_info.nfcid_3t.size());
            std::copy(std::begin(entry.atr_info.nfcid_3t), std::end(entry.atr_info.nfcid_3t), std::begin(nfcid));
        } else if constexpr (std::is_base_of_v<bits::target<BM>, poll_entry<Type>>) {
            // Obtain the logical index from the target bit, and then differentiate
            index = entry.logical_index;
            if constexpr (BM == baudrate_modulation::kbps106_iso_iec_14443_typea) {
                nfcid = entry.info.nfcid;
            } else if constexpr (BM == baudrate_modulation::kbps212_felica_polling or BM == baudrate_modulation::kbps424_felica_polling) {
                nfcid.resize(entry.info.nfcid_2t.size());
                std::copy(std::begin(entry.info.nfcid_2t), std::end(entry.info.nfcid_2t), std::begin(nfcid));
            } else if constexpr (BM == baudrate_modulation::kbps106_iso_iec_14443_3_typeb) {
                // Slice off the PUPI (Pseudo-Unique PICC Identifier) out of the atqb response
                if (entry.info.atqb_response.size() >= 5) {
                    nfcid.resize(4);
                    std::copy_n(std::begin(entry.info.atqb_response) + 1, 4, std::begin(nfcid));
                } else {
                    // Just use the whole atqb response
                    nfcid.resize(entry.info.atqb_response.size());
                    std::copy(std::begin(entry.info.atqb_response), std::end(entry.info.atqb_response), std::begin(nfcid));
                }
            } else if constexpr (BM == baudrate_modulation::kbps106_innovision_jewel_tag) {
                // Use jewel id
                nfcid.resize(entry.info.jewel_id.size());
                std::copy(std::begin(entry.info.jewel_id), std::end(entry.info.jewel_id), std::begin(nfcid));
            }
        } else {
            static_assert(std::is_base_of_v<poll_entry_with_atr, poll_entry<Type>>);
            // Obtain NFCID3t from the atr_res_info, we cannot do anything about the index
            nfcid.resize(entry.atr_info.nfcid_3t.size());
            std::copy(std::begin(entry.atr_info.nfcid_3t), std::end(entry.atr_info.nfcid_3t), std::begin(nfcid));
        }
    }
}
#endif//PN532_SCANNER_HPP
