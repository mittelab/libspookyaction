//
// Created by spak on 3/23/21.
//

#include "test_desfire_main.hpp"
#include <catch.hpp>
#include <numeric>

namespace ut::desfire_files {
    using namespace ut::desfire;
    using namespace ut::pn532;

    TEMPLATE_TEST_CASE_METHOD_SIG(card_fixture, "0040 Desfire files", "",
                                  ((channel_type CT), CT),
                                  channel_type::hsu, channel_type::i2c, channel_type::i2c_irq, channel_type::spi, channel_type::spi_irq) {
        if (not channel_is_supported(CT)) {
            SKIP("Unsupported channel type " << ut::pn532::to_string(CT));
        }

        REQUIRE(*this);

        // Create a temp app which will auto-delete
        const auto cipher = GENERATE(cipher_type::des, cipher_type::des3_2k, cipher_type::des3_3k, cipher_type::aes128);
        app_fixture_setup fmt{*this->mifare, cipher};

        fmt.select_and_authenticate();

        const auto security = GENERATE(file_security::none, file_security::authenticated, file_security::encrypted);
        const auto free_access = GENERATE(true, false);

        static constexpr file_id fid = 0x00;
        static constexpr data_file_settings dfs{0x100};
        static constexpr record_file_settings rfs{8, 2};
        static constexpr value_file_settings vfs{-10, 10, 0, true};

        mlab::bin_data test_payload;
        test_payload.resize(0x100);
        std::iota(std::begin(test_payload), std::end(test_payload), 0x00);

        // Select either all keys, or one key (the one we are using)
        const common_file_settings gfs{security, free_access ? file_access_rights{desfire::free_access} : file_access_rights{0_b}};

        SECTION("Standard") {
            REQUIRE(this->mifare->create_file(fid, file_settings<file_type::standard>{gfs, dfs}));
            REQUIRE(this->mifare->write_data(fid, test_payload, trust_card));
            const auto r_read = this->mifare->read_data(fid, trust_card, 0, test_payload.size());
            CHECKED_IF(r_read) {
                CHECK(test_payload == *r_read);
            }
        }

        SECTION("Backup") {
            REQUIRE(this->mifare->create_file(fid, file_settings<file_type::backup>{gfs, dfs}));
            REQUIRE(this->mifare->write_data(fid, test_payload, trust_card));

            const auto r_read_before_commit = this->mifare->read_data(fid, trust_card, 0, test_payload.size());
            CHECKED_IF(r_read_before_commit) {
                CHECK(r_read_before_commit->size() == test_payload.size());
                const auto all_zero = std::all_of(std::begin(*r_read_before_commit), std::end(*r_read_before_commit), [](auto b) { return b == 0; });
                CHECK(all_zero);
            }

            REQUIRE(this->mifare->commit_transaction());
            const auto r_read = this->mifare->read_data(fid, trust_card, 0, test_payload.size());
            CHECKED_IF(r_read) {
                CHECK(*r_read == test_payload);
            }
        }

        SECTION("Value") {
            REQUIRE(this->mifare->create_file(fid, file_settings<file_type::value>{gfs, vfs}));

            auto res_read = this->mifare->get_value(fid, trust_card);
            CHECKED_IF(res_read) {
                CHECK(*res_read == 0);
            }

            REQUIRE(this->mifare->credit(fid, 2, trust_card));

            res_read = this->mifare->get_value(fid, trust_card);
            CHECKED_IF(res_read) {
                CHECK(*res_read == 0);// Did not commit yet
            }

            REQUIRE(this->mifare->commit_transaction());

            res_read = this->mifare->get_value(fid, trust_card);
            CHECKED_IF(res_read) {
                CHECK(*res_read == 2);
            }

            REQUIRE(this->mifare->debit(fid, 5, trust_card));
            REQUIRE(this->mifare->commit_transaction());

            res_read = this->mifare->get_value(fid, trust_card);
            CHECKED_IF(res_read) {
                CHECK(*res_read == -3);
            }
        }

        SECTION("Record") {
            using record_t = std::array<std::uint8_t, 8>;
            const mlab::bin_data nibble = {0x00, 0x01, 0x02, 0x03};

            SECTION("Linear") {
                REQUIRE(this->mifare->create_file(fid, file_settings<file_type::linear_record>{gfs, rfs}));
            }

            SECTION("Cyclic") {
                REQUIRE(this->mifare->create_file(fid, file_settings<file_type::cyclic_record>{gfs, rfs}));
            }

            auto r_settings = this->mifare->get_file_settings(fid);
            CHECKED_IF(r_settings) {
                CHECK(r_settings->record_settings().record_count == 0);
            }

            REQUIRE(this->mifare->write_record(fid, nibble, trust_card, 4));
            REQUIRE(this->mifare->commit_transaction());

            r_settings = this->mifare->get_file_settings(fid);
            CHECKED_IF(r_settings) {
                CHECK(r_settings->record_settings().record_count == 1);
            }

            const auto r_records = this->mifare->template read_parse_records<record_t>(fid, trust_card, 0, all_records);

            CHECKED_IF(r_records) {
                CHECK(r_records->size() == 1);
                CHECK(r_records->front() == record_t{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03});
            }

            REQUIRE(this->mifare->clear_record_file(fid));
            REQUIRE(this->mifare->commit_transaction());

            r_settings = this->mifare->get_file_settings(fid);
            CHECKED_IF(r_settings) {
                CHECK(r_settings->record_settings().record_count == 0);
            }
        }

        REQUIRE(this->mifare->change_file_settings(fid, gfs, trust_card));
        REQUIRE(this->mifare->delete_file(fid));
    }

}// namespace ut::desfire_files