//
// Created by spak on 3/23/21.
//

#include "facility.hpp"
#include "helpers.hpp"
#include <catch.hpp>
#include <desfire/fs.hpp>
#include <mlab/strutils.hpp>
#include <numeric>

namespace ut {
    using namespace mlab_literals;

    TEST_CASE("0040 Desfire files") {
        const auto chn = GENERATE(channel_type::hsu, channel_type::i2c, channel_type::i2c_irq, channel_type::spi, channel_type::spi_irq);
        SECTION(to_string(chn)) {
            if (not facility::instance().supports(chn)) {
                SKIP();
            }

            auto ctrl = facility::instance().activate_channel(chn);
            REQUIRE(ctrl);

            auto tag = facility::instance().get_card();
            REQUIRE(tag);

            ensure_card_formatted raii1{tag};

            const auto cipher = GENERATE(desfire::cipher_type::des, desfire::cipher_type::des3_2k,
                                         desfire::cipher_type::des3_3k, desfire::cipher_type::aes128);
            SECTION(to_string(cipher)) {
                ensure_demo_app raii2{tag, demo_app{cipher}};

                REQUIRE(desfire::fs::login_app(*tag, raii2.app.aid, raii2.app.master_key));

                const auto security = GENERATE(desfire::file_security::none, desfire::file_security::authenticated, desfire::file_security::encrypted);
                SECTION(mlab::concatenate({"Security: ", to_string(security)})) {

                    const auto free_access = GENERATE(true, false);
                    SECTION(mlab::concatenate({"Free access: ", free_access ? "Y" : "N"})) {

                        static constexpr desfire::file_id fid = 0x00;
                        static constexpr desfire::data_file_settings dfs{0x100};
                        static constexpr desfire::record_file_settings rfs{8, 2};
                        static constexpr desfire::value_file_settings vfs{-10, 10, 0, true};

                        mlab::bin_data test_payload;
                        test_payload.resize(0x100);
                        std::iota(std::begin(test_payload), std::end(test_payload), 0x00);

                        // Select either all keys, or one key (the one we are using)
                        const desfire::common_file_settings gfs{
                                security,
                                free_access ? desfire::file_access_rights{desfire::free_access} : desfire::file_access_rights{0_b}};

                        SECTION("Standard data file") {
                            REQUIRE(tag->create_file(fid, desfire::file_settings<desfire::file_type::standard>{gfs, dfs}));
                            REQUIRE(tag->write_data(fid, test_payload, desfire::trust_card));
                            const auto r_read = tag->read_data(fid, desfire::trust_card, 0, test_payload.size());
                            CHECKED_IF(r_read) {
                                CHECK(test_payload == *r_read);
                            }
                        }

                        SECTION("Backup data file") {
                            REQUIRE(tag->create_file(fid, desfire::file_settings<desfire::file_type::backup>{gfs, dfs}));
                            REQUIRE(tag->write_data(fid, test_payload, desfire::trust_card));

                            const auto r_read_before_commit = tag->read_data(fid, desfire::trust_card, 0, test_payload.size());
                            CHECKED_IF(r_read_before_commit) {
                                CHECK(r_read_before_commit->size() == test_payload.size());
                                const auto all_zero = std::all_of(std::begin(*r_read_before_commit), std::end(*r_read_before_commit),
                                                                  [](auto b) { return b == 0; });
                                CHECK(all_zero);
                            }

                            REQUIRE(tag->commit_transaction());
                            const auto r_read = tag->read_data(fid, desfire::trust_card, 0, test_payload.size());
                            CHECKED_IF(r_read) {
                                CHECK(*r_read == test_payload);
                            }
                        }

                        SECTION("Value file") {
                            REQUIRE(tag->create_file(fid, desfire::file_settings<desfire::file_type::value>{gfs, vfs}));

                            auto res_read = tag->get_value(fid, desfire::trust_card);
                            CHECKED_IF(res_read) {
                                CHECK(*res_read == 0);
                            }

                            REQUIRE(tag->credit(fid, 2, desfire::trust_card));

                            res_read = tag->get_value(fid, desfire::trust_card);
                            CHECKED_IF(res_read) {
                                CHECK(*res_read == 0);// Did not commit yet
                            }

                            REQUIRE(tag->commit_transaction());

                            res_read = tag->get_value(fid, desfire::trust_card);
                            CHECKED_IF(res_read) {
                                CHECK(*res_read == 2);
                            }

                            REQUIRE(tag->debit(fid, 5, desfire::trust_card));
                            REQUIRE(tag->commit_transaction());

                            res_read = tag->get_value(fid, desfire::trust_card);
                            CHECKED_IF(res_read) {
                                CHECK(*res_read == -3);
                            }
                        }

                        SECTION("Record file") {
                            using record_t = std::array<std::uint8_t, 8>;
                            const mlab::bin_data nibble = {0x00, 0x01, 0x02, 0x03};

                            SECTION("Linear") {
                                REQUIRE(tag->create_file(fid, desfire::file_settings<desfire::file_type::linear_record>{gfs, rfs}));
                            }

                            SECTION("Cyclic") {
                                REQUIRE(tag->create_file(fid, desfire::file_settings<desfire::file_type::cyclic_record>{gfs, rfs}));
                            }

                            auto r_settings = tag->get_file_settings(fid);
                            CHECKED_IF(r_settings) {
                                CHECK(r_settings->record_settings().record_count == 0);
                            }

                            REQUIRE(tag->write_record(fid, nibble, desfire::trust_card, 4));
                            REQUIRE(tag->commit_transaction());

                            r_settings = tag->get_file_settings(fid);
                            CHECKED_IF(r_settings) {
                                CHECK(r_settings->record_settings().record_count == 1);
                            }

                            const auto r_records = tag->template read_parse_records<record_t>(fid, desfire::trust_card, 0, desfire::all_records);

                            CHECKED_IF(r_records) {
                                CHECK(r_records->size() == 1);
                                CHECK(r_records->front() == record_t{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03});
                            }

                            REQUIRE(tag->clear_record_file(fid));
                            REQUIRE(tag->commit_transaction());

                            r_settings = tag->get_file_settings(fid);
                            CHECKED_IF(r_settings) {
                                CHECK(r_settings->record_settings().record_count == 0);
                            }
                        }

                        REQUIRE(tag->change_file_settings(fid, gfs, desfire::trust_card));
                        REQUIRE(tag->delete_file(fid));
                    }
                }
            }
        }
    }

}// namespace ut