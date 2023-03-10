//
// Created by spak on 5/7/21.
//

#include <cassert>
#include <desfire/crypto_algo.hpp>
#include <desfire/log.h>
#include <desfire/protocol.hpp>
#include <mlab/mathutils.hpp>

namespace desfire {
    using mlab::bin_stream;
    using mlab::lsb16;
    using mlab::lsb32;
    using mlab::make_range;


    bool protocol_dummy::is_legacy() const {
        return true;
    }

    bool protocol_default::is_legacy() const {
        return false;
    }

    bool protocol_legacy::is_legacy() const {
        return true;
    }

    protocol_legacy::protocol_legacy(std::unique_ptr<desfire::crypto> crypto)
        : _iv{0, 0, 0, 0, 0, 0, 0, 0},
          _crypto{std::move(crypto)} {}

    desfire::crypto &protocol_legacy::crypto_provider() {
        return *_crypto;
    }

    protocol_legacy::block_t &protocol_legacy::get_zeroed_iv() {
        // Reset every time
        std::fill_n(std::begin(_iv), block_size, 0x00);
        return _iv;
    }


    protocol_legacy::mac_t protocol_legacy::compute_mac(range<bin_data::const_iterator> data) {
        static bin_data buffer{};

        // Resize the buffer and copy data
        buffer.clear();
        buffer.resize(mlab::next_multiple<std::size_t>(data.size(), block_size), 0x00);
        std::copy(std::begin(data), std::end(data), std::begin(buffer));

        // Return the first 4 bytes of the last block
        block_t &iv = get_zeroed_iv();
        crypto_provider().do_crypto(buffer.data_view(), make_range(iv), crypto_operation::mac);
        return {iv[0], iv[1], iv[2], iv[3]};
    }

    void protocol_legacy::init_session(bin_data const &random_data) {
        crypto_provider().init_session(random_data.data_view());
    }

    bool protocol_legacy::drop_padding_verify_crc(bin_data &d) {
        static const auto crc_fn = [](bin_data::const_iterator b, bin_data::const_iterator e, std::uint16_t init) -> std::uint16_t {
            return compute_crc16(range<std::uint8_t const *>{&*b, &*b + std::distance(b, e)}, init);
        };
        const auto [end_payload, did_verify] = find_crc_tail(std::begin(d), std::end(d), crc_fn, crc16_init, block_size, true);
        if (did_verify) {
            const std::size_t payload_length = std::distance(std::begin(d), end_payload);
            // In case of error, make sure to not get any weird size/number
            d.resize(std::max(payload_length, crc_size) - crc_size);
            return true;
        }
        return false;
    }

    void protocol_legacy::prepare_tx(bin_data &data, std::size_t offset, comm_mode mode) {
        if (offset >= data.size() or mode == comm_mode::plain) {
            return;// Nothing to do
        }
        if (mode == comm_mode::maced) {
            const auto mac = compute_mac(data.view(offset));
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_LOG_PREFIX " TX MAC", mac.data(), mac.size(), ESP_LOG_DEBUG);
            data << mac;
        } else {
            if (mode == comm_mode::ciphered) {
                data.reserve(offset + mlab::next_multiple(data.size() + crc_size - offset, block_size));
                data << lsb16 << compute_crc16(data.data_view(offset));
            } else {
                data.reserve(offset + mlab::next_multiple(data.size() - offset, block_size));
            }
            data.resize(offset + mlab::next_multiple(data.size() - offset, block_size), 0x00);
            crypto_provider().do_crypto(data.data_view(offset), make_range(get_zeroed_iv()), crypto_operation::encrypt);
        }
    }


    bool protocol_legacy::confirm_rx(bin_data &data, comm_mode mode) {
        if (data.size() == 1 or mode == comm_mode::plain) {
            // Just status byte, return as-is
            return true;
        }
        if (mode == comm_mode::maced) {
            bin_stream s{data};
            // Data, followed by mac, followed by status
            const auto data_view = s.read(s.remaining() - mac_size - 1);
            // Compute mac on data
            const mac_t computed_mac = compute_mac(data_view);
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_LOG_PREFIX " RX MAC", computed_mac.data(), computed_mac.size(), ESP_LOG_DEBUG);
            // Extract the transmitted mac
            mac_t rxd_mac{};
            s >> rxd_mac;
            if (rxd_mac == computed_mac) {
                // Good, move status byte at the end and drop the mac
                data[data.size() - mac_size - 1] = data[data.size() - 1];
                data.resize(data.size() - mac_size);
                return true;
            }
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_LOG_PREFIX " != MAC", rxd_mac.data(), rxd_mac.size(), ESP_LOG_DEBUG);
            return false;
        } else {
            // Pop the status byte
            const std::uint8_t status = data.back();
            data.pop_back();
            // Decipher what's left
            if (data.size() % block_size != 0) {
                DESFIRE_LOGW("Received enciphered data of length %u, not a multiple of the block size %u.",
                             data.size(), block_size);
                ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_LOG_PREFIX, data.data(), data.size(), ESP_LOG_WARN);
                return false;
            }
            crypto_provider().do_crypto(data.data_view(), make_range(get_zeroed_iv()), crypto_operation::decrypt);
            if (mode == comm_mode::ciphered) {
                // Truncate the padding and the crc
                const bool did_verify = drop_padding_verify_crc(data);
                // Reappend the status byte
                data << status;
                return did_verify;
            } else {
                // Reappend the status byte
                data << status;
                return true;
            }
        }
    }


    protocol_default::protocol_default(std::unique_ptr<crypto_with_cmac> crypto)
        : _iv{std::make_unique<std::uint8_t[]>(crypto->block_size())},
          _crypto{std::move(crypto)} {
        std::fill_n(_iv.get(), this->crypto_provider().block_size(), 0x00);
    }

    bool protocol_default::drop_padding_verify_crc(bin_data &d, std::uint8_t status) {
        const auto crc_fn = [=](bin_data::const_iterator b, bin_data::const_iterator e, std::uint32_t init) -> std::uint32_t {
            // Here we get a sequence [[ DATA || CRC ]]. But we need to compute the CRC on [[ DATA || STATUS || CRC ]].
            // So we split into two ranges, b..m and m..e, and chain the CRCs
            assert(std::distance(b, e) >= 0);
            const auto sequence_length = static_cast<std::size_t>(std::distance(b, e));
            const auto m = b + bin_data::difference_type(std::max(sequence_length, crc_size) - crc_size);
            assert(std::distance(b, m) >= 0);
            assert(std::distance(m, e) >= 0);
            // CRC of [[ DATA ]]
            const std::uint32_t crc_data = compute_crc32(range<std::uint8_t const *>{&*b, &*b + std::distance(b, m)}, init);
            // CRC of [[ DATA || STATUS ]] = crc32({status}, crc32([[ DATA ]], init)
            const std::uint32_t crc_data_status = compute_crc32(status, crc_data);
            // CRC of [[ DATA || STATUS || CRC ]] (should be 0)
            const std::uint32_t crc_full = compute_crc32(range<std::uint8_t const *>{&*m, &*m + std::distance(m, e)}, crc_data_status);
            return crc_full;
        };
        const auto [end_payload, did_verify] = find_crc_tail(std::begin(d), std::end(d), crc_fn, crc32_init, crypto_provider().block_size(), false);
        if (did_verify) {
            const std::size_t payload_length = std::distance(std::begin(d), end_payload);
            // In case of error, make sure to not get any weird size/number
            d.resize(std::max(payload_length, crc_size) - crc_size);
            return true;
        }
        return false;
    }

    crypto_with_cmac &protocol_default::crypto_provider() {
        return *_crypto;
    }

    range<std::uint8_t *> protocol_default::iv() {
        return {_iv.get(), _iv.get() + crypto_provider().block_size()};
    }

    void protocol_default::prepare_tx(bin_data &data, std::size_t offset, comm_mode mode) {
        if (mode == comm_mode::plain or mode == comm_mode::maced) {
            // Plain and MAC may still require to pass data through CMAC, unless specified otherwise
            // CMAC has to be computed on the whole data
            const auto cmac = crypto_provider().do_cmac(data.data_view(), iv());
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_LOG_PREFIX " TX MAC", cmac.data(), cmac.size(), ESP_LOG_DEBUG);
            if (mode == comm_mode::maced) {
                // Only MAC comm mode will actually append
                data << cmac;
            }
        } else {
            if (offset >= data.size()) {
                return;// Nothing to do
            }
            if (mode == comm_mode::ciphered) {
                data.reserve(offset + mlab::next_multiple(data.size() + crc_size - offset, crypto_provider().block_size()));
                // CRC has to be computed on the whole data
                data << lsb32 << compute_crc32(data);
            } else {
                data.reserve(offset + mlab::next_multiple(data.size() - offset, crypto_provider().block_size()));
            }
            data.resize(offset + mlab::next_multiple(data.size() - offset, crypto_provider().block_size()), 0x00);
            crypto_provider().do_crypto(data.data_view(offset), iv(), crypto_operation::encrypt);
        }
    }

    bool protocol_default::confirm_rx(bin_data &data, comm_mode mode) {
        if (data.size() == 1) {
            // Just status byte, return as-is
            return true;
        }
        if (mode == comm_mode::plain) {
            // Always pass data + status byte through CMAC
            // This will keep the IV in sync
            const auto cmac = crypto_provider().do_cmac(data.data_view(), iv());
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_LOG_PREFIX " RX MAC", cmac.data(), cmac.size(), ESP_LOG_DEBUG);
        } else if (mode == comm_mode::maced) {
            // [ data || maced || status ] -> [ data || status || maced ]; rotate mac_size + 1 bytes
            std::rotate(data.rbegin(), data.rbegin() + 1, data.rbegin() + mac_size + 1);
            // This will keep the IV in sync
            const auto computed_mac = crypto_provider().do_cmac(data.data_view(0, data.size() - mac_size), iv());
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_LOG_PREFIX " RX MAC", computed_mac.data(), computed_mac.size(), ESP_LOG_DEBUG);
            // Extract the transmitted maced
            bin_stream s{data};
            s.seek(data.size() - mac_size);
            crypto_with_cmac::mac_t rxd_mac{};
            s >> rxd_mac;
            if (rxd_mac == computed_mac) {
                // Good, drop the maced
                data.resize(data.size() - mac_size);
                return true;
            }
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_LOG_PREFIX " != MAC", rxd_mac.data(), rxd_mac.size(), ESP_LOG_DEBUG);
            return false;
        } else {
            // Pop the status byte
            const std::uint8_t status = data.back();
            data.pop_back();
            // Decipher what's left
            if (data.size() % crypto_provider().block_size() != 0) {
                DESFIRE_LOGW("Received enciphered data of length %u, not a multiple of the block size %u.",
                             data.size(), crypto_provider().block_size());
                ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_LOG_PREFIX, data.data(), data.size(), ESP_LOG_WARN);
                return false;
            }
            crypto_provider().do_crypto(data.data_view(), iv(), crypto_operation::decrypt);
            if (mode == comm_mode::ciphered) {
                // Truncate the padding and the crc
                const bool did_verify = drop_padding_verify_crc(data, status);
                // Reappend the status byte
                data << status;
                return did_verify;
            } else {
                // Reappend the status byte
                data << status;
                return true;
            }
        }
        return true;
    }

    void protocol_default::init_session(bin_data const &random_data) {
        crypto_provider().init_session(random_data.data_view());
        // Reset the IV
        std::fill_n(_iv.get(), this->crypto_provider().block_size(), 0x00);
    }

}// namespace desfire
