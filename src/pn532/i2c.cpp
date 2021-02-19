//
// Created by spak on 2/19/21.
//


#include "pn532/i2c.hpp"
#include <esp_log.h>
#include <memory>
#include <mlab/result.hpp>

#define PN532_I2C_TAG "PN532-I2C"

namespace pn532 {


    namespace {
        using mlab::prealloc;

        TickType_t duration_cast(std::chrono::milliseconds ms) {
            return ms.count() / portTICK_PERIOD_MS;
        }

    }// namespace
    namespace i2c {

        class promise {
            std::size_t _idx_of_buffer;
            friend class command;
            friend class response;
            friend class reuse_response;

            explicit promise(std::size_t idx_of_buffer) : _idx_of_buffer{idx_of_buffer} {}

            operator std::size_t() const {
                return _idx_of_buffer;
            }

        public:
            promise(promise const &) = delete;
            promise(promise &&) noexcept = default;
            promise &operator=(promise const &) = delete;
            promise &operator=(promise &&) noexcept = default;

            static promise invalid() {
                return promise{std::numeric_limits<std::size_t>::max()};
            }

            explicit operator bool() const {
                return _idx_of_buffer < std::numeric_limits<std::size_t>::max();
            }
        };

        class response {
            std::vector<bin_data> _buffers;

            friend class command;
            explicit response(std::vector<bin_data> &&buffers) : _buffers{std::move(buffers)} {}

        public:
            response(response const &) = delete;
            response(response &&) noexcept = default;
            response &operator=(response const &) = delete;
            response &operator=(response &&) noexcept = default;

            bin_data fulfill(promise const &p) {
                if (not p or p >= _buffers.size() or _buffers[p].empty()) {
                    ESP_LOGE(PN532_I2C_TAG, "Cannot fulfill an invalid promise.");
                    return {};
                }
                bin_data retval{};
                std::swap(retval, _buffers[p]);
                return retval;
            }
        };

        class reuse_response {
            std::vector<bin_data> const *_buffers;

            friend class command;
            explicit reuse_response(std::vector<bin_data> const &buffers) : _buffers{&buffers} {}

        public:
            reuse_response(reuse_response const &) = delete;
            reuse_response(reuse_response &&) noexcept = default;
            reuse_response &operator=(reuse_response const &) = delete;
            reuse_response &operator=(reuse_response &&) noexcept = default;

            bin_data const &fulfill(promise const &p) const {
                if (not p or p >= _buffers->size() or (*_buffers)[p].empty()) {
                    static bin_data _dummy{};
                    ESP_LOGE(PN532_I2C_TAG, "Cannot fulfill an invalid promise.");
                    return _dummy;
                }
                return (*_buffers)[p];
            }
        };

        enum struct error : std::int16_t {
            parameter_error = ESP_ERR_INVALID_ARG,
            fail = ESP_FAIL,
            invalid_state = ESP_ERR_INVALID_STATE,
            timeout = ESP_ERR_TIMEOUT
        };

        class command {
            i2c_cmd_handle_t _handle;
            std::vector<bin_data> _buffers;
            bool _sealed;
            bool _reusable;

            std::pair<std::uint8_t *, promise> prepare_buffer(std::size_t size) {
                _buffers.push_back(bin_data{prealloc(size)});
                _buffers.back().resize(size, 0x00);
                return {_buffers.back().data(), promise(_buffers.size() - 1)};
            }

            bool assert_not_sealed() const {
                if (_sealed) {
                    ESP_LOGE(PN532_I2C_TAG, "This command was already run and cannot be changed.");
                    return false;
                }
                return true;
            }

            mlab::result<error> run_internal(i2c_port_t port, std::chrono::milliseconds timeout) {
                if (not _reusable) {
                    ESP_LOGE(PN532_I2C_TAG, "This command was already run and cannot be reused.");
                }
                _sealed = true;
                const auto result_code = i2c_master_cmd_begin(port, _handle, duration_cast(timeout));
                if (result_code != ESP_OK) {
                    return static_cast<error>(result_code);
                }
                return mlab::result_success;
            }

        public:
            struct reuse_t {};
            static constexpr reuse_t reuse{};

            command() : _handle{i2c_cmd_link_create()}, _buffers{}, _sealed{false}, _reusable{true} {
                i2c_master_start(_handle);
            }

            ~command() {
                i2c_cmd_link_delete(_handle);
            }
            command(command const &) = delete;
            command(command &&) noexcept = default;
            command &operator=(command const &) = delete;
            command &operator=(command &&) noexcept = default;

            void write_byte(std::uint8_t b, bool enable_ack_check) {
                if (assert_not_sealed()) {
                    if (i2c_master_write_byte(_handle, b, enable_ack_check) != ESP_OK) {
                        ESP_LOGE(PN532_I2C_TAG, "i2c_master_write_byte failed.");
                    }
                }
            }

            void write(bin_data const &data, bool enable_ack_check) {
                if (assert_not_sealed()) {
                    if (i2c_master_write(_handle, const_cast<std::uint8_t *>(data.data()), data.size(), enable_ack_check) != ESP_OK) {
                        ESP_LOGE(PN532_I2C_TAG, "i2c_master_write failed.");
                    }
                }
            }

            promise read_byte(i2c_ack_type_t ack) {
                if (assert_not_sealed()) {
                    auto raw_ptr_promise = prepare_buffer(1);
                    if (i2c_master_read_byte(_handle, raw_ptr_promise.first, ack) != ESP_OK) {
                        ESP_LOGE(PN532_I2C_TAG, "i2c_master_read_byte failed.");
                    }
                    return std::move(raw_ptr_promise.second);
                }
                return promise::invalid();
            }

            promise read(std::size_t length, i2c_ack_type_t ack) {
                if (assert_not_sealed()) {
                    auto raw_ptr_promise = prepare_buffer(length);
                    if (i2c_master_read(_handle, raw_ptr_promise.first, length, ack) != ESP_OK) {
                        ESP_LOGE(PN532_I2C_TAG, "i2c_master_read failed.");
                    }
                    return std::move(raw_ptr_promise.second);
                }
                return promise::invalid();
            }

            void read_into(bin_data &bd, i2c_ack_type_t ack) {
                if (assert_not_sealed()) {
                    if (i2c_master_read(_handle, bd.data(), bd.size(), ack) != ESP_OK) {
                        ESP_LOGE(PN532_I2C_TAG, "i2c_master_read with custom buffer failed.");
                    }
                }
            }

            void stop() {
                if (assert_not_sealed()) {
                    if (i2c_master_stop(_handle) != ESP_OK) {
                        ESP_LOGE(PN532_I2C_TAG, "i2c_master_stop failed.");
                    }
                }
            }

            mlab::result<error, response> operator()(i2c_port_t port, std::chrono::milliseconds timeout) {
                const auto res_run = run_internal(port, timeout);
                if (not res_run) {
                    return res_run.error();
                }
                return response(std::move(_buffers));
            }

            mlab::result<error, reuse_response> operator()(i2c_port_t port, std::chrono::milliseconds timeout, reuse_t) {
                const auto res_run = run_internal(port, timeout);
                if (not res_run) {
                    return res_run.error();
                }
                return reuse_response(_buffers);
            }
        };
    }// namespace i2c

    bool i2c_channel::wake() {
        reduce_timeout rt{ms{100}};
        // pn532 should be waken up when it hears its address on the I2C bus
        i2c::command cmd;
        cmd.write_byte(slave_address_to_write(), true);
        cmd.stop();
        return bool(cmd(_port, rt.remaining()));
    }

    bool i2c_channel::prepare_receive(std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};

        i2c::command cmd;
        cmd.write_byte(slave_address_to_read(), true);
        const i2c::promise p_status = cmd.read_byte(I2C_MASTER_LAST_NACK);
        cmd.stop();

        while (rt) {
            const auto res_resp = cmd(_port, rt.remaining(), i2c::command::reuse);
            if (not res_resp) {
                /// @todo Log message
                return false;
            }
            // Check returned status byte
            bin_data const &status_data = res_resp->fulfill(p_status);
            if (status_data.size() != 1) {
                /// @todo Log message
                return false;// Malformed
            } else if (status_data.front() != 0x00) {
                return true;// Ready to receive
            }
            // Retry after 10 ms
            vTaskDelay(duration_cast(std::chrono::milliseconds{10}));
        };
        return false;// Timeout
    }

    bool i2c_channel::send_raw(const bin_data &data, std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};
        i2c::command cmd;
        cmd.write_byte(slave_address_to_write(), true);
        cmd.write(data, true);
        cmd.stop();
        return bool(cmd(_port, rt.remaining()));
    }

    bool i2c_channel::receive_raw(bin_data &data, const std::size_t length, std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};
        data.clear();
        data.resize(length);

        i2c::command cmd;
        cmd.read_into(data, I2C_MASTER_ACK);
        cmd.stop();
        return bool(cmd(_port, rt.remaining()));
    }
}// namespace pn532
