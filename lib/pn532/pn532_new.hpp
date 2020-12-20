//
// Created by Pietro Saccardi on 20/12/2020.
//

#ifndef APERTURAPORTA_PN532_HPP
#define APERTURAPORTA_PN532_HPP


#include <array>
#include <vector>
#include <cstddef>
#include <limits>
#include <mbcontroller.h>
#include "instructions_new.hpp"

namespace pn532 {

    template <class Iterator>
    struct range {
        Iterator it_begin;
        Iterator it_end;
        inline Iterator begin() const { return it_begin; }
        inline Iterator end() const { return it_end; }
    };

    template <class Iterator>
    inline range<Iterator> make_range(Iterator begin, Iterator end) {
        return {begin, end};
    }


    class bin_data {
        std::vector<std::uint8_t> _data;
    public:
        using iterator = std::vector<std::uint8_t>::iterator;
        using const_iterator = std::vector<std::uint8_t>::const_iterator;

        bin_data() = default;

        inline bin_data(std::initializer_list<std::uint8_t> data);
        inline explicit bin_data(std::vector<std::uint8_t> &&data);

        template <class ByteIterator>
        inline bin_data(ByteIterator begin, ByteIterator end);

        inline const_iterator begin() const;
        inline const_iterator end() const;

        [[nodiscard]] inline std::size_t size() const;

        inline range<const_iterator> view(std::size_t start = 0,
                                          std::size_t length = std::numeric_limits<std::size_t>::max()) const;

        template <class ByteIterator>
        void append(ByteIterator begin, ByteIterator end);
        inline void append(std::uint8_t byte);


        template <class ByteContainer>
        inline bin_data &operator<<(ByteContainer const &data);
        inline bin_data &operator<<(std::uint8_t byte);

        template <class ...ByteOrByteContainers>
        static bin_data chain(ByteOrByteContainers&& ...others);
    };

    namespace frames {
        bin_data get_information(command cmd, bin_data const &payload);

        bin_data const &get_ack();
        bin_data const &get_nack();
        bin_data const &get_error();
    }

    class nfc {
        uart_port_t _uart;
    public:
        inline explicit nfc(uart_port_t uart);

        nfc(nfc const &) = delete;
        nfc(nfc &&) = default;

        nfc &operator=(nfc const &) = delete;
        nfc &operator=(nfc &&) = default;


    };



    nfc::nfc(uart_port_t uart) : _uart{uart} {}

    bin_data::bin_data(std::initializer_list<std::uint8_t> data) : _data{data} {}
    bin_data::bin_data(std::vector<std::uint8_t> &&data) : _data{std::move(data)} {}

    template <class ByteIterator>
    bin_data::bin_data(ByteIterator begin, ByteIterator end) : _data{begin, end} {}

    template <class ByteIterator>
    void bin_data::append(ByteIterator begin, ByteIterator end) {
        _data.reserve(_data.size() + std::distance(begin, end));
        std::copy(begin, end, std::back_inserter(_data));
    }

    void bin_data::append(std::uint8_t byte) {
        _data.push_back(byte);
    }

    template <class ByteContainer>
    bin_data &bin_data::operator<<(ByteContainer const &data) {
        append(std::begin(data), std::end(data));
        return *this;
    }

    bin_data &bin_data::operator<<(std::uint8_t byte) {
        append(byte);
        return *this;
    }

    bin_data::const_iterator bin_data::begin() const {
        return std::begin(_data);
    }

    bin_data::const_iterator bin_data::end() const {
        return std::end(_data);
    }

    std::size_t bin_data::size() const {
        return _data.size();
    }

    namespace impl {
        template <class ByteOrByteContainer, class ...Args>
        struct chainer {
            inline void operator()(bin_data &target, ByteOrByteContainer &&data, Args &&... others) const {
                chainer<ByteOrByteContainer>{}(target, std::forward<ByteOrByteContainer>(data));
                chainer<Args...>{}(target, std::forward<Args>(others)...);
            }
        };

        template <class ByteOrByteContainer>
        struct chainer<ByteOrByteContainer> {
            inline void operator()(bin_data &target, ByteOrByteContainer const &data) const {
                target << data;
            }
        };
    }

    template <class ...ByteOrByteContainers>
    bin_data bin_data::chain(ByteOrByteContainers && ...others) {
        bin_data retval{};
        impl::chainer<ByteOrByteContainers...>{}(retval, std::forward<ByteOrByteContainers>(others)...);
        return retval;
    }


    range<bin_data::const_iterator> bin_data::view(std::size_t start, std::size_t length) const {
        start = std::min(start, size() - 1);
        length = std::min(length, size() - start - 1);
        return make_range(begin() + start, begin() + start + length);
    }


}


#endif //APERTURAPORTA_PN532_HPP
