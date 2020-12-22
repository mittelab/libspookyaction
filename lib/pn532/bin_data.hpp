//
// Created by Pietro Saccardi on 21/12/2020.
//

#ifndef APERTURAPORTA_BIN_DATA_HPP
#define APERTURAPORTA_BIN_DATA_HPP

#include <cstdint>
#include <vector>
#include <algorithm>

namespace pn532 {

    template<class Iterator>
    struct range {
        Iterator it_begin;
        Iterator it_end;

        inline Iterator begin() const { return it_begin; }

        inline Iterator end() const { return it_end; }
    };

    template<class Iterator>
    inline range<Iterator> make_range(Iterator begin, Iterator end) {
        return {begin, end};
    }

    struct bit_ref {
        std::uint8_t &byte;
        const std::uint8_t index;
        const std::uint8_t write_mask;

        inline bit_ref &operator=(bool v);

        inline operator bool() const;
    };

    class bin_data : public std::vector<std::uint8_t> {
    public:
        bin_data() = default;

        inline bin_data(std::initializer_list<std::uint8_t> data);

        inline explicit bin_data(std::vector<std::uint8_t> &&data);

        template<class ByteIterator>
        inline bin_data(ByteIterator begin, ByteIterator end);

        inline range<const_iterator> view(std::size_t start = 0,
                                          std::size_t length = std::numeric_limits<std::size_t>::max()) const;

        template<class ByteIterator>
        void push_back(ByteIterator begin, ByteIterator end);

        using std::vector<std::uint8_t>::push_back;

        template<class ByteContainer>
        inline bin_data &operator<<(ByteContainer const &data);

        inline bin_data &operator<<(std::uint8_t byte);

        template<class ...ByteOrByteContainers>
        static bin_data chain(ByteOrByteContainers &&...others);
    };
}

namespace pn532 {

    bin_data::bin_data(std::initializer_list<std::uint8_t> data) : std::vector<uint8_t>{data} {}
    bin_data::bin_data(std::vector<std::uint8_t> &&data) : std::vector<uint8_t>{std::move(data)} {}

    template <class ByteIterator>
    bin_data::bin_data(ByteIterator begin, ByteIterator end) : std::vector<uint8_t>{begin, end} {}

    template <class ByteIterator>
    void bin_data::push_back(ByteIterator begin, ByteIterator end) {
        reserve(size() + std::distance(begin, end));
        std::copy(begin, end, std::back_inserter(*this));
    }

    template <class ByteContainer>
    bin_data &bin_data::operator<<(ByteContainer const &data) {
        push_back(std::begin(data), std::end(data));
        return *this;
    }

    bin_data &bin_data::operator<<(std::uint8_t byte) {
        push_back(byte);
        return *this;
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

    bit_ref &bit_ref::operator=(bool v) {
        if (0 != (write_mask & (1 << index))) {
            if (v) {
                byte |= 1 << index;
            } else {
                byte &= ~(1 << index);
            }
        }
        return *this;
    }

    bit_ref::operator bool() const {
        return 0 != (byte & (1 << index));
    }


}

#endif //APERTURAPORTA_BIN_DATA_HPP
