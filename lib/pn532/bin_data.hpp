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

        inline explicit bin_data(range<const_iterator> const &view);

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

    enum struct stream_ref {
        beg,
        pos,
        end
    };

    class bin_stream {
        bin_data const *_data = nullptr;
        std::size_t _pos = 0;
        bool _bad = false;

        inline std::size_t get_ref(stream_ref ref) const;
    public:
        bin_stream() = default;
        inline explicit bin_stream(bin_data const &data, std::size_t position = 0);

        inline void seek(std::intptr_t offset, stream_ref ref = stream_ref::beg);
        inline std::size_t tell(stream_ref ref = stream_ref::beg) const;

        inline std::size_t remaining() const;

        template <class OutputIterator>
        std::size_t read(OutputIterator it, std::size_t n);

        inline range<bin_data::const_iterator> read(std::size_t n);

        inline std::uint8_t pop();

        inline bool good() const;
        inline bool eof() const;
        inline bool bad() const;

        inline void set_bad();
        inline void clear_bad();
    };

    inline bin_stream &operator>>(bin_stream &s, std::uint8_t &byte);
    inline bin_stream &operator>>(bin_stream &s, std::uint16_t &word);

    template <std::size_t Length>
    bin_stream &operator>>(bin_stream &s, std::array<std::uint8_t, Length> &out);
}

namespace pn532 {

    bin_data::bin_data(std::initializer_list<std::uint8_t> data) : std::vector<uint8_t>{data} {}
    bin_data::bin_data(std::vector<std::uint8_t> &&data) : std::vector<uint8_t>{std::move(data)} {}
    bin_data::bin_data(range<const_iterator> const &view) : bin_data{std::begin(view), std::end(view)} {}

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

    bin_stream::bin_stream(bin_data const &data, std::size_t position) : _data{&data}, _pos{position}, _bad{false} {}

    void bin_stream::seek(std::intptr_t offset, stream_ref ref) {
        if (_data != nullptr) {
            _pos = get_ref(ref) + offset;
        }
    }
    std::size_t bin_stream::tell(stream_ref ref) const {
        if (_data != nullptr) {
            return _pos - get_ref(ref);
        }
        return std::numeric_limits<std::size_t>::max();
    }
    std::size_t bin_stream::get_ref(stream_ref ref) const {
        if (_data != nullptr) {
            switch (ref) {
                case stream_ref::beg: return 0;
                case stream_ref::pos: return _pos;
                case stream_ref::end: return _data->size();
            }
        }
        return std::numeric_limits<std::size_t>::max();
    }

    range<bin_data::const_iterator> bin_stream::read(std::size_t n) {
        if (good()) {
            const std::size_t old_pos = _pos;
            if (remaining() < n) {
                _pos = get_ref(stream_ref::end);
                set_bad();
            } else {
                _pos += n;
            }
            return _data->view(old_pos, _pos - old_pos);
        }
        set_bad();
        return {};
    }

    bool bin_stream::good() const {
        return not bad() and not eof();
    }
    bool bin_stream::eof() const {
        return _data == nullptr or _pos >= _data->size();
    }
    bool bin_stream::bad() const {
        return _data == nullptr or _bad;
    }
    void bin_stream::set_bad() {
        _bad = true;
    }
    void bin_stream::clear_bad() {
        _bad = false;
    }

    std::size_t bin_stream::remaining() const {
        return get_ref(stream_ref::end) - tell();
    }

    std::uint8_t bin_stream::pop() {
        if (good()) {
            return (*_data)[_pos++];
        }
        set_bad();
        return 0x00;
    }

    template <class OutputIterator>
    std::size_t bin_stream::read(OutputIterator it, std::size_t n) {
        const auto data = read(n);
        std::copy(std::begin(data), std::end(data), it);
        return std::end(data) - std::begin(data);
    }

    bin_stream &operator>>(bin_stream &s, std::uint8_t &byte) {
        byte = s.pop();
        return s;
    }

    bin_stream &operator>>(bin_stream &s, std::uint16_t &word) {
        word = s.pop();
        word <<= 8;
        word |= s.pop();
        return s;
    }

    template <std::size_t Length>
    bin_stream &operator>>(bin_stream &s, std::array<std::uint8_t, Length> &out) {
        s.template read(std::begin(out), Length);
        return s;
    }

}

#endif //APERTURAPORTA_BIN_DATA_HPP
