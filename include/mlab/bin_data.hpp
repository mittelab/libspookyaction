//
// Created by Pietro Saccardi on 21/12/2020.
//

#ifndef MLAB_BIN_DATA_HPP
#define MLAB_BIN_DATA_HPP

#include "byte_order.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <esp_log.h>
#include <type_traits>
#include <vector>

namespace mlab {

    template <class Iterator>
    struct range {
        Iterator it_begin;
        Iterator it_end;

        range() = default;

        inline range(Iterator b, Iterator e) : it_begin{b}, it_end{e} {}

        template <class Jterator, class = typename std::enable_if<std::is_convertible_v<Jterator, Iterator>>::type>
        range(range<Jterator> const &other) : it_begin{other.it_begin}, it_end{other.it_end} {}

        [[nodiscard]] inline typename std::iterator_traits<Iterator>::difference_type size() const {
            return std::distance(it_begin, it_end);
        }

        [[nodiscard]] inline typename std::add_const<typename std::iterator_traits<Iterator>::pointer>::type data() const {
            return &*it_begin;
        }

        [[nodiscard]] inline typename std::iterator_traits<Iterator>::pointer data() {
            return &*it_begin;
        }

        [[nodiscard]] inline Iterator begin() const { return it_begin; }

        [[nodiscard]] inline Iterator end() const { return it_end; }
    };

    template <class Iterator>
    inline range<Iterator> make_range(Iterator begin, Iterator end) {
        return {begin, end};
    }

    struct bit_ref {
        std::uint8_t &byte;
        const std::uint8_t index;
        const std::uint8_t write_mask;

        inline bit_ref &operator=(bool v);

        inline explicit operator bool() const;
    };

    struct prealloc {
        inline explicit prealloc(std::size_t size) : requested_size{size} {}

        std::size_t requested_size = 0;
    };

    class bin_data : public std::vector<std::uint8_t> {
    public:
        bin_data() = default;

        inline bin_data(std::initializer_list<std::uint8_t> data);

        inline explicit bin_data(range<const_iterator> const &view);

        inline explicit bin_data(std::vector<std::uint8_t> &&data);

        inline explicit bin_data(prealloc const &pa);

        template <class ByteIterator>
        inline bin_data(ByteIterator begin, ByteIterator end);

        [[nodiscard]] inline range<const_iterator> view(
                std::size_t start = 0,
                std::size_t length = std::numeric_limits<std::size_t>::max()) const;

        [[nodiscard]] inline range<iterator> view(
                std::size_t start = 0,
                std::size_t length = std::numeric_limits<std::size_t>::max());

        using std::vector<std::uint8_t>::push_back;

        template <class... ByteOrByteContainers>
        static bin_data chain(ByteOrByteContainers &&... others);
    };

    inline bin_data &operator<<(bin_data &bd, prealloc const &pa);

    enum struct stream_ref {
        beg,
        pos,
        end
    };


    class bin_stream {
        bin_data const *_data = nullptr;
        std::size_t _pos = 0;
        bool _bad = false;

        [[nodiscard]] inline std::size_t get_ref(stream_ref ref) const;

    public:
        template <class>
        struct is_extractable;

        bin_stream() = default;

        inline explicit bin_stream(bin_data const &data, std::size_t position = 0);

        inline void seek(std::intptr_t offset, stream_ref ref = stream_ref::beg);

        [[nodiscard]] inline std::size_t tell(stream_ref ref = stream_ref::beg) const;

        [[nodiscard]] inline std::size_t remaining() const;

        template <class OutputIterator>
        std::size_t read(OutputIterator it, std::size_t n);

        inline range<bin_data::const_iterator> read(std::size_t n);

        inline std::uint8_t pop();

        [[nodiscard]] inline range<bin_data::const_iterator> peek() const;

        [[nodiscard]] inline bool good() const;

        [[nodiscard]] inline bool eof() const;

        [[nodiscard]] inline bool bad() const;

        inline void set_bad();

        inline void clear_bad();
    };

    template <unsigned Bits>
    struct lsb_t {};

    template <unsigned Bits>
    struct msb_t {};

    [[maybe_unused]] static constexpr lsb_t<16> lsb16{};
    [[maybe_unused]] static constexpr lsb_t<24> lsb24{};
    [[maybe_unused]] static constexpr lsb_t<32> lsb32{};
    [[maybe_unused]] static constexpr msb_t<16> msb16{};
    [[maybe_unused]] static constexpr msb_t<24> msb24{};
    [[maybe_unused]] static constexpr msb_t<32> msb32{};

    template <unsigned BitSize, byte_order Order>
    struct ordered_injector { bin_data &bd; };

    template <unsigned BitSize, byte_order Order>
    struct ordered_extractor { bin_stream &s; };

    template <unsigned BitSize>
    inline ordered_extractor<BitSize, byte_order::lsb_first> operator>>(bin_stream &s, lsb_t<BitSize>);

    template <unsigned BitSize>
    inline ordered_extractor<BitSize, byte_order::msb_first> operator>>(bin_stream &s, msb_t<BitSize>);

    inline bin_data &operator<<(bin_data &bd, std::uint8_t byte);

    inline bin_data &operator<<(bin_data &bd, bool b);

    inline bin_stream &operator>>(bin_stream &s, bool &b);

    inline bin_stream &operator>>(bin_stream &s, std::uint8_t &byte);

    template <std::size_t Length>
    bin_stream &operator>>(bin_stream &s, std::array<std::uint8_t, Length> &out);

    template <class T>
    struct bin_stream::is_extractable {
        template <class U>
        static constexpr decltype(std::declval<bin_stream &>() >> std::declval<U &>(), bool()) test_get(int) {
            return true;
        }

        template <class>
        static constexpr bool test_get(...) {
            return false;
        }

        static constexpr bool value = test_get<T>(int());
    };

    namespace impl {
        template <class T>
        struct is_range_enumerable {
            template <class U>
            static constexpr decltype(
                    std::begin(std::declval<U const &>()) != std::end(std::declval<U const &>()),
                    *std::begin(std::declval<U const &>()),
                    std::next(std::begin(std::declval<U const &>())),
                    bool())
            test_get(int) {
                return true;
            }

            template <class>
            static constexpr bool test_get(...) {
                return false;
            }

            static constexpr bool value = test_get<T>(int());
        };

        template <class T>
        static constexpr bool is_range_enumerable_v = is_range_enumerable<T>::value;

        template <class T, bool>
        struct safe_underlying_type {
            using type = T;
        };

        template <class T>
        struct safe_underlying_type<T, true> {
            /// Referencing underlying_type without first checking if it's an enum its a failed assertion
            using type = typename std::underlying_type<T>::type;
        };

        template <class T, bool>
        struct safe_value_type {
            using type = T;
        };

        template <class T>
        struct safe_value_type<T, true> {
            using type = typename std::decay_t<decltype(*std::begin(std::declval<T const &>()))>;
        };

        template <class T>
        static constexpr bool is_byte_enum_v = std::is_enum_v<T> and std::is_same_v<typename safe_underlying_type<T, std::is_enum_v<T>>::type, std::uint8_t>;

        template <class T>
        static constexpr bool is_byte_enumerable_v = is_range_enumerable_v<T> and std::is_same_v<typename safe_value_type<T, is_range_enumerable_v<T>>::type, std::uint8_t>;

        template <class T>
        static constexpr bool is_byte_enum_enumerable_v = is_range_enumerable_v<T> and is_byte_enum_v<typename safe_value_type<T, is_range_enumerable_v<T>>::type>;

    }// namespace impl

    template <class Enum, class = typename std::enable_if<impl::is_byte_enum_v<Enum>>::type>
    bin_stream &operator>>(bin_stream &s, Enum &t);

    template <class T, class = typename std::enable_if<
                               impl::is_byte_enum_v<T> or impl::is_byte_enumerable_v<T> or
                               impl::is_byte_enum_enumerable_v<T>>::type>
    bin_data &operator<<(bin_data &bd, T const &t);
}// namespace mlab

namespace mlab {

    bin_data::bin_data(std::initializer_list<std::uint8_t> data) : std::vector<uint8_t>{data} {}

    bin_data::bin_data(std::vector<std::uint8_t> &&data) : std::vector<uint8_t>{std::move(data)} {}

    bin_data::bin_data(prealloc const &pa) : bin_data{} {
        reserve(pa.requested_size);
    }

    bin_data::bin_data(range<const_iterator> const &view) : bin_data{std::begin(view), std::end(view)} {}

    template <class ByteIterator>
    bin_data::bin_data(ByteIterator begin, ByteIterator end) : std::vector<uint8_t>{begin, end} {}

    bin_data &operator<<(bin_data &bd, std::uint8_t byte) {
        bd.push_back(byte);
        return bd;
    }

    bin_data &operator<<(bin_data &bd, bool b) {
        bd.push_back(b ? 0x01 : 0x00);
        return bd;
    }

    namespace impl {
        template <class ByteOrByteContainer, class... Args>
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
    }// namespace impl

    template <class... ByteOrByteContainers>
    bin_data bin_data::chain(ByteOrByteContainers &&... others) {
        bin_data retval{};
        impl::chainer<ByteOrByteContainers...>{}(retval, std::forward<ByteOrByteContainers>(others)...);
        return retval;
    }


    range<bin_data::const_iterator> bin_data::view(std::size_t start, std::size_t length) const {
        start = std::min(start, size());
        length = std::min(length, size() - start);
        return make_range(begin() + start, begin() + start + length);
    }

    range<bin_data::iterator> bin_data::view(std::size_t start, std::size_t length) {
        start = std::min(start, size() - 1);
        length = std::min(length, size() - start);
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

    bin_data &operator<<(bin_data &bd, prealloc const &pa) {
        bd.reserve(bd.size() + pa.requested_size);
        return bd;
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
                case stream_ref::beg:
                    return 0;
                case stream_ref::pos:
                    return _pos;
                case stream_ref::end:
                    return _data->size();
            }
        }
        return std::numeric_limits<std::size_t>::max();
    }

    range<bin_data::const_iterator> bin_stream::peek() const {
        if (good()) {
            return _data->view(_pos);
        }
        return {};
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

    bin_stream &operator>>(bin_stream &s, bool &b) {
        b = s.pop() != 0x00;
        return s;
    }

    bin_stream &operator>>(bin_stream &s, std::uint8_t &byte) {
        byte = s.pop();
        return s;
    }

    template <std::size_t Length>
    bin_stream &operator>>(bin_stream &s, std::array<std::uint8_t, Length> &out) {
        s.template read(std::begin(out), Length);
        return s;
    }

    template <class Enum, class>
    bin_stream &operator>>(bin_stream &s, Enum &t) {
        using underlying_t = typename std::underlying_type_t<Enum>;
        auto value = static_cast<underlying_t>(Enum{});// A valid enum entry
        s >> value;
        if (not s.bad()) {
            t = static_cast<Enum>(value);
        }
        return s;
    }

    template <class T, class>
    bin_data &operator<<(bin_data &bd, T const &t) {
        if constexpr (impl::is_byte_enum_v<T>) {
            bd << static_cast<std::uint8_t>(t);
        } else if constexpr (impl::is_byte_enumerable_v<T>) {
            bd.reserve(bd.size() + std::distance(std::begin(t), std::end(t)));
            std::copy(std::begin(t), std::end(t), std::back_inserter(bd));
        } else if constexpr (impl::is_byte_enum_enumerable_v<T>) {
            bd.reserve(bd.size() + std::distance(std::begin(t), std::end(t)));
            for (auto const be : t) {
                bd << static_cast<std::uint8_t>(be);
            }
        }
        return bd;
    }


    template <unsigned BitSize>
    ordered_extractor<BitSize, byte_order::lsb_first> operator>>(bin_stream &s, lsb_t<BitSize>) {
        return {s};
    }

    template <unsigned BitSize>
    ordered_extractor<BitSize, byte_order::msb_first> operator>>(bin_stream &s, msb_t<BitSize>) {
        return {s};
    }

    template <unsigned BitSize>
    ordered_injector<BitSize, byte_order::lsb_first> operator<<(bin_data &bd, lsb_t<BitSize>) {
        return {bd};
    }

    template <unsigned BitSize>
    ordered_injector<BitSize, byte_order::msb_first> operator<<(bin_data &bd, msb_t<BitSize>) {
        return {bd};
    }

    template <class Num, unsigned BitSize, byte_order Order,
              class = typename std::enable_if<(std::is_unsigned_v<Num> or std::is_signed_v<Num>) and sizeof(Num) * 8 >= BitSize>::type>
    bin_stream &operator>>(ordered_extractor<BitSize, Order> e, Num &n) {
        std::array<std::uint8_t, BitSize / 8> b{};
        e.s >> b;
        n = decode<Order, BitSize, Num>(b);
        return e.s;
    }

    template <class Num, unsigned BitSize, byte_order Order,
              class = typename std::enable_if<(std::is_unsigned_v<Num> or std::is_signed_v<Num>) and sizeof(Num) * 8 >= BitSize>::type>
    bin_data &operator<<(ordered_injector<BitSize, Order> i, Num n) {
        return i.bd << encode<Order, BitSize, Num>(n);
    }


}// namespace mlab

#endif//MLAB_BIN_DATA_HPP
