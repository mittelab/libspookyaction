//
// Created by Pietro Saccardi on 21/12/2020.
//

#ifndef MLAB_BIN_DATA_HPP
#define MLAB_BIN_DATA_HPP

#include <algorithm>
#include <array>
#include <cstdint>
#include <esp_log.h>
#include <limits>
#include <mlab/byte_order.hpp>
#include <mlab/tracker_allocator.hpp>
#include <type_traits>
#include <vector>

namespace mlab_literals {
    [[nodiscard]] constexpr std::uint8_t operator""_b(unsigned long long int n);
}

namespace mlab {

#ifdef MLAB_TRACK_BIN_DATA
    static constexpr bool track_bin_data_mem = true;
#else
    static constexpr bool track_bin_data_mem = false;
#endif

    template <class Iterator>
    struct range {
        Iterator it_begin{};
        Iterator it_end{};

        constexpr range() = default;

        constexpr inline range(Iterator b, Iterator e) : it_begin{b}, it_end{e} {}

        template <class Container>
        constexpr explicit range(Container &c) : range{std::begin(c), std::end(c)} {}

        template <class Jterator, class = typename std::enable_if<std::is_convertible_v<Jterator, Iterator>>::type>
        constexpr range(range<Jterator> other) : it_begin{other.it_begin}, it_end{other.it_end} {}

        template <class Jterator = Iterator, class = std::enable_if_t<std::is_same_v<typename std::iterator_traits<Jterator>::iterator_category, std::random_access_iterator_tag>>>
        [[nodiscard]] constexpr inline typename std::iterator_traits<Iterator>::difference_type size() const {
            return std::distance(it_begin, it_end);
        }

        /**
         * @todo Deprecate, we have no knowledge about data contiguity at this point. Used only in log statements FTTB.
         */
        [[nodiscard]] constexpr inline typename std::add_const_t<typename std::iterator_traits<Iterator>::pointer> data() const {
            return &*it_begin;
        }

        /**
         * @todo Deprecate, we have no knowledge about data contiguity at this point. Used only in log statements FTTB.
         */
        [[nodiscard]] constexpr inline typename std::iterator_traits<Iterator>::pointer data() {
            return &*it_begin;
        }

        [[nodiscard]] constexpr inline Iterator begin() const { return it_begin; }

        [[nodiscard]] constexpr inline Iterator end() const { return it_end; }
    };

    template <class Iterator>
    constexpr inline range<Iterator> make_range(Iterator begin, Iterator end) {
        return {begin, end};
    }

    template <class Container>
    constexpr inline auto make_range(Container &c) {
        return range<decltype(std::begin(std::declval<Container &>()))>{c};
    }

    template <class, std::size_t Size>
    struct tagged_array : public std::array<std::uint8_t, Size> {
        static constexpr std::size_t array_size = Size;

        [[nodiscard]] bool operator==(tagged_array const &other) const;
        [[nodiscard]] bool operator!=(tagged_array const &other) const;
    };

    template <class T>
    concept is_range_enumerable = requires(T t) {
                                      std::begin(t) != std::end(t);
                                      *std::begin(t);
                                      std::next(std::begin(t));
                                  };

    /**
     * Structure that can only be constructed from a bool. Cannot get an `int`, or a `const char *`.
     * This prevents sinking various values into a bool accidentally.
     */
    struct explicit_bool {
        bool v;

        template <class T, class = std::enable_if_t<std::is_same_v<T, bool>>>
        constexpr explicit_bool(T v_) : v{v_} {}

        constexpr explicit operator bool() const {
            return v;
        }
    };

    struct bit_ref {
        std::uint8_t &byte;
        const std::uint8_t index;
        const std::uint8_t write_mask;

        inline bit_ref &operator=(explicit_bool v);

        inline explicit operator bool() const;
    };

    struct prealloc {
        constexpr inline explicit prealloc(std::size_t size) : requested_size{size} {}

        std::size_t requested_size = 0;
    };

    using bin_data_base = std::conditional_t<track_bin_data_mem, std::vector<std::uint8_t, tracker_allocator<std::uint8_t>>, std::vector<std::uint8_t>>;

    class bin_data : public bin_data_base {
    public:
        bin_data() = default;

        inline bin_data(std::initializer_list<std::uint8_t> data);

        inline explicit bin_data(range<bin_data::const_iterator> view);

        inline explicit bin_data(bin_data_base &&data);

        inline explicit bin_data(prealloc const &pa);

        template <class ByteIterator>
        inline bin_data(ByteIterator begin, ByteIterator end);

        [[nodiscard]] inline range<bin_data::const_iterator> view(
                std::size_t start = 0,
                std::size_t length = std::numeric_limits<std::size_t>::max()) const;

        [[nodiscard]] inline range<iterator> view(
                std::size_t start = 0,
                std::size_t length = std::numeric_limits<std::size_t>::max());

        [[nodiscard]] inline range<value_type const *> data_view(
                std::size_t start = 0,
                std::size_t length = std::numeric_limits<std::size_t>::max()) const;

        [[nodiscard]] inline range<value_type *> data_view(
                std::size_t start = 0,
                std::size_t length = std::numeric_limits<std::size_t>::max());

        using bin_data_base::push_back;

        template <class... ByteOrByteContainers>
        static bin_data chain(ByteOrByteContainers &&...others);
    };

    template <class T>
    concept is_injectable = requires(T const &t) {
                                std::declval<bin_data &>() << t;
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
        bin_stream() = default;

        inline explicit bin_stream(bin_data const &data, std::size_t position = 0);

        inline void seek(std::intptr_t offset, stream_ref ref = stream_ref::beg);

        [[nodiscard]] inline std::size_t tell(stream_ref ref = stream_ref::beg) const;

        [[nodiscard]] inline std::size_t remaining() const;

        template <class OutputIterator>
        std::size_t read(OutputIterator it, std::size_t n);

        inline range<bin_data::const_iterator> read(std::size_t n);

        inline std::uint8_t pop();

        [[nodiscard]] inline std::uint8_t peek_one();

        [[nodiscard]] inline range<bin_data::const_iterator> peek() const;

        [[nodiscard]] inline bool good() const;

        [[nodiscard]] inline bool eof() const;

        [[nodiscard]] inline bool bad() const;

        inline void set_bad();

        inline void clear_bad();
    };

    template <class T>
    concept is_extractable = requires(T &t) {
                                 std::declval<bin_stream &>() >> t;
                             };

    template <unsigned Bits>
    struct lsb_t {};

    template <unsigned Bits>
    struct msb_t {};

    [[maybe_unused]] static constexpr lsb_t<16> lsb16{};
    [[maybe_unused]] static constexpr lsb_t<24> lsb24{};
    [[maybe_unused]] static constexpr lsb_t<32> lsb32{};
    [[maybe_unused]] static constexpr lsb_t<64> lsb64{};
    [[maybe_unused]] static constexpr msb_t<16> msb16{};
    [[maybe_unused]] static constexpr msb_t<24> msb24{};
    [[maybe_unused]] static constexpr msb_t<32> msb32{};
    [[maybe_unused]] static constexpr msb_t<64> msb64{};
    [[maybe_unused]] static constexpr lsb_t<0> lsb_auto{};
    [[maybe_unused]] static constexpr msb_t<0> msb_auto{};

    template <unsigned BitSize, byte_order Order>
    struct ordered_injector {
        bin_data &bd;
    };

    template <unsigned BitSize, byte_order Order>
    struct ordered_extractor {
        bin_stream &s;
    };

    template <class Num>
    concept is_signed_or_unsigned_v = std::is_unsigned_v<Num> or std::is_signed_v<Num>;

    template <is_signed_or_unsigned_v Num, unsigned BitSize, byte_order Order>
    bin_stream &operator>>(ordered_extractor<BitSize, Order> e, Num &n);

    template <is_signed_or_unsigned_v Num, unsigned BitSize, byte_order Order>
    bin_data &operator<<(ordered_injector<BitSize, Order> i, Num n);


    template <unsigned BitSize>
    inline ordered_extractor<BitSize, byte_order::lsb_first> operator>>(bin_stream &s, lsb_t<BitSize>);

    template <unsigned BitSize>
    inline ordered_extractor<BitSize, byte_order::msb_first> operator>>(bin_stream &s, msb_t<BitSize>);

    template <unsigned BitSize>
    ordered_injector<BitSize, byte_order::lsb_first> operator<<(bin_data &bd, lsb_t<BitSize>);

    template <unsigned BitSize>
    ordered_injector<BitSize, byte_order::msb_first> operator<<(bin_data &bd, msb_t<BitSize>);

    inline bin_data &operator<<(bin_data &bd, explicit_bool b);

    inline bin_stream &operator>>(bin_stream &s, bool &b);

    inline bin_stream &operator>>(bin_stream &s, std::uint8_t &byte);

    template <std::size_t Length>
    bin_stream &operator>>(bin_stream &s, std::array<std::uint8_t, Length> &out);

    template <class T>
    using underlying_t = std::conditional_t<std::is_enum_v<T>, std::underlying_type_t<T>, T>;

    template <class T>
    using range_value_t = std::decay_t<decltype(*std::begin(std::declval<T>()))>;

    template <class T>
    concept is_byte_enum = std::is_enum_v<T> and std::is_same_v<underlying_t<T>, std::uint8_t>;

    template <class T>
    concept is_byte_enumerable = is_range_enumerable<T> and std::is_same_v<range_value_t<T>, std::uint8_t>;

    template <class T>
    concept is_byte_enum_enumerable = is_range_enumerable<T> and is_byte_enum<range_value_t<T>>;

    template <is_byte_enum Enum>
    bin_stream &operator>>(bin_stream &s, Enum &t);

    template <class T>
    concept is_byte_sequence = is_byte_enum<T> or is_byte_enumerable<T> or is_byte_enum_enumerable<T> or std::is_same_v<T, std::uint8_t>;

    template <is_byte_sequence T>
    bin_data &operator<<(bin_data &bd, T const &t);

    struct length_encoded_t {
    } constexpr length_encoded{};

    template <class T>
    struct encode_length {
        T &s;
    };

    inline encode_length<bin_stream> operator>>(bin_stream &s, length_encoded_t);
    inline encode_length<bin_data> operator<<(bin_data &bd, length_encoded_t);

    template <class T>
    concept container_of_injectables = is_range_enumerable<T> and requires(T const &t) {
                                                                      { std::declval<bin_data &>() << lsb32 << std::uint32_t(t.size()) };
                                                                      { std::declval<bin_data &>() << *std::begin(t) };
                                                                  };

    template <class T>
    concept container_of_extractables = is_range_enumerable<T> and requires(T &t) {
                                                                       t.resize(std::uint32_t{});
                                                                       { std::declval<bin_stream &>() >> *++std::begin(t) };
                                                                   };

    template <container_of_injectables Container>
    bin_data &operator<<(encode_length<bin_data> w, Container const &c);

    template <container_of_extractables Container>
    bin_stream &operator>>(encode_length<bin_stream> w, Container &c);

    static_assert(not is_injectable<int>);
    static_assert(not is_injectable<std::string>);
    static_assert(container_of_injectables<range<std::uint8_t *>>);
    static_assert(not container_of_injectables<std::string>);
}// namespace mlab

namespace mlab {


    template <class T, std::size_t Size>
    bool tagged_array<T, Size>::operator==(tagged_array const &other) const {
        return std::equal(std::begin(*this), std::end(*this), std::begin(other));
    }

    template <class T, std::size_t Size>
    bool tagged_array<T, Size>::operator!=(tagged_array const &other) const {
        return not operator==(other);
    }

    bin_data::bin_data(std::initializer_list<std::uint8_t> data) : bin_data_base{data} {}

    bin_data::bin_data(bin_data_base &&data) : bin_data_base{std::move(data)} {}

    bin_data::bin_data(prealloc const &pa) : bin_data{} {
        reserve(pa.requested_size);
    }

    bin_data::bin_data(range<bin_data::const_iterator> view) : bin_data{std::begin(view), std::end(view)} {}

    template <class ByteIterator>
    bin_data::bin_data(ByteIterator begin, ByteIterator end) : bin_data_base{begin, end} {}

    bin_data &operator<<(bin_data &bd, explicit_bool b) {
        bd.push_back(b ? 0x01 : 0x00);
        return bd;
    }

    template <class... ByteOrByteContainers>
    bin_data bin_data::chain(ByteOrByteContainers &&...others) {
        bin_data retval{};
        (retval << ... << others);
        return retval;
    }


    range<bin_data::const_iterator> bin_data::view(std::size_t start, std::size_t length) const {
        start = std::min(start, size());
        length = std::min(length, size() - start);
        return {begin() + difference_type(start), begin() + difference_type(start + length)};
    }

    range<bin_data::iterator> bin_data::view(std::size_t start, std::size_t length) {
        start = std::min(start, size() - 1);
        length = std::min(length, size() - start);
        return {begin() + difference_type(start), begin() + difference_type(start + length)};
    }

    range<bin_data::value_type const *> bin_data::data_view(std::size_t start, std::size_t length) const {
        start = std::min(start, size());
        length = std::min(length, size() - start);
        return {data() + start, data() + start + length};
    }

    range<bin_data::value_type *> bin_data::data_view(std::size_t start, std::size_t length) {
        start = std::min(start, size() - 1);
        length = std::min(length, size() - start);
        return {data() + start, data() + start + length};
    }

    bit_ref &bit_ref::operator=(explicit_bool v) {
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
        if (n == 0) {
            return _data->view(_pos, 0);
        }
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

    std::uint8_t bin_stream::peek_one() {
        if (good()) {
            return (*_data)[_pos];
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

    template <is_byte_enum Enum>
    bin_stream &operator>>(bin_stream &s, Enum &t) {
        using underlying_t = typename std::underlying_type_t<Enum>;
        auto value = static_cast<underlying_t>(Enum{});// A valid enum entry
        s >> value;
        if (not s.bad()) {
            t = static_cast<Enum>(value);
        }
        return s;
    }

    template <is_byte_sequence T>
    bin_data &operator<<(bin_data &bd, T const &t) {
        if constexpr (is_byte_enum<T>) {
            bd.push_back(static_cast<std::uint8_t>(t));
        } else if constexpr (is_byte_enumerable<T>) {
            bd.reserve(bd.size() + std::distance(std::begin(t), std::end(t)));
            for (auto const item : t) {
                bd.push_back(item);
            }
        } else if constexpr (is_byte_enum_enumerable<T>) {
            bd.reserve(bd.size() + std::distance(std::begin(t), std::end(t)));
            for (auto const be : t) {
                bd.push_back(static_cast<std::uint8_t>(be));
            }
        } else if constexpr (std::is_same_v<T, std::uint8_t>) {
            bd.push_back(t);
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

    template <is_signed_or_unsigned_v Num, unsigned BitSize, byte_order Order>
    bin_stream &operator>>(ordered_extractor<BitSize, Order> e, Num &n) {
        static_assert(sizeof(Num) * 8 >= BitSize);
        if constexpr (BitSize == 0) {
            return ordered_extractor<sizeof(Num) * 8, Order>{e.s} >> n;
        } else {
            std::array<std::uint8_t, BitSize / 8> b{};
            e.s >> b;
            n = decode<Order, BitSize, Num>(b);
            return e.s;
        }
    }

    template <is_signed_or_unsigned_v Num, unsigned BitSize, byte_order Order>
    bin_data &operator<<(ordered_injector<BitSize, Order> i, Num n) {
        static_assert(sizeof(Num) * 8 >= BitSize);
        if constexpr (BitSize == 0) {
            return ordered_injector<sizeof(Num) * 8, Order>{i.bd} << n;
        } else {
            return i.bd << encode<Order, BitSize, Num>(n);
        }
    }

    encode_length<bin_stream> operator>>(bin_stream &s, length_encoded_t) {
        return {s};
    }

    encode_length<bin_data> operator<<(bin_data &bd, length_encoded_t) {
        return {bd};
    }

    template <container_of_injectables Container>
    bin_data &operator<<(encode_length<bin_data> w, Container const &c) {
        w.s << lsb32 << c.size();
        for (auto it = std::begin(c); it != std::end(c); ++it) {
            w.s << *it;
        }
        return w.s;
    }

    template <container_of_extractables Container>
    bin_stream &operator>>(encode_length<bin_stream> w, Container &c) {
        std::uint32_t size = 0;
        w.s >> lsb32 >> size;
        if (w.s.bad()) {
            return w.s;
        }
        if (size * sizeof(typename Container::value_type) > 10 * 1024 * 1024) {
            ESP_LOGW("MLAB", "Attempt at extracting > 10MB of data?! %lu items in encoded array.", size);
        }
        c.resize(size);
        for (auto it = std::begin(c); it != std::end(c); ++it) {
            w.s >> *it;
        }
        return w.s;
    }
}// namespace mlab

namespace mlab_literals {
    constexpr std::uint8_t operator""_b(unsigned long long int n) {
        return std::uint8_t(n);
    }
}// namespace mlab_literals

#endif//MLAB_BIN_DATA_HPP
