//
// Created by spak on 11/24/22.
//

#ifndef DESFIRE_KEYS_HPP
#define DESFIRE_KEYS_HPP

#include <desfire/bits.hpp>
#include <desfire/crypto_algo.hpp>
#include <mlab/any_of.hpp>
#include <mlab/bin_data.hpp>

namespace desfire {
    namespace {
        using desfire::bits::cipher_type;
        using mlab::bin_data;
    }// namespace

    /**
     * @brief Super light wrapper around a function pointer that fills a buffer of random bytes.
     * This is a wrapper and not directly a function pointer to that the construction of e.g. @ref key
     * can be done without risk that `{}` will pass a `nullptr` to a random oracle, but it will instead
     * select the default constructor of @ref key_data.
     */
    struct random_oracle {
        using fn_t = void (*)(void *, std::size_t);
        fn_t fn = nullptr;

        explicit random_oracle(fn_t fn_) : fn{fn_} {}

        void operator()(void *ptr, std::size_t len) const { fn(ptr, len); }
    };

    template <cipher_type Cipher>
    struct key {
        static constexpr cipher_type cipher = Cipher;
    };

    class any_key : public mlab::any_of<cipher_type, key, cipher_type::none> {
    public:
        using mlab::any_of<cipher_type, key, cipher_type::none>::any_of;

        any_key() = default;

        template <cipher_type Cipher>
        any_key(key<Cipher> obj);

        any_key(any_key const &other);
        any_key &operator=(any_key const &other);
        any_key(any_key &&other) noexcept = default;
        any_key &operator=(any_key &&other) noexcept = default;

        explicit any_key(cipher_type cipher);
        any_key(cipher_type cipher, mlab::range<std::uint8_t const *> k, std::uint8_t key_no = 0);
        any_key(cipher_type cipher, mlab::range<std::uint8_t const *> k, std::uint8_t key_no, std::uint8_t v);
        any_key(cipher_type cipher, random_oracle rng, std::uint8_t key_no = 0);
        any_key(cipher_type cipher, random_oracle rng, std::uint8_t key_no, std::uint8_t v);

        [[nodiscard]] std::uint8_t key_number() const;
        [[nodiscard]] std::uint8_t version() const;
        [[nodiscard]] mlab::range<std::uint8_t const *> data() const;

        void set_key_number(std::uint8_t v);
        void set_version(std::uint8_t v);
        void set_data(mlab::range<std::uint8_t const *> k);
        void randomize(random_oracle rng);

        [[nodiscard]] any_key with_key_number(std::uint8_t v);

        /**
         * Size in bytes of the key. Does not account for the fact that DES key in Desfire cards are stored as 16 bytes,
         * that is, will return 8 for a DES key.
         */
        [[nodiscard]] std::size_t size() const;

        [[nodiscard]] bool parity_bits_are_version() const;

        /**
         * Does not include version for keys that do not use @ref parity_bits_are_version.
         */
        [[nodiscard]] bin_data get_packed_key_body() const;

        /**
         * @note Assume that keys which do not use parity bits as version will dump the version byte last in a
         * @ref bin_data.
         */
        [[nodiscard]] bin_data xored_with(any_key const &key_to_xor_with) const;

        bin_data &operator<<(bin_data &bd) const;
    };

    template <std::size_t KeyLength, bool ParityBitsAreVersion>
    class key_storage;

    template <std::size_t KeyLength>
    class key_storage<KeyLength, true /* ParityBitsAreVersion */> {
    public:
        static constexpr std::size_t size = KeyLength;
        using key_data = std::array<std::uint8_t, size>;

        [[nodiscard]] inline mlab::range<std::uint8_t const *> as_range() const;

        key_storage() = default;

        inline explicit key_storage(random_oracle rng);
        inline key_storage(random_oracle rng, std::uint8_t v);

        inline explicit key_storage(key_data k);
        inline key_storage(key_data k, std::uint8_t v);

        [[nodiscard]] inline std::uint8_t version() const;
        inline void set_version(std::uint8_t v);

        [[nodiscard]] inline key_data const &data() const;
        inline void set_data(key_data k);

        void randomize(random_oracle rng);

    protected:
        key_data _data{};
    };

    template <std::size_t KeyLength>
    class key_storage<KeyLength, false /* ParityBitsAreVersion */> : private key_storage<KeyLength, true> {
    public:
        using key_data = typename key_storage<KeyLength, true>::key_data;

        using key_storage<KeyLength, true>::size;
        using key_storage<KeyLength, true>::as_range;

        key_storage() = default;

        inline explicit key_storage(random_oracle rng, std::uint8_t v = 0);
        inline explicit key_storage(key_data k, std::uint8_t v = 0);

        /**
         * @addtogroup Shadowing
         * @note Deliberately shadowing for conveniency
         * @{
         */
        [[nodiscard]] inline std::uint8_t version() const;
        inline void set_version(std::uint8_t v);
        void randomize(random_oracle rng);
        /**
         * @}
         */

        using key_storage<KeyLength, true>::data;
        using key_storage<KeyLength, true>::set_data;

    private:
        std::uint8_t _version{};
    };


    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    class key_base : public key_storage<KeyLength, ParityBitsAreVersion> {
    public:
        using storage = key_storage<KeyLength, ParityBitsAreVersion>;

        static constexpr bool parity_bits_are_version = ParityBitsAreVersion;

        using typename storage::key_data;

        using storage::as_range;
        using storage::data;
        using storage::randomize;
        using storage::set_data;
        using storage::set_version;
        using storage::size;
        using storage::version;

        key_base() = default;
        explicit key_base(random_oracle rng);
        key_base(std::uint8_t key_no, random_oracle rng);
        key_base(std::uint8_t key_no, key_data k);
        key_base(std::uint8_t key_no, random_oracle rng, std::uint8_t v);
        key_base(std::uint8_t key_no, key_data k, std::uint8_t v);

        [[nodiscard]] inline CRTPSubclass with_key_number(std::uint8_t key_no) const;

        [[nodiscard]] inline std::uint8_t key_number() const;
        inline void set_key_number(std::uint8_t key_no);

    private:
        std::uint8_t _key_no{0};
    };

    template <>
    struct key<cipher_type::des> : public key_base<8, true, key<cipher_type::des>> {
        using key_base = key_base<8, true, key<cipher_type::des>>;
        static constexpr cipher_type cipher = cipher_type::des;
        using key_base::data;
        using key_base::key_base;
        using key_base::key_number;
        using key_base::randomize;
        using key_base::set_data;
        using key_base::set_key_number;
        using key_base::set_version;
        using key_base::size;
        using key_base::version;
        using key_base::with_key_number;
    };

    template <>
    struct key<cipher_type::des3_2k> : public key_base<16, true, key<cipher_type::des3_2k>> {
        using key_base = key_base<16, true, key<cipher_type::des3_2k>>;
        static constexpr cipher_type cipher = cipher_type::des3_2k;
        using key_base::data;
        using key_base::key_base;
        using key_base::key_number;
        using key_base::randomize;
        using key_base::set_data;
        using key_base::set_key_number;
        using key_base::set_version;
        using key_base::size;
        using key_base::version;
        using key_base::with_key_number;
    };

    template <>
    struct key<cipher_type::des3_3k> : public key_base<24, true, key<cipher_type::des3_3k>> {
        using key_base = key_base<24, true, key<cipher_type::des3_3k>>;
        static constexpr cipher_type cipher = cipher_type::des3_3k;
        using key_base::data;
        using key_base::key_base;
        using key_base::key_number;
        using key_base::randomize;
        using key_base::set_data;
        using key_base::set_key_number;
        using key_base::set_version;
        using key_base::size;
        using key_base::version;
        using key_base::with_key_number;
    };

    template <>
    struct key<cipher_type::aes128> : public key_base<16, false, key<cipher_type::aes128>> {
        using key_base = key_base<16, false, key<cipher_type::aes128>>;
        static constexpr cipher_type cipher = cipher_type::aes128;
        using key_base::data;
        using key_base::key_base;
        using key_base::key_number;
        using key_base::randomize;
        using key_base::set_data;
        using key_base::set_key_number;
        using key_base::set_version;
        using key_base::size;
        using key_base::version;
        using key_base::with_key_number;
    };

}// namespace desfire

namespace mlab {
    bin_data &operator<<(bin_data &bd, desfire::any_key const &k);
}// namespace mlab

namespace desfire {

    template <std::size_t KeyLength>
    key_storage<KeyLength, false>::key_storage(key_data k, std::uint8_t v) : key_storage<KeyLength, true>{k}, _version{v} {}

    template <std::size_t KeyLength>
    key_storage<KeyLength, false>::key_storage(random_oracle rng, std::uint8_t v) : key_storage<KeyLength, true>{rng}, _version{v} {}

    template <std::size_t KeyLength>
    std::uint8_t key_storage<KeyLength, false>::version() const {
        return _version;
    }

    template <std::size_t KeyLength>
    void key_storage<KeyLength, false>::set_version(std::uint8_t v) {
        _version = v;
    }

    template <std::size_t KeyLength>
    void key_storage<KeyLength, false>::randomize(random_oracle rng) {
        rng(key_storage<KeyLength, true>::_data.data(), key_storage<KeyLength, true>::_data.size());
    }

    template <std::size_t KeyLength>
    mlab::range<std::uint8_t const *> key_storage<KeyLength, true>::as_range() const {
        return mlab::make_range(_data);
    }

    template <std::size_t KeyLength>
    key_storage<KeyLength, true>::key_storage(key_data k) : _data{k} {}

    template <std::size_t KeyLength>
    key_storage<KeyLength, true>::key_storage(random_oracle rng) : key_storage{} {
        rng(_data.data(), _data.size());
    }

    template <std::size_t KeyLength>
    key_storage<KeyLength, true>::key_storage(random_oracle rng, std::uint8_t v) : key_storage{} {
        rng(_data.data(), _data.size());
        set_version(v);
    }

    template <std::size_t KeyLength>
    key_storage<KeyLength, true>::key_storage(key_data k, std::uint8_t v) : _data{k} {
        set_version(v);
    }

    template <std::size_t KeyLength>
    std::uint8_t key_storage<KeyLength, true>::version() const {
        return get_key_version(_data);
    }

    template <std::size_t KeyLength>
    void key_storage<KeyLength, true>::set_version(std::uint8_t v) {
        set_key_version(_data, v);
    }

    template <std::size_t KeyLength>
    void key_storage<KeyLength, true>::randomize(random_oracle rng) {
        const auto v = version();
        rng(_data.data(), _data.size());
        set_version(v);
    }

    template <std::size_t KeyLength>
    typename key_storage<KeyLength, true>::key_data const &key_storage<KeyLength, true>::data() const {
        return _data;
    }

    template <std::size_t KeyLength>
    void key_storage<KeyLength, true>::set_data(key_data k) {
        _data = k;
    }

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_base(std::uint8_t key_no, key_data k_) : storage{k_}, _key_no{key_no} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_base(std::uint8_t key_no, key_data k_, std::uint8_t v_) : storage{k_, v_}, _key_no{key_no} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_base(random_oracle rng) : storage{rng}, _key_no{0} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_base(std::uint8_t key_no, random_oracle rng) : storage{rng}, _key_no{key_no} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_base(std::uint8_t key_no, random_oracle rng, std::uint8_t v) : storage{rng, v}, _key_no{key_no} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    CRTPSubclass key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::with_key_number(std::uint8_t key_no) const {
        return CRTPSubclass{key_no, data(), version()};
    }

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    std::uint8_t key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_number() const {
        return _key_no;
    }

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    void key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::set_key_number(std::uint8_t key_no) {
        _key_no = key_no;
    }

    template <cipher_type Cipher>
    any_key::any_key(key<Cipher> obj) : mlab::any_of<cipher_type, key, cipher_type::none>{std::move(obj)} {}

}// namespace desfire

#endif//DESFIRE_KEYS_HPP
