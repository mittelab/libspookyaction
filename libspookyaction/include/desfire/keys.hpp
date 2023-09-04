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
    using mlab::bin_data;

    /**
     * @brief Super light wrapper around a function pointer that fills a buffer of random bytes.
     * This is a wrapper and not directly a function pointer to that the construction of e.g. @ref key
     * can be done without risk that `{}` will pass a `nullptr` to a random oracle, but it will instead
     * select the default constructor of @ref key_storage.
     */
    struct random_oracle {
        using fn_t = void (*)(void *, std::size_t);//!< Function pointer which takes a void pointer and a size.
        fn_t fn = nullptr;                         //!< Pointer to the buffer-filling function.

        /**
         * Explicitly wraps around a function pointer.
         * @param fn_ Buffer-filling function matching the `void (void *, std::size_t)` signature.
         */
        explicit random_oracle(fn_t fn_) : fn{fn_} {}

        /**
         * @brief Fills a preallocated buffer @p ptr of length @p len with random bytes.
         * This is done by forwarding the arguments as-is to @ref fn.
         * @param ptr Preallocated buffer pointer
         * @param len Number of bytes to fill at @p ptr.
         */
        void operator()(void *ptr, std::size_t len) const { fn(ptr, len); }
    };

    /**
     * Templated struct used only for template specialization and to make sense of @ref cipher_type::none.
     * Represent a key on a given @p cipher_type; refer to @ref key<cipher_type::des>, @ref key<cipher_type::des3_2k>,
     * @ref key<cipher_type::des3_3k>, @ref key<cipher_type::aes128>.
     * @tparam Cipher Cipher type of this key.
     */
    template <cipher_type Cipher>
    struct key {
        static constexpr cipher_type cipher = Cipher;//<! Alias for the template parm.
    };

    /**
     * Type-erased class that holds a key of any cipher type.
     */
    class any_key : public mlab::any_of<cipher_type, key, cipher_type::none> {
    public:
        using mlab::any_of<cipher_type, key, cipher_type::none>::any_of;

        /**
         * Default-constructs an empty key with @ref cipher_type::none.
         */
        any_key() = default;

        /**
         * Converts implicitly a strongly typed key of a given type to a type-erased @ref any_key.
         * @tparam Cipher Cipher of the key
         * @param obj Key instance (moved into the instance).
         */
        template <cipher_type Cipher>
        any_key(key<Cipher> obj);

        /**
         * @name Rule of five.
         * Copy-constructors have to be manually implemented for `mlab::any_of`.
         * @{
         */
        any_key(any_key const &other);
        any_key &operator=(any_key const &other);
        any_key(any_key &&other) noexcept = default;
        any_key &operator=(any_key &&other) noexcept = default;
        /**
         * @}
         */

        /**
         * Constructs key number 0, with the key body set to all zeroes, of the given @p cipher type.
         * @param cipher Cipher type for which to construct the key.
         */
        explicit any_key(cipher_type cipher);

        /**
         * Constructs a key of the given @p cipher, using the body specified in @p k and the key number @p key_no.
         * @param cipher cipher Cipher type for which to construct the key.
         * @param k Key body. This must be a preallocated buffer of the appropriate size for the key.
         *  If it is smaller, the rest of the body is filled with zeroes.
         * @param key_no Number of the key, in the range 0..13 (included).
         */
        any_key(cipher_type cipher, mlab::range<std::uint8_t const *> k, std::uint8_t key_no = 0);

        /**
         * Constructs a key of the given @p cipher, using the body specified in @p k and the key number @p key_no.
         * Subsequently, applies the version @p v.
         * @param cipher cipher Cipher type for which to construct the key.
         * @param k Key body. This must be a preallocated buffer of the appropriate size for the key.
         *  If it is smaller, the rest of the body is filled with zeroes.
         * @param key_no Number of the key, in the range 0..13 (included).
         * @param v Key version.
         */
        any_key(cipher_type cipher, mlab::range<std::uint8_t const *> k, std::uint8_t key_no, std::uint8_t v);

        /**
         * Constructs a random key of the given @p cipher, using the given random number generator and the key number @p key_no.
         * @param cipher cipher Cipher type for which to construct the key.
         * @param rng Random number generator function to use for filling the key body.
         * @param key_no Number of the key, in the range 0..13 (included).
         */
        any_key(cipher_type cipher, random_oracle rng, std::uint8_t key_no = 0);

        /**
         * Constructs a random key of the given @p cipher, using the  given random number generator and the key number @p key_no.
         * Subsequently, applies the version @p v.
         * @param cipher cipher Cipher type for which to construct the key.
         * @param rng Random number generator function to use for filling the key body.
         * @param key_no Number of the key, in the range 0..13 (included).
         * @param v Key version.
         */
        any_key(cipher_type cipher, random_oracle rng, std::uint8_t key_no, std::uint8_t v);

        /**
         * Key number of the key.
         * @return A number in the range 0..13 (included).
         */
        [[nodiscard]] std::uint8_t key_number() const;

        /**
         * @brief Version of the key.
         * DES-based keys encode the version in the key body, while AES128 keys store that separately.
         * @return A number in the range 0..255 (included).
         */
        [[nodiscard]] std::uint8_t version() const;

        /**
         * @brief Returns a data range holding the key body.
         * @return A pair of iterators, which yield a zero-length sequence if the key has @ref cipher_type::none.
         */
        [[nodiscard]] mlab::range<std::uint8_t const *> body() const;

        /**
         * @brief Changes the key number to @p v.
         * @param v A number in the range 0..13 (included).
         */
        void set_key_number(std::uint8_t v);

        /**
         * @brief Changes the key version to @p v.
         * DES-based keys encode the version in the key body, while AES128 keys store that separately.
         * @param v A byte.
         */
        void set_version(std::uint8_t v);

        /**
         * @brief Changes the key body.
         * @note For DES keys, this will change the key version. The rationale is that the incoming data is from a known key,
         *  therefore it is ok to carry on the version. If you are generating a random key, use @ref randomize.
         * @param k Key body, it will be copied. This must be a preallocated buffer of the appropriate size for the key.
         *  If it is smaller, the rest of the body is filled with zeroes.
         */
        void set_body(mlab::range<std::uint8_t const *> k);

        /**
         * @brief Randomizes the key without changing its type.
         * @note This does *not* change the key version.
         * @param rng Random number generator function to use for filling the key body.
         */
        void randomize(random_oracle rng);

        /**
         * @brief Copies the same key but changes the @ref key_number.
         * @param key_no Number of the key, in the range 0..13 (included).
         * @return An identical key, with different @ref key_number.
         */
        [[nodiscard]] any_key with_key_number(std::uint8_t key_no) const;

        /**
         * @brief Size in bytes of the key.
         * Does not account for the fact that DES key in Desfire cards are stored as 16 bytes,
         * that is, will return 8 for a DES key. Also does not count the version byte for AES128 keys, i.e.
         * for AES it will return 16.
         */
        [[nodiscard]] std::size_t size() const;

        /**
         * @brief Does this key store the version into the parity (LSB) bits of the key body?
         * True only for DES-based keys.
         * @return True if the LSB bits of the @ref data include the version.
         */
        [[nodiscard]] bool parity_bits_are_version() const;

        /**
         * @brief Returns a copy of the key body as used in authentication procedures.
         * @note DES keys are 2K3DES keys with two identical halves. Does not include version for keys
         *  that do not have @ref parity_bits_are_version.
         */
        [[nodiscard]] bin_data get_packed_key_body() const;

        /**
         * @brief XOR-s together the @ref get_packed_key_body of this instance and @p key_to_xor_with (includes version).
         * For AES128 keys, where @ref parity_bits_are_version returns false, the key version is appended at the end
         * and is excluded from the xoring process.
         * @param key_to_xor_with Key for which to extract the body in order to XOR it with this instance.
         * @return The result of @ref get_packed_key_body, XOR-ed with @p key_to_xor_with and with a version byte appended if necessary.
         */
        [[nodiscard]] bin_data xored_with(any_key const &key_to_xor_with) const;
    };

    struct key_tag {};

    /**
     * Strongly typed array of a given length identifying the key body.
     */
    template <std::size_t Length>
    using key_body = mlab::tagged_array<key_tag, Length>;

    /**
     * Templated struct used only for specialization puposes. This is a mixin holding the key body.
     * @tparam KeyLength Length of the key.
     * @tparam ParityBitsAreVersion Whether the parity (LSB) bits of the key body hold the key version.
     */
    template <std::size_t KeyLength, bool ParityBitsAreVersion>
    class key_storage;

    /**
     * Mixin used for holding the key body where the parity bits of the body are the version.
     * @note This is also used to provide most of the methods of @ref key_storage<KeyLength,false> and
     *  @ref key_base.
     * @see
     *  - key_storage<KeyLength,false>
     *  - key_base
     * @tparam KeyLength Length of the key.
     */
    template <std::size_t KeyLength>
    class key_storage<KeyLength, true /* ParityBitsAreVersion */> {
    public:
        static constexpr std::size_t size = KeyLength;//!< Key length alias.

        using key_body_t = key_body<KeyLength>;//!< Key body alias.

        /**
         * @brief Access the key body as a byte range.
         */
        [[nodiscard]] constexpr mlab::range<std::uint8_t const *> as_range() const;

        /**
         * Constructs a key filled with zeroes and version 0.
         */
        key_storage() = default;

        /**
         * Constructs a random key body (and a random version).
         * @param rng Random number generator function to use for filling the key body.
         */
        inline explicit key_storage(random_oracle rng);

        /**
         * Constructs a random key body with a pre-defined version.
         * @param rng Random number generator function to use for filling the key body.
         * @param v Version of this key.
         */
        key_storage(random_oracle rng, std::uint8_t v);

        /**
         * Constructs a key storage containing the given key body and version @p k.
         * @param k Key body.
         */
        constexpr explicit key_storage(key_body_t k);

        /**
         * Constructs a key storage containing the given key body @p k and the version @p v.
         * @param k Key body.
         * @param v Version (takes over what can be extracted from @p k).
         */
        constexpr key_storage(key_body_t k, std::uint8_t v);

        /**
         * @brief Version of the key.
         * The version is encoded in the parity bits of the key body.
         * @return A number in the range 0..255 (included).
         */
        [[nodiscard]] constexpr std::uint8_t version() const;


        /**
         * @brief Changes the key version to @p v.
         * The version is encoded in the parity bits of the key body.
         * @param v A byte.
         */
        inline void set_version(std::uint8_t v);

        /**
         * Accesses the internal key body.
         */
        [[nodiscard]] constexpr key_body_t const &body() const;

        /**
         * @brief Changes the key body.
         * @note This will change the key version. The rationale is that the incoming data is from a known key,
         *  therefore it is ok to carry on the version. If you are generating a random key, use @ref randomize.
         * @param k Key body.
         */
        inline void set_body(key_body_t k);

        /**
         * @brief Randomizes the key.
         * @note This does *not* change the key version.
         * @param rng Random number generator function to use for filling the key body.
         */
        void randomize(random_oracle rng);

    protected:
        key_body_t _body{};
    };

    /**
     * Mixin used for holding the key body where the version is stored as a separate byte.
     * @note This is also used to provide most of the methods @ref key_base.
     * @see
     *  - key_storage<KeyLength,true>
     *  - key_base
     * @tparam KeyLength Length of the key.
     */
    template <std::size_t KeyLength>
    class key_storage<KeyLength, false /* ParityBitsAreVersion */> : private key_storage<KeyLength, true> {
    public:
        using key_body_t = typename key_storage<KeyLength, true>::key_body_t;//!< Key body alias.

        using key_storage<KeyLength, true>::size;//!< Key length alias.

        /**
         * @brief Access the key body as a byte range.
         */
        using key_storage<KeyLength, true>::as_range;

        /**
         * Constructs a key filled with zeroes and version 0.
         */
        constexpr key_storage() = default;

        /**
         * Constructs a random key body with a pre-defined version.
         * @param rng Random number generator function to use for filling the key body.
         * @param v Version of this key.
         */
        explicit key_storage(random_oracle rng, std::uint8_t v = 0);

        /**
         * Constructs a key storage containing the given key body @p k and the version @p v.
         * @param k Key body.
         * @param v Version.
         */
        constexpr explicit key_storage(key_body_t k, std::uint8_t v = 0);

        /**
         * @brief Version of the key.
         * @note This deliberately shadows its private base class's member.
         * @return A number in the range 0..255 (included).
         */
        [[nodiscard]] constexpr std::uint8_t version() const;

        /**
         * @brief Changes the key version to @p v.
         * @note This deliberately shadows its private base class's member.
         * @param v A byte.
         */
        inline void set_version(std::uint8_t v);

        /**
         * @brief Randomizes the key without changing version.
         * @note This deliberately shadows its private base class's member.
         * @param rng Random number generator function to use for filling the key body.
         */
        void randomize(random_oracle rng);

        /**
         * Accesses the internal key body.
         */
        using key_storage<KeyLength, true>::body;

        /**
         * @brief Changes the key body.
         * @note This will change the key version. The rationale is that the incoming data is from a known key,
         *  therefore it is ok to carry on the version. If you are generating a random key, use @ref randomize.
         * @param k Key body.
         */
        using key_storage<KeyLength, true>::set_body;

    private:
        std::uint8_t _version{};
    };


    /**
     * @brief A Desfire key; this extends @ref key_storage.
     * All subclasses only specialize some of the templated arguments so that they can be used with `mlab::any_of`.
     * Other than that, they are perfectly identical. This glues together the methods from @ref key_storage<KeyLength,false>
     * and @ref key_storage<KeyLength,true>.
     * @see
     *  - key_storage<KeyLength,false>
     *  - key_storage<KeyLength,true>
     *  - any_key
     * @tparam KeyLength Length of the key in bytes.
     * @tparam ParityBitsAreVersion Whether the parity bits store the key version or not (DES-based keys)
     * @tparam CRTPSubclass Subclass type: used in conjunction with CRTP to implement @ref with_key_number.
     */
    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    class key_base : public key_storage<KeyLength, ParityBitsAreVersion> {
    public:
        using storage = key_storage<KeyLength, ParityBitsAreVersion>;//!< Storage type (the base class)

        static constexpr bool parity_bits_are_version = ParityBitsAreVersion;//!< Whether the parity bits store the version byte or not.

        using typename storage::key_body_t;

        using storage::as_range;
        using storage::body;
        using storage::randomize;
        using storage::set_body;
        using storage::set_version;
        using storage::size;
        using storage::version;

        /**
         * Default constructs a key with index 0 and body 0.
         */
        constexpr key_base() = default;

        /**
         * Constructs a random key 0 (with a random version if @ref parity_bits_are_version).
         * @param rng Random number generator function to use for filling the key body.
         */
        explicit key_base(random_oracle rng);

        /**
         * Constructs a random key with the given @p key_no (with a random version if @ref parity_bits_are_version).
         * @param key_no Key number, integer in the range 0..13 (included).
         * @param rng Random number generator function to use for filling the key body.
         */
        key_base(std::uint8_t key_no, random_oracle rng);

        /**
         * Constructs a key of index @p key_no with body @p k.
         * @param key_no Key number, integer in the range 0..13 (included).
         * @param k Key body.
         */
        constexpr key_base(std::uint8_t key_no, key_body_t k);

        /**
         * Constructs a random key with the given @p key_no and version @p v.
         * @param key_no Key number, integer in the range 0..13 (included).
         * @param rng Random number generator function to use for filling the key body.
         * @param v Key version.
         */
        key_base(std::uint8_t key_no, random_oracle rng, std::uint8_t v);

        /**
         * Constructs a key of index @p key_no with body @p k and version @p v.
         * @param key_no Key number, integer in the range 0..13 (included).
         * @param k Key body.
         * @param v Key version.
         */
        constexpr key_base(std::uint8_t key_no, key_body_t k, std::uint8_t v);
        /**
         * @brief Copies the same key but changes the @ref key_number.
         * @param key_no Number of the key, in the range 0..13 (included).
         * @return An identical key, with different @ref key_number.
         */
        [[nodiscard]] CRTPSubclass with_key_number(std::uint8_t key_no) const;

        /**
         * Key number of the key.
         * @return A number in the range 0..13 (included).
         */
        [[nodiscard]] constexpr std::uint8_t key_number() const;

        /**
         * @brief Changes the key number to @p key_no.
         * @param key_no A number in the range 0..13 (included).
         */
        inline void set_key_number(std::uint8_t key_no);

        /**
         * @name Comparison operators
         * @{
         */
        [[nodiscard]] inline bool operator==(key_base const &other) const;
        [[nodiscard]] inline bool operator!=(key_base const &other) const;
        /**
         * @}
         */

    private:
        std::uint8_t _key_no{0};
    };

    /**
     * A DES key. This inherits all members and properties of the base classes.
     * @see
     *  - key_storage
     *  - key_base
     *  - any_key
     */
    template <>
    struct key<cipher_type::des> : public key_base<8, true, key<cipher_type::des>> {
        using key_base = key_base<8, true, key<cipher_type::des>>;
        static constexpr cipher_type cipher = cipher_type::des;
        using key_base::body;
        using key_base::key_base;
        using key_base::key_number;
        using key_base::randomize;
        using key_base::set_body;
        using key_base::set_key_number;
        using key_base::set_version;
        using key_base::size;
        using key_base::version;
        using key_base::with_key_number;
    };

    /**
     * A 2TDEA key. This inherits all members and properties of the base classes.
     * @see
     *  - key_storage
     *  - key_base
     *  - any_key
     */
    template <>
    struct key<cipher_type::des3_2k> : public key_base<16, true, key<cipher_type::des3_2k>> {
        using key_base = key_base<16, true, key<cipher_type::des3_2k>>;
        static constexpr cipher_type cipher = cipher_type::des3_2k;
        using key_base::body;
        using key_base::key_base;
        using key_base::key_number;
        using key_base::randomize;
        using key_base::set_body;
        using key_base::set_key_number;
        using key_base::set_version;
        using key_base::size;
        using key_base::version;
        using key_base::with_key_number;
    };

    /**
     * A 3DES key. This inherits all members and properties of the base classes.
     * @see
     *  - key_storage
     *  - key_base
     *  - any_key
     */
    template <>
    struct key<cipher_type::des3_3k> : public key_base<24, true, key<cipher_type::des3_3k>> {
        using key_base = key_base<24, true, key<cipher_type::des3_3k>>;
        static constexpr cipher_type cipher = cipher_type::des3_3k;
        using key_base::body;
        using key_base::key_base;
        using key_base::key_number;
        using key_base::randomize;
        using key_base::set_body;
        using key_base::set_key_number;
        using key_base::set_version;
        using key_base::size;
        using key_base::version;
        using key_base::with_key_number;
    };

    /**
     * An AES128 key. This inherits all members and properties of the base classes.
     * @see
     *  - key_storage
     *  - key_base
     *  - any_key
     */
    template <>
    struct key<cipher_type::aes128> : public key_base<16, false, key<cipher_type::aes128>> {
        using key_base = key_base<16, false, key<cipher_type::aes128>>;
        static constexpr cipher_type cipher = cipher_type::aes128;
        using key_base::body;
        using key_base::key_base;
        using key_base::key_number;
        using key_base::randomize;
        using key_base::set_body;
        using key_base::set_key_number;
        using key_base::set_version;
        using key_base::size;
        using key_base::version;
        using key_base::with_key_number;
    };

}// namespace desfire

namespace mlab {
#ifndef DOXYGEN_SHOULD_SKIP_THIS
    /**
     * @addtogroup IOOperators
     * @{
     */
    bin_data &operator<<(bin_data &bd, desfire::any_key const &k);
    /**
     * @}
     */
#endif
}// namespace mlab

namespace desfire {

    template <std::size_t KeyLength>
    constexpr key_storage<KeyLength, false>::key_storage(key_body_t k, std::uint8_t v) : key_storage<KeyLength, true>{k}, _version{v} {}

    template <std::size_t KeyLength>
    key_storage<KeyLength, false>::key_storage(random_oracle rng, std::uint8_t v) : key_storage<KeyLength, true>{rng}, _version{v} {}

    template <std::size_t KeyLength>
    constexpr std::uint8_t key_storage<KeyLength, false>::version() const {
        return _version;
    }

    template <std::size_t KeyLength>
    void key_storage<KeyLength, false>::set_version(std::uint8_t v) {
        _version = v;
    }

    template <std::size_t KeyLength>
    void key_storage<KeyLength, false>::randomize(random_oracle rng) {
        rng(key_storage<KeyLength, true>::_body.data(), key_storage<KeyLength, true>::_body.size());
    }

    template <std::size_t KeyLength>
    constexpr mlab::range<std::uint8_t const *> key_storage<KeyLength, true>::as_range() const {
        return mlab::make_range(_body);
    }

    template <std::size_t KeyLength>
    constexpr key_storage<KeyLength, true>::key_storage(key_body_t k) : _body{k} {}

    template <std::size_t KeyLength>
    key_storage<KeyLength, true>::key_storage(random_oracle rng) : key_storage{} {
        rng(_body.data(), _body.size());
    }

    template <std::size_t KeyLength>
    key_storage<KeyLength, true>::key_storage(random_oracle rng, std::uint8_t v) : key_storage{} {
        rng(_body.data(), _body.size());
        set_version(v);
    }

    template <std::size_t KeyLength>
    constexpr key_storage<KeyLength, true>::key_storage(key_body_t k, std::uint8_t v) : _body{k} {
        set_version(v);
    }

    template <std::size_t KeyLength>
    constexpr std::uint8_t key_storage<KeyLength, true>::version() const {
        return get_key_version(_body);
    }

    template <std::size_t KeyLength>
    void key_storage<KeyLength, true>::set_version(std::uint8_t v) {
        set_key_version(_body, v);
    }

    template <std::size_t KeyLength>
    void key_storage<KeyLength, true>::randomize(random_oracle rng) {
        const auto v = version();
        rng(_body.data(), _body.size());
        set_version(v);
    }

    template <std::size_t KeyLength>
    constexpr typename key_storage<KeyLength, true>::key_body_t const &key_storage<KeyLength, true>::body() const {
        return _body;
    }

    template <std::size_t KeyLength>
    void key_storage<KeyLength, true>::set_body(key_body_t k) {
        _body = k;
    }

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    constexpr key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_base(std::uint8_t key_no, key_body_t k_) : storage{k_}, _key_no{key_no} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    constexpr key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_base(std::uint8_t key_no, key_body_t k_, std::uint8_t v_) : storage{k_, v_}, _key_no{key_no} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_base(random_oracle rng) : storage{rng}, _key_no{0} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_base(std::uint8_t key_no, random_oracle rng) : storage{rng}, _key_no{key_no} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_base(std::uint8_t key_no, random_oracle rng, std::uint8_t v) : storage{rng, v}, _key_no{key_no} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    CRTPSubclass key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::with_key_number(std::uint8_t key_no) const {
        return CRTPSubclass{key_no, body(), version()};
    }

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    constexpr std::uint8_t key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_number() const {
        return _key_no;
    }

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    void key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::set_key_number(std::uint8_t key_no) {
        _key_no = key_no;
    }

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    bool key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::operator==(key_base const &other) const {
        return key_number() == other.key_number() and version() == other.version() and body() == other.body();
    }
    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    bool key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::operator!=(key_base const &other) const {
        return key_number() != other.key_number() or version() != other.version() or body() != other.body();
    }

    template <cipher_type Cipher>
    any_key::any_key(key<Cipher> obj) : mlab::any_of<cipher_type, key, cipher_type::none>{std::move(obj)} {}

}// namespace desfire

#endif//DESFIRE_KEYS_HPP
