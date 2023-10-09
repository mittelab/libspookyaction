//
// Created by spak on 11/24/22.
//

#include <desfire/keys.hpp>
#include <desfire/log.h>

namespace desfire {
    using mlab::prealloc;

    any_key::any_key(const any_key &other) : any_key{other.type()} {
        *this = other;
    }

    any_key::any_key(cipher_type cipher) : mlab::any_of<cipher_type, desfire::key, cipher_type::none> { cipher }
    {
        switch (cipher) {
            case cipher_type::none:
                set<cipher_type::none>(key<cipher_type::none>{});
                break;
            case cipher_type::des:
                set<cipher_type::des>(key<cipher_type::des>{});
                break;
            case cipher_type::des3_2k:
                set<cipher_type::des3_2k>(key<cipher_type::des3_2k>{});
                break;
            case cipher_type::des3_3k:
                set<cipher_type::des3_3k>(key<cipher_type::des3_3k>{});
                break;
            case cipher_type::aes128:
                set<cipher_type::aes128>(key<cipher_type::aes128>{});
                break;
        }
    }

    any_key::any_key(cipher_type cipher, mlab::range<std::uint8_t const *> k, std::uint8_t key_no)
        : mlab::any_of<cipher_type, key, cipher_type::none> { cipher }
    {
        switch (cipher) {
            case cipher_type::none:
                set<cipher_type::none>(key<cipher_type::none>{});
                break;
            case cipher_type::des: {
                key<cipher_type::des>::key_body_t kd{};
                std::copy_n(std::begin(k), kd.size(), std::begin(kd));
                set<cipher_type::des>(key<cipher_type::des>{key_no, kd});
            } break;
            case cipher_type::des3_2k: {
                key<cipher_type::des3_2k>::key_body_t kd{};
                std::copy_n(std::begin(k), kd.size(), std::begin(kd));
                set<cipher_type::des3_2k>(key<cipher_type::des3_2k>{key_no, kd});
            } break;
            case cipher_type::des3_3k: {
                key<cipher_type::des3_3k>::key_body_t kd{};
                std::copy_n(std::begin(k), kd.size(), std::begin(kd));
                set<cipher_type::des3_3k>(key<cipher_type::des3_3k>{key_no, kd});
            } break;
            case cipher_type::aes128: {
                key<cipher_type::aes128>::key_body_t kd{};
                std::copy_n(std::begin(k), kd.size(), std::begin(kd));
                set<cipher_type::aes128>(key<cipher_type::aes128>{key_no, kd});
            } break;
        }
    }

    any_key::any_key(cipher_type cipher, mlab::range<std::uint8_t const *> k, std::uint8_t key_no, std::uint8_t v)
        : mlab::any_of<cipher_type, key, cipher_type::none> { cipher }
    {
        switch (cipher) {
            case cipher_type::none:
                set<cipher_type::none>(key<cipher_type::none>{});
                break;
            case cipher_type::des: {
                key<cipher_type::des>::key_body_t kd{};
                std::copy_n(std::begin(k), kd.size(), std::begin(kd));
                set<cipher_type::des>(key<cipher_type::des>{key_no, kd, v});
            } break;
            case cipher_type::des3_2k: {
                key<cipher_type::des3_2k>::key_body_t kd{};
                std::copy_n(std::begin(k), kd.size(), std::begin(kd));
                set<cipher_type::des3_2k>(key<cipher_type::des3_2k>{key_no, kd, v});
            } break;
            case cipher_type::des3_3k: {
                key<cipher_type::des3_3k>::key_body_t kd{};
                std::copy_n(std::begin(k), kd.size(), std::begin(kd));
                set<cipher_type::des3_3k>(key<cipher_type::des3_3k>{key_no, kd, v});
            } break;
            case cipher_type::aes128: {
                key<cipher_type::aes128>::key_body_t kd{};
                std::copy_n(std::begin(k), kd.size(), std::begin(kd));
                set<cipher_type::aes128>(key<cipher_type::aes128>{key_no, kd, v});
            } break;
        }
    }

    any_key::any_key(cipher_type cipher, random_oracle rng, std::uint8_t key_no)
        : mlab::any_of<cipher_type, key, cipher_type::none> { cipher }
    {
        switch (cipher) {
            case cipher_type::none:
                set<cipher_type::none>(key<cipher_type::none>{});
                break;
            case cipher_type::des:
                set<cipher_type::des>(key<cipher_type::des>{key_no, rng});
                break;
            case cipher_type::des3_2k:
                set<cipher_type::des3_2k>(key<cipher_type::des3_2k>{key_no, rng});
                break;
            case cipher_type::des3_3k:
                set<cipher_type::des3_3k>(key<cipher_type::des3_3k>{key_no, rng});
                break;
            case cipher_type::aes128:
                set<cipher_type::aes128>(key<cipher_type::aes128>{key_no, rng});
                break;
        }
    }

    any_key::any_key(cipher_type cipher, random_oracle rng, std::uint8_t key_no, std::uint8_t v)
        : mlab::any_of<cipher_type, key, cipher_type::none> { cipher }
    {
        switch (cipher) {
            case cipher_type::none:
                set<cipher_type::none>(key<cipher_type::none>{});
                break;
            case cipher_type::des:
                set<cipher_type::des>(key<cipher_type::des>{key_no, rng, v});
                break;
            case cipher_type::des3_2k:
                set<cipher_type::des3_2k>(key<cipher_type::des3_2k>{key_no, rng, v});
                break;
            case cipher_type::des3_3k:
                set<cipher_type::des3_3k>(key<cipher_type::des3_3k>{key_no, rng, v});
                break;
            case cipher_type::aes128:
                set<cipher_type::aes128>(key<cipher_type::aes128>{key_no, rng, v});
                break;
        }
    }

    any_key &any_key::operator=(const any_key &other) {
        switch (other.type()) {
            case cipher_type::none:
                set<cipher_type::none>(other.get<cipher_type::none>());
                break;
            case cipher_type::des:
                set<cipher_type::des>(other.get<cipher_type::des>());
                break;
            case cipher_type::des3_2k:
                set<cipher_type::des3_2k>(other.get<cipher_type::des3_2k>());
                break;
            case cipher_type::des3_3k:
                set<cipher_type::des3_3k>(other.get<cipher_type::des3_3k>());
                break;
            case cipher_type::aes128:
                set<cipher_type::aes128>(other.get<cipher_type::aes128>());
                break;
        }
        return *this;
    }

    std::uint8_t any_key::key_number() const {
        switch (type()) {
            case cipher_type::des:
                return get<cipher_type::des>().key_number();
            case cipher_type::des3_2k:
                return get<cipher_type::des3_2k>().key_number();
            case cipher_type::des3_3k:
                return get<cipher_type::des3_3k>().key_number();
            case cipher_type::aes128:
                return get<cipher_type::aes128>().key_number();
            case cipher_type::none:
                [[fallthrough]];
            default:
                return std::numeric_limits<std::uint8_t>::max();
        }
    }

    std::uint8_t any_key::version() const {
        switch (type()) {
            case cipher_type::des:
                return get<cipher_type::des>().version();
            case cipher_type::des3_2k:
                return get<cipher_type::des3_2k>().version();
            case cipher_type::des3_3k:
                return get<cipher_type::des3_3k>().version();
            case cipher_type::aes128:
                return get<cipher_type::aes128>().version();
            case cipher_type::none:
                [[fallthrough]];
            default:
                return std::numeric_limits<std::uint8_t>::max();
        }
    }

    std::size_t any_key::size() const {
        switch (type()) {
            case cipher_type::des:
                return key<cipher_type::des>::size;
            case cipher_type::des3_2k:
                return key<cipher_type::des3_2k>::size;
            case cipher_type::des3_3k:
                return key<cipher_type::des3_3k>::size;
            case cipher_type::aes128:
                return key<cipher_type::aes128>::size;
            case cipher_type::none:
                [[fallthrough]];
            default:
                return 0;
        }
    }

    mlab::range<std::uint8_t const *> any_key::body() const {
        switch (type()) {
            case cipher_type::des:
                return mlab::make_range(get<cipher_type::des>().body());
            case cipher_type::des3_2k:
                return mlab::make_range(get<cipher_type::des3_2k>().body());
            case cipher_type::des3_3k:
                return mlab::make_range(get<cipher_type::des3_3k>().body());
            case cipher_type::aes128:
                return mlab::make_range(get<cipher_type::aes128>().body());
            case cipher_type::none:
                [[fallthrough]];
            default:
                return {nullptr, nullptr};
        }
    }

    void any_key::set_key_number(std::uint8_t v) {
        switch (type()) {
            case cipher_type::des:
                get<cipher_type::des>().set_key_number(v);
                break;
            case cipher_type::des3_2k:
                get<cipher_type::des3_2k>().set_key_number(v);
                break;
            case cipher_type::des3_3k:
                get<cipher_type::des3_3k>().set_key_number(v);
                break;
            case cipher_type::aes128:
                get<cipher_type::aes128>().set_key_number(v);
                break;
            case cipher_type::none:
                break;
        }
    }

    void any_key::set_version(std::uint8_t v) {
        switch (type()) {
            case cipher_type::des:
                get<cipher_type::des>().set_version(v);
                break;
            case cipher_type::des3_2k:
                get<cipher_type::des3_2k>().set_version(v);
                break;
            case cipher_type::des3_3k:
                get<cipher_type::des3_3k>().set_version(v);
                break;
            case cipher_type::aes128:
                get<cipher_type::aes128>().set_version(v);
                break;
            case cipher_type::none:
                break;
        }
    }

    void any_key::randomize(random_oracle rng) {
        switch (type()) {
            case cipher_type::des:
                get<cipher_type::des>().randomize(rng);
                break;
            case cipher_type::des3_2k:
                get<cipher_type::des3_2k>().randomize(rng);
                break;
            case cipher_type::des3_3k:
                get<cipher_type::des3_3k>().randomize(rng);
                break;
            case cipher_type::aes128:
                get<cipher_type::aes128>().randomize(rng);
                break;
            case cipher_type::none:
                break;
        }
    }

    void any_key::set_body(mlab::range<std::uint8_t const *> k) {
        if (std::size_t(k.size()) != size()) {
            DESFIRE_LOGE("Cannot setup a key of length %d with %d bytes.", size(), k.size());
            return;
        }
        switch (type()) {
            case cipher_type::des: {
                key<cipher_type::des>::key_body_t kd{};
                std::copy_n(std::begin(k), kd.size(), std::begin(kd));
                get<cipher_type::des>().set_body(kd);
            } break;

            case cipher_type::des3_2k: {
                key<cipher_type::des3_2k>::key_body_t kd{};
                std::copy_n(std::begin(k), kd.size(), std::begin(kd));
                get<cipher_type::des3_2k>().set_body(kd);
            } break;

            case cipher_type::des3_3k: {
                key<cipher_type::des3_3k>::key_body_t kd{};
                std::copy_n(std::begin(k), kd.size(), std::begin(kd));
                get<cipher_type::des3_3k>().set_body(kd);
            } break;

            case cipher_type::aes128: {
                key<cipher_type::aes128>::key_body_t kd{};
                std::copy_n(std::begin(k), kd.size(), std::begin(kd));
                get<cipher_type::aes128>().set_body(kd);
            } break;

            case cipher_type::none:
                break;
        }
    }


    any_key any_key::with_key_number(std::uint8_t key_no) const {
        any_key copy{*this};
        copy.set_key_number(key_no);
        return copy;
    }


    bool any_key::parity_bits_are_version() const {
        // Extract packed key data from the other key
        switch (type()) {
            case cipher_type::none:
                DESFIRE_LOGE("Cannot decide if parity bits are version on cipher_type::none.");
                return false;
            case cipher_type::des:
                return key<cipher_type::des>::parity_bits_are_version;
            case cipher_type::des3_2k:
                return key<cipher_type::des3_2k>::parity_bits_are_version;
            case cipher_type::des3_3k:
                return key<cipher_type::des3_3k>::parity_bits_are_version;
            case cipher_type::aes128:
                return key<cipher_type::aes128>::parity_bits_are_version;
        }
        return false;
    }

    bin_data any_key::get_packed_key_body() const {
        bin_data body{};
        // Extract packed key data from the other key
        switch (type()) {
            case cipher_type::none:
                DESFIRE_LOGE("Cannot extract data payload with a key of type cipher_type::none.");
                break;
            case cipher_type::des:
                /**
                 * @note Special treatment for DES.
                 */
                {
                    auto const &k = get<cipher_type::des>().body();
                    body << prealloc(2 * k.size()) << k << k;
                }
                break;
            case cipher_type::des3_2k:
                body << get<cipher_type::des3_2k>().body();
                break;
            case cipher_type::des3_3k:
                body << get<cipher_type::des3_3k>().body();
                break;
            case cipher_type::aes128:
                body << get<cipher_type::aes128>().body();
                break;
        }
        return body;
    }

    bin_data any_key::xored_with(any_key const &key_to_xor_with) const {
        const bin_data their_data = key_to_xor_with.get_packed_key_body();
        if (their_data.empty()) {
            return {};
        }
        bin_data our_data = get_packed_key_body();
        if (our_data.empty()) {
            return {};
        }
        for (std::size_t i = 0; i < std::min(our_data.size(), their_data.size()); ++i) {
            our_data[i] |= their_data[i];
        }
        if (not parity_bits_are_version()) {
            our_data << version();
        }
        return our_data;
    }


    bool any_key::operator==(any_key const &other) const {
        if (other.type() == type() and other.version() == version()) {
            return std::equal(std::begin(body()), std::end(body()), std::begin(other.body()));
        }
        return false;
    }

    bool any_key::operator!=(any_key const &other) const {
        return not operator==(other);
    }


}// namespace desfire

namespace mlab {
    bin_data &operator<<(bin_data &bd, desfire::any_key const &k) {
        bd << k.get_packed_key_body();
        if (not k.parity_bits_are_version()) {
            bd << k.version();
        }
        return bd;
    }
}// namespace mlab