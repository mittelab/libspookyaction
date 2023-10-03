//
// Created by spak on 2/1/23.
//

#ifndef MLAB_STRUTILS_HPP
#define MLAB_STRUTILS_HPP

#include <chrono>
#include <mlab/bin_data.hpp>
#include <optional>

namespace mlab {
    using datetime = std::chrono::time_point<std::chrono::system_clock>;

    [[nodiscard]] range<std::uint8_t const *> data_view_from_string(std::string_view s);
    [[nodiscard]] bin_data data_from_string(std::string_view s);

    template <std::size_t N>
    [[nodiscard]] std::string data_to_string(std::array<std::uint8_t, N> const &v);
    [[nodiscard]] std::string data_to_string(std::vector<std::uint8_t> const &v);
    [[nodiscard]] std::string data_to_string(range<bin_data::const_iterator> rg);
    [[nodiscard]] std::string data_to_string(range<std::uint8_t const *> rg);

    template <std::size_t N>
    [[nodiscard]] std::string data_to_hex_string(std::array<std::uint8_t, N> const &v);
    [[nodiscard]] std::string data_to_hex_string(std::vector<std::uint8_t> const &v);
    [[nodiscard]] std::string data_to_hex_string(range<bin_data::const_iterator> rg);
    [[nodiscard]] std::string data_to_hex_string(range<std::uint8_t const *> rg);

    [[nodiscard]] bin_data data_from_hex_string(std::string_view s);

    template <class It>
    [[nodiscard]] std::string data_to_hex_string(It begin, It end);

    [[nodiscard]] std::string replace_all(std::string_view text, std::string_view search, std::string_view replace);

    [[nodiscard]] std::string concatenate(std::vector<std::string_view> const &strs, std::string_view separator = "");
    [[nodiscard]] std::string concatenate_s(std::vector<std::string> const &strs, std::string_view separator = "");

    /**
     * Parse C++ dates using C's strptime.
     */
    [[nodiscard]] std::optional<datetime> strptime(std::string_view s, std::string_view fmt);

    /**
     * Formats C++ dates using C's strftime.
     */
    [[nodiscard]] std::string strftime(datetime const &dt, std::string_view fmt);

    bin_data &operator<<(encode_length<bin_data> w, std::string_view sv);
    bin_stream &operator>>(encode_length<bin_stream> w, std::string &c);

}// namespace mlab


namespace mlab {
    template <std::size_t N>
    std::string data_to_string(std::array<std::uint8_t, N> const &v) {
        return data_to_string(make_range(v));
    }

    template <std::size_t N>
    std::string data_to_hex_string(std::array<std::uint8_t, N> const &v) {
        return data_to_hex_string(make_range(v));
    }

    template <class It>
    std::string data_to_hex_string(It begin, It end) {
        std::string retval;
        // Include one NUL ending char needed for snprintf
        retval.resize(2 * std::distance(begin, end) + 1);
        auto it = std::begin(retval);
        for (; begin != end; ++begin, it += 2) {
            std::snprintf(&*it, 3, "%02x", *begin);
        }
        // Remove the final null separator
        retval.pop_back();
        return retval;
    }
}// namespace mlab

#endif//MLAB_STRUTILS_HPP
