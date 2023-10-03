//
// Created by spak on 2/1/23.
//

#include <mlab/strutils.hpp>

namespace mlab {
    std::string concatenate_s(std::vector<std::string> const &strs, std::string_view separator) {
        std::vector<std::string_view> views;
        views.reserve(strs.size());
        std::copy(std::begin(strs), std::end(strs), std::back_inserter(views));
        return concatenate(views, separator);
    }

    std::string concatenate(std::vector<std::string_view> const &strs, std::string_view separator) {
        if (strs.empty()) {
            return "";
        }
        std::size_t tot_len = 0;
        for (auto const &s : strs) {
            tot_len += s.size();
        }
        std::string retval;
        retval.resize(tot_len + (strs.size() - 1) * separator.size(), '\0');
        auto jt = std::begin(strs);
        auto it = std::copy(std::begin(*jt), std::end(*jt), std::begin(retval));
        for (++jt; jt != std::end(strs); ++jt) {
            it = std::copy(std::begin(separator), std::end(separator), it);
            it = std::copy(std::begin(*jt), std::end(*jt), it);
        }
        return retval;
    }

    range<std::uint8_t const *> data_view_from_string(std::string_view s) {
        return range<std::uint8_t const *>{
                reinterpret_cast<std::uint8_t const *>(s.data()),
                reinterpret_cast<std::uint8_t const *>(s.data() + s.size())};
    }

    bin_data data_from_string(std::string_view s) {
        bin_data retval;
        retval << prealloc(s.size()) << data_view_from_string(s);
        return retval;
    }

    namespace {
        /**
         * I'm sure there is a clever way but scanf doesn't work on bytes,
         * apparently, and I'm sick and tired of digging through C oddities.
         */
        [[nodiscard]] std::uint8_t constexpr char_to_byte(char c) {
            if ('0' <= c and c <= '9') {
                return std::uint8_t(c - '0');
            } else if ('a' <= c and c <= 'f') {
                return std::uint8_t(0xa) + std::uint8_t(c - 'a');
            } else if ('A' <= c and c <= 'F') {
                return std::uint8_t(0xa) + std::uint8_t(c - 'A');
            } else {
                return 0;
            }
        }
    }// namespace

    bin_data data_from_hex_string(std::string_view s) {
        bin_data retval;
        retval.resize(s.size() / 2);
        for (std::size_t i = 0; i < retval.size(); ++i) {
            retval[i] = (char_to_byte(s[2 * i]) << 4) | char_to_byte(s[2 * i + 1]);
        }
        return retval;
    }

    std::string data_to_string(std::vector<std::uint8_t> const &v) {
        return data_to_string(make_range(v));
    }

    std::string data_to_string(range<bin_data::const_iterator> rg) {
        const range<char const *> view{
                reinterpret_cast<char const *>(rg.data()),
                reinterpret_cast<char const *>(rg.data() + rg.size())};
        return std::string{std::begin(view), std::end(view)};
    }

    std::string data_to_string(range<std::uint8_t const *> rg) {
        const range<char const *> view{
                reinterpret_cast<char const *>(rg.data()),
                reinterpret_cast<char const *>(rg.data() + rg.size())};
        return std::string{std::begin(view), std::end(view)};
    }

    std::string data_to_string(bin_data const &bd) {
        const range<char const *> view{
                reinterpret_cast<char const *>(bd.data()),
                reinterpret_cast<char const *>(bd.data() + bd.size())};
        return std::string{std::begin(view), std::end(view)};
    }

    std::string data_to_hex_string(std::vector<std::uint8_t> const &v) {
        return data_to_hex_string(std::begin(v), std::end(v));
    }

    std::string data_to_hex_string(range<bin_data::const_iterator> rg) {
        return data_to_hex_string(std::begin(rg), std::end(rg));
    }

    std::string data_to_hex_string(range<std::uint8_t const *> rg) {
        return data_to_hex_string(std::begin(rg), std::end(rg));
    }

    std::string replace_all(std::string_view text, std::string_view search, std::string_view replace) {
        if (text.empty() or search.empty()) {
            return std::string{text};
        }
        std::string retval;
        retval.reserve(text.length());

        std::size_t last_pos = 0;
        std::size_t cur_pos = std::string::npos;

        auto append_cur_range = [&]() {
            const std::size_t beg = std::clamp(last_pos, 0u, text.length());
            const std::size_t end = std::clamp(cur_pos, beg, text.length());
            retval.append(
                    std::begin(text) + std::string::difference_type(beg),
                    std::begin(text) + std::string::difference_type(end));
        };

        while ((cur_pos = text.find(search, last_pos)) != std::string::npos) {
            append_cur_range();
            retval.append(replace);
            last_pos = cur_pos + search.length();
        }
        append_cur_range();
        return retval;
    }

    std::optional<datetime> strptime(std::string_view s, std::string_view fmt) {
        if (std::tm tm{}; ::strptime(s.data(), fmt.data(), &tm) != nullptr) {
            const auto c_time = std::mktime(&tm);
            return std::chrono::system_clock::from_time_t(c_time);
        }
        return std::nullopt;
    }

    std::string strftime(datetime const &dt, std::string_view fmt) {
        std::array<char, 64> buffer{};
        const auto c_time = std::chrono::system_clock::to_time_t(dt);
        const auto *tm = std::localtime(&c_time);
        if (const auto nchars = std::strftime(buffer.data(), buffer.size(), fmt.data(), tm); nchars > 0) {
            return {std::begin(buffer), std::begin(buffer) + nchars};
        }
        return "<date format too long>";
    }

    bin_data &operator<<(encode_length<bin_data> w, std::string_view sv) {
        return w << data_from_string(sv);
    }

    bin_stream &operator>>(encode_length<bin_stream> w, std::string &c) {
        mlab::bin_data raw_data;
        w >> raw_data;
        if (not w.s.bad()) {
            c = data_to_string(raw_data);
        }
        return w.s;
    }

}// namespace mlab
