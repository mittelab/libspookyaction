//
// Created by Pietro Saccardi on 21/12/2020.
//

#include <random>
#include "bin_data.hpp"

namespace pn532 {
    void bin_data::randomize() {
        std::random_device r;
        std::default_random_engine e{r()};
        std::uniform_int_distribution<std::uint8_t> dist{
            std::numeric_limits<std::uint8_t>::min(),
            std::numeric_limits<std::uint8_t>::max()
        };
        for (auto &byte : _data) {
            byte = dist(e);
        }
    }
}