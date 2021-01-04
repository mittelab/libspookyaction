//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_CONTROLLER_HPP
#define DESFIRE_CONTROLLER_HPP

#include <utility>
#include "mlab/bin_data.hpp"

namespace desfire {
    class controller {
    public:
        virtual std::pair<mlab::bin_data, bool> communicate(mlab::bin_data const &data) = 0;

        virtual ~controller() = default;
    };
}

#endif //DESFIRE_CONTROLLER_HPP
