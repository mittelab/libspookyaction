//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_PCD_HPP
#define DESFIRE_PCD_HPP

#include <mlab/bin_data.hpp>
#include <utility>

namespace desfire {
    class pcd {
    public:
        virtual std::pair<mlab::bin_data, bool> communicate(mlab::bin_data const &data) = 0;

        virtual ~pcd() = default;
    };
}// namespace desfire

#endif//DESFIRE_PCD_HPP
