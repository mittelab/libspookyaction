//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_CONTROLLER_HPP
#define DESFIRE_CONTROLLER_HPP

namespace desfire {
    class controller {
    public:
        virtual std::pair<bin_data, bool> communicate(bin_data const &data) = 0;

        virtual ~controller() = default;
    };
}

#endif //DESFIRE_CONTROLLER_HPP
