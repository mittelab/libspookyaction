//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_TAG_HPP
#define DESFIRE_TAG_HPP

#include <memory>
#include "cipher.hpp"
#include "controller.hpp"

namespace desfire {

    class tag {
        controller *_controller;

        inline controller &ctrl();


    public:
        inline explicit tag(controller &controller);

        tag(tag const &) = delete;

        tag(tag &&) = default;

        tag &operator=(tag const &) = delete;

        tag &operator=(tag &&) = default;


    };
}

namespace desfire {

    controller & tag::ctrl() {
        return *_controller;
    }

    tag::tag(controller &controller) : _controller{&controller} {}

}

#endif //DESFIRE_TAG_HPP
