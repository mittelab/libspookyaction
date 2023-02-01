//
// Created by spak on 3/22/21.
//

#include "registrar.hpp"
#include <esp_log.h>

namespace ut {

    test_registrar &default_registrar() {
        static thread_local test_registrar _registrar{};
        return _registrar;
    }

    bool test_registrar::register_instance(std::uint32_t tag, std::weak_ptr<void> instance) {
        auto lower_bd = _test_instances.lower_bound(tag);
        if (lower_bd == std::end(_test_instances) or lower_bd->first != tag) {
            // Can just emplace
            _test_instances.emplace_hint(lower_bd, tag, instance);
            return true;
        } else {
            // Is the previous pointer expired?
            if (lower_bd->second.expired()) {
                // Replace
                lower_bd->second = instance;
                return true;
            } else {
                ESP_LOGE("UT", "Test instance for tag %lu already registered and in use.", tag);
                return false;
            }
        }
    }

}// namespace ut