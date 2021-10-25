//
// Created by spak on 3/22/21.
//

#ifndef SPOOKY_ACTION_REGISTRAR_HPP
#define SPOOKY_ACTION_REGISTRAR_HPP

#include <map>
#include <memory>

namespace ut {

    using test_tag_t = std::uint32_t;

    template <test_tag_t Tag>
    class test_instance {};

    template <class>
    struct test_tag_of_type {};

    template <test_tag_t Tag>
    struct test_tag_of_type<test_instance<Tag>> {
        static constexpr test_tag_t value = Tag;
    };

    template <class T>
    static constexpr test_tag_t test_tag_of_v = test_tag_of_type<T>::value;

    class test_registrar {
        std::map<test_tag_t, std::weak_ptr<void>> _test_instances;

        bool register_instance(test_tag_t tag, std::weak_ptr<void> instance);

    public:
        test_registrar() = default;

        test_registrar(test_registrar const &) = delete;
        test_registrar &operator=(test_registrar const &) = delete;

        test_registrar(test_registrar &&) noexcept = default;

        test_registrar &operator=(test_registrar &&) noexcept = default;

        template <class TestInstance>
        [[nodiscard]] std::shared_ptr<test_instance<test_tag_of_v<TestInstance>>> get();

        template <class TestInstance>
        bool register_instance(std::shared_ptr<TestInstance> const &instance);
    };

    test_registrar &default_registrar();

}// namespace ut

namespace ut {


    template <class TestInstance>
    [[nodiscard]] std::shared_ptr<test_instance<test_tag_of_v<TestInstance>>> test_registrar::get() {
        static constexpr test_tag_t Tag = test_tag_of_v<TestInstance>;
        if (auto it = _test_instances.template find(Tag); it != std::end(_test_instances)) {
            return std::reinterpret_pointer_cast<test_instance<Tag>>(it->second.lock());
        }
        return nullptr;
    }

    template <class TestInstance>
    bool test_registrar::register_instance(std::shared_ptr<TestInstance> const &instance) {
        static constexpr test_tag_t Tag = test_tag_of_v<TestInstance>;
        static_assert(std::is_base_of_v<test_instance<Tag>, TestInstance>);
        return register_instance(Tag, std::reinterpret_pointer_cast<void>(instance));
    }


}// namespace ut

#endif//SPOOKY_ACTION_REGISTRAR_HPP
