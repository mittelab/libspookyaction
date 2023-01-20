//
// Created by spak on 1/20/23.
//

#ifndef PN532_P2P_HPP
#define PN532_P2P_HPP

#include <pn532/controller.hpp>

namespace pn532::p2p {
    using ms = std::chrono::milliseconds;
    namespace {
        using namespace std::chrono_literals;
    }

    template <class... Args>
    using result = pn532::controller::result<Args...>;

    /**
     * @brief Generic interface of a P2P NFC module acting as initiator.
     * This sends commands and expects answers.
     */
    struct initiator {
        [[nodiscard]] virtual result<mlab::bin_data> communicate(mlab::bin_data const &data, ms timeout) = 0;

        virtual ~initiator() = default;
    };

    /**
     * @brief Generic interface of a P2P NFC module acting as a target.
     * This responds to commands by sending answers.
     */
    struct target {
        [[nodiscard]] virtual result<mlab::bin_data> receive(ms timeout) = 0;
        virtual result<> send(mlab::bin_data const &data, ms timeout) = 0;
        virtual ~target() = default;
    };

    /**
     * @brief Specialization of @ref initiator which uses a @ref pn532::controller as initiator.
     */
    class pn532_initiator : public initiator {
        pn532::controller *_controller = nullptr;
        std::uint8_t _idx{};

    public:
        pn532_initiator() = default;
        /**
         * @brief Wraps a @ref pn532::controller and a target associated to the given @p logical_index to work as a initiator in P2P comm.
         * @param logical_index Logical index of the P2P target, used for @ref pn532::controller::initiator_data_exchange.
         */
        pn532_initiator(pn532::controller &controller, std::uint8_t logical_index);
        pn532_initiator(pn532_initiator const &) = delete;
        pn532_initiator &operator=(pn532_initiator const &) = delete;
        pn532_initiator(pn532_initiator &&) noexcept = default;
        pn532_initiator &operator=(pn532_initiator &&) noexcept = default;

        /**
         * @brief Implements communication over @ref pn532::controller::initiator_data_exchange.
         */
        [[nodiscard]] result<mlab::bin_data> communicate(mlab::bin_data const &data, ms timeout) override;
    };

    /**
     * @brief Specialization of @ref initiator which uses a @ref pn532::controller as target.
     */
    class pn532_target : public target {
        pn532::controller *_controller = nullptr;

    public:
        pn532_target() = default;
        explicit pn532_target(pn532::controller &controller);
        pn532_target(pn532_target const &) = delete;
        pn532_target &operator=(pn532_target const &) = delete;
        pn532_target(pn532_target &&) noexcept = default;
        pn532_target &operator=(pn532_target &&) noexcept = default;

        /**
         * @brief Shorthand method which initializes the given @ref pn532::controller as a DEP target.
         * This method will make up some of the parameters needed for initialization, and must be called before an
         * exchange can begin. Of course the caller may also call @ref pn532::controller::target_init_as_target by themselves,
         * providing custom parameters.
         * This method will initialize a DEP-only, passive or active target for P2P NFC communications.
         * @param nfcid_3t NFCID to use when in the RF. 2t and 1t versions will be truncated from here.
         * @param timeout Timeout for activation.
         * @see pn532::controller::target_init_as_target
         */
        [[nodiscard]] result<pn532::init_as_target_res> init_as_dep_target(std::array<std::uint8_t, 10> nfcid_3t, ms timeout = 5s);

        /**
         * @brief Receives data over @ref pn532::target_get_data.
         */
        [[nodiscard]] result<mlab::bin_data> receive(ms timeout) override;

        /**
         * @brief Receives data over @ref pn532::target_set_data.
         */
        result<> send(mlab::bin_data const &data, ms timeout) override;
    };

}// namespace pn532::p2p

#endif//PN532_P2P_HPP
