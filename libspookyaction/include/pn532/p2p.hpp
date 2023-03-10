//
// Created by spak on 1/20/23.
//

#ifndef PN532_P2P_HPP
#define PN532_P2P_HPP

#include <pn532/controller.hpp>

/**
 * Objects that help establishing a peer-to-peer communication between two PN532.
 */
namespace pn532::p2p {
    using ms = std::chrono::milliseconds;

    /**
     * @brief Generic interface of a P2P NFC module acting as initiator in P2P communication.
     * This sends commands and expects answers.
     */
    struct initiator {
        /**
         * Sends data and receives an answer.
         * @param data Data to send.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The data sent by the target as a response, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] virtual result<mlab::bin_data> communicate(mlab::bin_data const &data, ms timeout) = 0;

        virtual ~initiator() = default;
    };

    /**
     * @brief Generic interface of a P2P NFC module acting as a target in P2P communication.
     * This responds to commands by sending answers.
     */
    struct target {
        /**
         * @brief Receives, synchronously, the data sent by the @ref initiator.
         * A call to @ref send must follow right after having processed the data.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The data sent by the initiator, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] virtual result<mlab::bin_data> receive(ms timeout) = 0;

        /**
         * @brief Sends back an answer to the @ref initiator.
         * This must always be called after @ref receive has returned.
         * @param data Data to send back to the initiator.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success` or any of the @ref channel_error error conditions.
         */
        virtual result<> send(mlab::bin_data const &data, ms timeout) = 0;

        virtual ~target() = default;
    };

    /**
     * @brief Specialization of @ref initiator which uses a @ref controller as initiator.
     * This is a move-only object.
     */
    class pn532_initiator : public initiator {
        controller *_controller = nullptr;
        std::uint8_t _idx{};

    public:
        /**
         * @brief Default-constructs the initiator class.
         * The @ref communicate method will always return @ref channel_error::app_error.
         */
        pn532_initiator() = default;

        /**
         * @brief Wraps a @ref controller and a target associated to the given @p logical_index to work as a initiator.
         * @param controller The PN532 controller. This reference must stay valid throughout the whole lifetime of this object.
         * @param logical_index Logical index of the P2P target, which can be obtained by e.g. @ref controller::initiator_auto_poll.
         * @see controller::initiator_auto_poll
         */
        pn532_initiator(controller &controller, std::uint8_t logical_index);

        pn532_initiator(pn532_initiator const &) = delete;
        pn532_initiator &operator=(pn532_initiator const &) = delete;
        pn532_initiator(pn532_initiator &&) noexcept = default;
        pn532_initiator &operator=(pn532_initiator &&) noexcept = default;

        /**
         * @brief Implements communication over @ref controller::initiator_data_exchange.
         */
        [[nodiscard]] result<mlab::bin_data> communicate(mlab::bin_data const &data, ms timeout) override;
    };

    /**
     * @brief Specialization of @ref initiator which uses a @ref controller as target.
     * This is a move-only object.
     */
    class pn532_target : public target {
        controller *_controller = nullptr;

    public:
        /**
         * @brief Default-constructs the target class.
         * The @ref receive and @ref send methods will always return @ref channel_error::app_error.
         */
        pn532_target() = default;

        /**
         * @brief Wraps a @ref controller to work as a P2P target.
         * @param controller The PN532 controller. This reference must stay valid throughout the whole lifetime of this object.
         * @note This method does not itself put @p controller into target mode. The caller should do this themselves. The
         *  method @ref init_as_dep_target is provided as a shorthand.
         * @see
         *  - controller::target_init_as_target
         *  - init_as_dep_target
         */
        explicit pn532_target(controller &controller);

        pn532_target(pn532_target const &) = delete;
        pn532_target &operator=(pn532_target const &) = delete;
        pn532_target(pn532_target &&) noexcept = default;
        pn532_target &operator=(pn532_target &&) noexcept = default;

        /**
         * @brief Shorthand method which initializes the given @ref controller as a DEP target.
         * This method will make up some of the parameters needed for initialization, and must be called before an
         * exchange can begin. Of course the caller may also call @ref controller::target_init_as_target by themselves,
         * providing custom parameters.
         * This method will initialize a DEP-only, passive or active target for P2P NFC communications.
         * @param nfcid NFCID to use when in the RF. 2t and 1t versions will be truncated from here.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @see controller::target_init_as_target
         */
        [[nodiscard]] result<pn532::activation_as_target> init_as_dep_target(nfcid_3t nfcid, ms timeout = 5s);

        /**
         * @brief Receives data over @ref controller::target_get_data.
         */
        [[nodiscard]] result<mlab::bin_data> receive(ms timeout) override;

        /**
         * @brief Receives data over @ref controller::target_set_data.
         */
        result<> send(mlab::bin_data const &data, ms timeout) override;
    };

}// namespace pn532::p2p

#endif//PN532_P2P_HPP
