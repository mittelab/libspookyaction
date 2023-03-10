//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_PCD_HPP
#define DESFIRE_PCD_HPP

#include <mlab/bin_data.hpp>
#include <optional>
#include <utility>

namespace desfire {
    /**
     * Abstract class for a Proximity Coupling Device, i.e. a Desfire card reader.
     * @see pn532::desfire_pcd
     */
    class pcd {
    public:
        /**
         * @brief Exchanges data with an NFC card.
         * @param data Data to send
         * @return A response-success pair; the first element of the pair is the response from the card, the second boolean represent whether the
         *  exchange was successful.
         */
        [[nodiscard]] virtual std::optional<mlab::bin_data> communicate(mlab::bin_data const &data) = 0;

        virtual ~pcd() = default;
    };
}// namespace desfire

#endif//DESFIRE_PCD_HPP
