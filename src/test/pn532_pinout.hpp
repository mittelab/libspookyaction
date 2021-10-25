//
// Created by spak on 10/25/21.
//

#ifndef SPOOKY_ACTION_PN532_PINOUT_HPP
#define SPOOKY_ACTION_PN532_PINOUT_HPP

#include <driver/gpio.h>

namespace ut::pn532 {
    enum struct channel_type {
        hsu,
        i2c,
        i2c_irq,
        spi,
        spi_irq
    };


    namespace pinout {

#ifndef PN532_SERIAL_RX
        static constexpr gpio_num_t pn532_hsu_rx = GPIO_NUM_NC;
#else
        static constexpr gpio_num_t pn532_hsu_rx = static_cast<gpio_num_t>(PN532_SERIAL_RX);
#endif

#ifndef PN532_SERIAL_TX
        static constexpr gpio_num_t pn532_hsu_tx = GPIO_NUM_NC;
#else
        static constexpr gpio_num_t pn532_hsu_tx = static_cast<gpio_num_t>(PN532_SERIAL_TX);
#endif

#ifndef PN532_I2C_SCL
        static constexpr gpio_num_t pn532_i2c_scl = GPIO_NUM_NC;
#else
        static constexpr gpio_num_t pn532_i2c_scl = static_cast<gpio_num_t>(PN532_I2C_SCL);
#endif

#ifndef PN532_I2C_SDA
        static constexpr gpio_num_t pn532_i2c_sda = GPIO_NUM_NC;
#else
        static constexpr gpio_num_t pn532_i2c_sda = static_cast<gpio_num_t>(PN532_I2C_SDA);
#endif

#ifndef PN532_SPI_MISO
        static constexpr gpio_num_t pn532_spi_miso = GPIO_NUM_NC;
#else
        static constexpr gpio_num_t pn532_spi_miso = static_cast<gpio_num_t>(PN532_SPI_MISO);
#endif

#ifndef PN532_SPI_MOSI
        static constexpr gpio_num_t pn532_spi_mosi = GPIO_NUM_NC;
#else
        static constexpr gpio_num_t pn532_spi_mosi = static_cast<gpio_num_t>(PN532_SPI_MOSI);
#endif

#ifndef PN532_SPI_SCK
        static constexpr gpio_num_t pn532_spi_sck = GPIO_NUM_NC;
#else
        static constexpr gpio_num_t pn532_spi_sck = static_cast<gpio_num_t>(PN532_SPI_SCK);
#endif

#ifndef PN532_SPI_SS
        static constexpr gpio_num_t pn532_spi_ss = GPIO_NUM_NC;
#else
        static constexpr gpio_num_t pn532_spi_ss = static_cast<gpio_num_t>(PN532_SPI_SS);
#endif

#ifndef PN532_I0
        static constexpr gpio_num_t pn532_cicd_i0 = GPIO_NUM_NC;
#else
        static constexpr gpio_num_t pn532_cicd_i0 = static_cast<gpio_num_t>(PN532_I0);
#endif

#ifndef PN532_I1
        static constexpr gpio_num_t pn532_cicd_i1 = GPIO_NUM_NC;
#else
        static constexpr gpio_num_t pn532_cicd_i1 = static_cast<gpio_num_t>(PN532_I1);
#endif

#ifndef PN532_RSTN
        static constexpr gpio_num_t pn532_cicd_rstn = GPIO_NUM_NC;
#else
        static constexpr gpio_num_t pn532_cicd_rstn = static_cast<gpio_num_t>(PN532_RSTN);
#endif

#ifndef PN532_IRQ
        static constexpr gpio_num_t pn532_irq = GPIO_NUM_NC;
#else
        static constexpr gpio_num_t pn532_irq = static_cast<gpio_num_t>(PN532_IRQ);
#endif
    }// namespace pinout

#ifdef SPOOKY_I2C
    static constexpr bool supports_i2c = true;
#else
    static constexpr bool supports_i2c = false;
#endif
#ifdef SPOOKY_I2C_IRQ
    static constexpr bool supports_i2c_irq = true;
#else
    static constexpr bool supports_i2c_irq = false;
#endif

#ifdef SPOOKY_SPI
    static constexpr bool supports_spi = true;
#else
    static constexpr bool supports_spi = false;
#endif
#ifdef SPOOKY_SPI_IRQ
    static constexpr bool supports_spi_irq = true;
#else
    static constexpr bool supports_spi_irq = false;
#endif


#ifdef SPOOKY_HSU
    static constexpr bool supports_hsu = true;
#else
    static constexpr bool supports_hsu = false;
#endif

#ifdef SPOOKY_CI_CD_MACHINE
    static constexpr bool supports_cicd_machine = true;
#else
    static constexpr bool supports_cicd_machine = false;
#endif

    constexpr bool channel_is_supported(channel_type type) {
        switch (type) {
            case channel_type::i2c_irq:
                return supports_i2c_irq;
            case channel_type::i2c:
                return supports_i2c;
            case channel_type::hsu:
                return supports_hsu;
            case channel_type::spi:
                return supports_spi;
            case channel_type::spi_irq:
                return supports_spi_irq;
            default:
                return false;
        }
    }

#define PN532_ASSERT_DEFINED_PIN(PIN_MACRO) \
    static_assert(PIN_MACRO > GPIO_NUM_NC and PIN_MACRO < GPIO_NUM_MAX, "You did not define macro " #PIN_MACRO " (must be a valid GPIO pin).")

#if defined(SPOOKY_I2C) || defined(SPOOKY_I2C_IRQ)
    PN532_ASSERT_DEFINED_PIN(PN532_I2C_SCL);
    PN532_ASSERT_DEFINED_PIN(PN532_I2C_SDA);
#endif

#if defined(SPOOKY_SPI) || defined(SPOOKY_SPI_IRQ)
    PN532_ASSERT_DEFINED_PIN(PN532_SPI_MISO);
    PN532_ASSERT_DEFINED_PIN(PN532_SPI_MOSI);
    PN532_ASSERT_DEFINED_PIN(PN532_SPI_SCK);
    PN532_ASSERT_DEFINED_PIN(PN532_SPI_SS);
#endif

#if defined(SPOOKY_SPI_IRQ) || defined(SPOOKY_I2C_IRQ)
    PN532_ASSERT_DEFINED_PIN(PN532_IRQ);
#endif

#if defined(SPOOKY_HSU)
    PN532_ASSERT_DEFINED_PIN(PN532_SERIAL_TX);
    PN532_ASSERT_DEFINED_PIN(PN532_SERIAL_RX);
#endif

#if defined(SPOOKY_CI_CD_MACHINE)
    PN532_ASSERT_DEFINED_PIN(PN532_I0);
    PN532_ASSERT_DEFINED_PIN(PN532_I1);
    PN532_ASSERT_DEFINED_PIN(PN532_RSTN);
#endif

#undef PN532_ASSERT_DEFINED_PIN

}// namespace ut::pn532

#endif//SPOOKY_ACTION_PN532_PINOUT_HPP
