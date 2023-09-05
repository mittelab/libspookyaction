Terminology
===========

This library is split in 3 main part

.. graphviz::

    digraph libspookyaction {
       fontname="Lato, proxima-nova, 'Helvetica Neue', Arial, sans-serif"
       graph [nodesep=0.2, ranksep=1];
       node [shape = "record" fontname="Lato, proxima-nova, 'Helvetica Neue', Arial, sans-serif"];

       newrank=true;
       compound=true;
       subgraph cluster_Channels{
           label="Channels"
           I2C[label="pn532::i2c" shape=box];
           SPI[label="pn532::spi"shape=box];
           UART[label="pn532::hsu"shape=box];
       }
       subgraph cluster_nfc{
           label="pn532::controller"
           channel[shape=box];
       }
       subgraph cluster_tag{
           label="desfire::tag"
           controller[shape=box];
       }

       channel_interface [label="{\<\<interface\>\>\nChannel|+ raw_send()\l+ raw_receive()\l+ raw_receive_mode()\l+ on_receive_prepare()\l+ on_receive_complete()\l+ on_send_prepare()\l+ on_send_complete()\l}"]

       controllers [label="{\<\<interface\>\>\nController|
       + communicate()}"]

       I2C -> channel [ltail=cluster_Channels];
       channel -> controller [ltail=cluster_nfc];
       channel_interface -> SPI[lhead=cluster_Channels arrowhead="odot"];
       controllers -> channel [lhead=cluster_nfc arrowhead="odot"];

       {rank = same; channel_interface; controllers;}
       {rank = same; I2C;UART;SPI; channel;controller}
    }

Channels
--------

Abstract the communication between the user (microcontroller, computer ecc..) and the tag reader.
At the moment the I2C, SPI and HSU(UART) channel are implemented.

Controllers
-----------

This implements the commands necessary to control the tag reader. It uses a channel to communicate with the reader.
At the moment only the PN532 reader is implemented.

Tags
----

Implement the command and functionality present in a Tag. It uses a controller to communicate with the tag.
At the moment only the DESFIRE tag is implemented.