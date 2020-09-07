## Logical Layers

The realization of OSFP EVB Interface can be understood in terms of 3 logical layers.

Note: These layer only describe coding logic.

1. master control transport layer

    This layer is the connection between EVB and master computer, such as a serial or socket.

2. management data transfer layer

    This layer sets/gets the basic management data for EVB, such as analog/digital values and twi registers.

3. application layer

    Applications based on layer 2, such as Vcc setting or module pin status.