CMIS Interface Userguide
===

CMIS python 库依据 CMIS Specification 4.0，将符合 CMIS 协议的模块抽象出来，以达到统一接口的目的。

CMIS 接口的设计原则是：

1. 与 CMIS 协议的一致性。所有专有名词（如 signal pin name）和描述方式与 CMIS 协议保持一致。
2. 直观，简洁，易用。大部分基础操作可以采用运算符实现，不需要调用函数，使用更为便捷。

对于 CMIS 协议规定的某些名词或缩写，本文档将直接引用，不做额外的解释。所有专有名词与 CMIS 协议保持严格一致。

CMIS 接口主要包含以下几个方面的内容：

I. 基础管理接口

1. CMIS generic signals
2. Form factor specific signals
3. TWI register and bits operations

II. 应用接口

1. Module State Machine and Data Path State Machine
2. CDB (Common Data Block)
3. Other informations, e.g. Module PN/SN, etc.
4. Extended applications, e.g. get Pre-Fec BER

由于预期不会出现 flat memory 的模块，所有接口都是针对 multi-page 模块而设计。

下面详细介绍这些接口。

## 接口设计

### 基础管理接口

1. CMIS generic signals and form factor specific signals

    CMIS generic signals 是由 CMIS 协议规定的通用信号名称，包括 ResetL，Interrupt，LPMode。

    Form factor specific signals 是由对应模块的封装协议所规定的信号名称，通常对应物理 pin 脚的电平高低。以 OSFP 为例，它定义了 4 个信号：RSTn, INT, LPWn, PRSn。我们只关注这些信号的逻辑值，而不关心其具体的物理实现。

    CMIS 对象在初始化时会指定模块的 hw_type，根据这个参数来确定其具有哪些 form factor specific signals。

    每个 CMIS generic signal 在 form factor 都有其对应的 form factor specific signal，但它们的逻辑可能是相反的。以 OSFP 为例，CMIS 中的 ResetL 对应 OSFP 的RSTn，它们都是 active low，因此它们的逻辑是相同的。而 CMIS 中的 LPMode 是 active high，对应 OSFP 中的 LPWn，是 active low。因此这两个信号的逻辑值是相反的。

    使用 `[]` 操作符对这些信号进行操作，赋值或返回一个 bool 类型。`[]` 操作符接收一个字符串，与协议规定的信号名称严格一致。

    我们以一个 OSFP 类型的 cmis 对象为例：

    - 读取信号

        ``` python
        state = cmis['LPMode']  # returns a bool
        state = cmis['LPWn']    # returns a bool
        ```

    - 设置信号

        对于无法被设置的信号，抛出一个 PermissionError

        ``` python
        cmis['LPMode'] = True   # set LPMode -> True
        cmis['LPWn'] = False    # set LPWn -> False
        # 以上操作是完全等价的
        cmis['INT'] = True      # raise a PermissionError
        ```

2. TWI register and bits operations

    CMIS 使用 TWI 来对模块内的寄存器进行读写访问。通过 `[]` 操作符，可以对寄存器进行随机读写（Random Read/Write）和随机序列读写（Sequential Read from Random Start Address/Sequential Write）。

    对于读取单个寄存器所得到的寄存器值（事实上是一个 RegisterValue 对象），还可以进一步对其进行位和位区间的读写操作。

    不指定地址的读操作无法通过 `[]` 操作完成（通常情况下不建议使用该操作，因为它无法保证操作是符合预期的），但你仍可以通过 cmis 的 read_twi_register 方法来实现该操作。

    - Random Byte Read Operation

        `[]` 操作符接收寄存器的地址（int）作为参数，返回一个 RegisterValue 对象。这个对象是一个 int-like 对象，支持 int 对象的所有操作，它的值与寄存器所表示的无符号整数的值相等。

        ``` python
        reg_value = cmis[0x7F]  # returns a RegisterValue object
        reg_value = cmis[127]   # returns a RegisterValue object
        ```

        如果你需要该寄存器所代表的有符号整数的值，可以使用 `RegisterValue.to_signed()` 方法，该方法返回一个 int。

        ``` python
        val = cmis[0x7F].to_signed()
        ```

        如果指定的地址超过了 CMIS 协议规定的有效范围（0x00~0xFF），将抛出一个 `IndexError`。

        对 RegisterValue 还可以进行进一步的位操作，将在后文中描述。

    - Byte Write Operation

        `[]` 操作符接受寄存器的地址（int）作为参数，赋值一个 int 对象。该 int 对象将作为寄存器所表示的无符号整数写入寄存器。

        ``` python
        cmis[0x7F] = 0x10
        ```

        如果指定的地址超过了 CMIS 协议规定的有效范围（0x00~0xFF），将抛出一个 `IndexError`。如果赋值超过了寄存器所能表示的无符号整数的范围（0x00~0xFF），将抛出一个 `ValueError`。

    - Sequential Read from Random Start Address

        `[]` 操作符接收寄存器地址的起止位作为参数，返回一个 `RegisterSequence` 对象。这个对象是一个 bytes-like 对象，支持 bytes 对象的所有操作，它的值与寄存器序列的值一一对应。

        该操作主要用于将一段寄存器序列通过 sequential read 的方式读取出来。按照协议，对于长度为 2 bytes 的 sequential read，需要保证数据在各个寄存器中的一致性。对于长度大于 2 bytes 的 sequential read，数据一致性由模块制造商决定，协议并不保证。

        ``` python
        val = cmis[0x70:0x71]
        # Sequential Reads register: 0x70, 0x71
        # Returns an bytes-like RegisterSequence object
        ```

        需要注意的是，在 Sequential Read 操作中，寄存器地址的起止位都被包含在所需要读取的地址序列中。例如：`cmis[0x00:0x03]` 将读取 4 个地址，最后一位 `0x03` 也被包括其中。这点与 python 中大多数序列的一般表示不同。这样设计的原因一是为了与 `CMIS` 对于寄存器序列的表达形式相一致；二是对于寄存器表来说，这种表达方式更为直观和优雅。你肯定不希望你的代码里出现 `cmis[0xFE:0x100]` 这种丑陋的表达，因为 `0x100` 这个地址在寄存器中并不存在的。

        如果你需要获得寄存器序列所对应的整数值，你可以使用 `to_signed` 和 `to_unsigned` 方法，将其转换成 `int` 类型（分别视为 `signed int` 和 `unsigned int`）。

        ``` python
        cmis[0x70:0x71].to_signed()
        cmis[0x70:0x71].to_unsigned()
        ```

        如果序列中的任何一个地址超过了 CMIS 协议规定的有效范围（0x00~0xFF），将抛出一个 `IndexError`。

    - Sequential Byte Write Operation

        该操作用于将一段寄存器序列作为整体，接受赋值。赋值的类型可以是 `bytes` 类型，或其他由 int 构成的 Iterable 类型（将被转化为bytes），也可以是 `int` 类型。对于 `bytes` 类型或其它 Iterable 类型，数据的长度应与指定的寄存器地址的长度严格相等；对于 `int` 类型，应以 `unsigned` 的形式写入，且数据的值不能超过寄存器序列所能表示的最大无符号整数的值。对于不符合要求的数据，将抛出 `ValueError`。

        ``` python
        cmis[0x70:0x71] = 0x1001
        # OR
        cmis[0x70:0x71] = b'\x10\x11'
        # OR
        cmis[0x70:0x71] = [0x10, 0x11]
        ```

        同样的，寄存器地址的起止位都包含在所需读取的地址序列中。

        如果序列的任何一个地址超过了 CMIS 协议规定的有效范围（0x00~0xFF），将抛出一个 `IndexError`。如果所赋值的数据不符合要求，将抛出一个 `ValueError`。

    - Bits Read Operation

        对于读取寄存器所获得的 `RegisterValue` 对象，还可以进一步进行位的读写操作。既可以读取某个位的值，也可以读取几个连续位组成的位区间。

        对 RegisterValue 读取位或位序列，将返回一个整数，该整数的值为这段位或位序列所表示的无符号整数。

        ``` python
        v_bit3 = cmis[0x03][3]      # value of 0x30.3
        v_bit7_3 = cmis[0x03][7:4]  # value of 0x30.7-3
        ```

        由于寄存器位中，bit 7 为 MSB，因此一个寄存器序列的起始位总是大于终止位，如果起始位小于终止位，将抛出 `IndexError`：

        ``` python
        v_bits = cmis[0x03][4:7]    # raise IndexError
        ```

        如果任意位号超过了寄存器的位号范围（0~7），将抛出 `IndexError`。

        需要注意的是，在该操作中，位号的起止位都被包含在所需要读取的位序列中。例如：`cmis[0x03][7:4]` 将读取 4 个位，最后一位 `bit4` 也被包括其中。这点与序列的一般操作不同。这样设计的原因一是为了与 `CMIS` 对于寄存器位的表达相一致；二是对于寄存器表来说，这种表达方式更为合适、直观、优雅。你肯定不希望你的代码里出现 `cmis[0x03][3:-1]` 这种丑陋的表达，竟然出现了负数的位号，这显然很别扭。

        事实上，该操作只是对已经获取的 `RegisterValue` 值所做的数学处理。真正的读取操作早在 `RegisterValue` 生成时就已经完成了。

    - Bits Write Operation

        类似的，你可以将合适的整数赋值给一个寄存器位或者位序列。

        ``` python
        cmis[0x03][7:4] = 0b1011
        ```

        由于寄存器位中，bit 7 为 MSB，因此一个寄存器序列的起始位总是大于终止位，如果起始位小于终止位，将抛出 `IndexError`。如果任意位号超过了寄存器的位号范围（0~7），将抛出 `IndexError`。如果赋值的整数超过了寄存器位或位序列所能容纳的无符号整数范围，将抛出 `ValueError`。

        同样的，寄存器位号的起止位都包含在所需读取的寄存器位序列中。

        事实上，该操作首先对应获取的 `RegisterValue` 做数学处理，替换掉所写入的位或位序列，然后将新的值写回寄存器中。

    - page & bank select

        通过 `page` 和 `bank` 属性来读取当前的 page 和 bank。

        ``` python
        p = cmis.page
        b = cmis.bank
        ```

        通过 `select_page(page)` 方法或者 `page` 属性来设置 `page`。通过 `select_bank_page(bank, page)` 方法来同时设置 bank 和 page。根据 CMIS 协议，单独设置 bank 是无效的操作，因此 `bank` 属性是不可写的，必须通过 `select_bank_page()` 方法来设置 bank 和 page。

        ``` python
        cmis.page = 0x10                # set page to 0x10
        cmis.select_page(0x10)             # set page to 0x10
        cmis.select_bank_page(0, 0x10)     # set to bank 0, page 0x10
        ```

        设置的 page 和 bank 的值必须在 CMIS 协议规定的范围。bank index：（0-255），page index：（0x00-0xFF)。

    - page & bank select with register operation

        在使用 `[]` 操作符时，可以指定 bank 和/或 page。这在需要切换 page 的单歩操作中很有用，例如读取单个寄存器或寄存器序列。

        - 指定 page，并进行操作：

            ``` python
            cmis[page_num, position]
            # 等价于：
            cmis.page = page_num
            cmis[position]
            ```

            任何 `[]` 操作符支持的 `position` 都是有效的，例如寄存器的读写以及寄存器序列的读写。

            例如：
            ``` python
            cmis[0x10, 160][7:4] = 0b0110
            # page 10h, byte 160, bit 7~4 set 0b0110
            ```

        - 指定 bank 和 page，并进行操作

            ``` python
            cmis[bank_num, page_num, position]
            # 等价于
            cmis.select_bank_page(bank_num, page_num)
            cmis[position]
            ```
            
            任何 `[]` 操作符支持的 `position` 都是有效的，例如寄存器的读写以及寄存器序列的读写。

            例如：
            ``` python
            cmis[0, 0x10, 160][7:4] = 0b0110
            # bank 0, page 10h, byte 160, bit 7~4 set 0b0110
            ```

        这个操作格式本质上是一个语法糖，对于设置 page/bank 后只进行单歩操作的情况，这种表达方式更加的简洁清晰。但是对于设置 page/bank 后需要进行一系列操作的情况，将 page/bank 设置单独的提出来放在所有操作的开头，可能会使逻辑更清晰。

### 应用接口

1. Module State Machine and Data Path State Machine

    - `cmis.get_module_state()`

        返回模块状态字符串，与 CMIS 协议所规定的标准命名相一致。

        例如：`'ModulePwrDn'`

        更多细节参考 CMIS 协议。

    - `cmis.get_data_path_state(n_lane)`

        `n_lane`: int, lane 的序号。

        返回 Data Path 状态字符串，与 CMIS 协议所规定的标准命名相一致。

        例如：`'DataPathInit'`

        更多细节参考 CMIS 协议。

2. CDB (Command Data Block)

    根据 CMIS 协议，每个模块可以至多支持 2 个 Command Data Block。可以通过 `cdb1` 和 `cdb2` 属性来分别访问这两个 `CDB` 对象。

    需要注意的是，对于 CDB 的支持是由模块装配商决定的，为了减少对模块的不必要操作，不会检查 CDB 的装配情况。你需要自己确保你所操作的 CDB 已在模块中实现。

    每个 CDB 对象都具有以下功能：

    * 获取 CDB 的状态。主要包括 L-CDB block complete flag，以及 CDB status fields 中的一系列信号。

        ``` python
        # L-CDB complete flag
        flag = cmis.cdb1.complete

        # CDB status fields
        cmis.cdb1.STS_BUSY
        cmis.cdb1.STS_FAIL
        cmis.cdb1.result
        ```

    * CDB 命令的执行。

        可以通过 `execute` 方法或者直接调用 `CDB` 对象来执行 CDB 命令。lpl 和 epl 是可选的，取决于具体的命令。

        默认情况下，程序会等待 CDB 命令结束，并返回一个结果元祖，第一个元素表示命令是否成功，第二个元素为 result。

        你可以给 CDB 命令指定一个 timeout 参数，这样如果超时，函数会报错并退出。

        如果你希望异步执行 CDB 命令，可以设置 `_async` 为 `True`，这样程序会在完成 CDB 命令的写入后立刻返回（无返回值）。你可以通过手动读取 CDB status field 相关的属性来判断 CDB 的状态，以及获取结果。

        ``` python
        cmis.cdb1(cmd, lpl, epl, timeout=5)
        # OR
        cmis.cdb1.execute(cmd, lpl, epl, _async = True)
        # 'cmd' is required, while 'lpl' and 'epl' are optional.
        ```
    
    * 获取返回的 payload。

        某些 CDB 命令会在 RLPL 或 EPL 中返回一些数据。可以使用 `get_rlpl()` 或 `get_epl()` 方法获得这些数据。对于 RLPL，会自动检查 RLPLLen 以及 RLPLChkCode 并进行验证，最终返回的只有 RLPL 的数据（bytes）。

        ``` python
        cmis.cdb1.get_rlpl()
        cmis.cdb2.get_epl()
        ```

3. Information

4. Other applications
