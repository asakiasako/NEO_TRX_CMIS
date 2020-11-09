## Usage of CMIS object:

Chinese version is also available in same dir.

Let's name a `CMIS` instance as `cmis`.

* **Hardware pins:**

    The key is a str, exactly the same as hardware pin names defined in corresponding Hardware specification, such as 'LPWn', 'INT' for OSFP modules.

    * Get hardware pin level: 
    
        ``` python
        # v_level is a bool. True -> high level, False -> low level
        v_level = cmis['LPWn']
        ```

    * Set hardware pin level:
    
        Only control pins can be set, alarm pins can only be get.

        ``` python
        # True -> high level, False -> low level
        cmis['LPWn'] = True
        ```

* **Register operation:**

    The key is an int, such as `0x80` or `128`. Since CMIS module register address is in range of `0 ~ 0xFF`, keys out of range are invalid.

    * Get register value:

        ``` python
        reg_value = cmis[0x80]
        # returns a int-like object -- RegisterValue. Further operations are described in Bits operation.
        ```

    * Set register value:

        ``` python
        # value is an int in range of 0 to 0xFF
        cmis[0x80] = value
        ```

    * Read a multi-register sequence:

        ``` python
        # Returns a int. Note that stop reg is included.
        # Max length = 4
        # registers must be sequential
        s1 = cmis[0x80: 0x81]
        # same as: 2^8 * cmis[0x80] + cmis[0x81]
        # Note that 0x81 is included

    * Write a multi-register sequence:
  
    ``` python
    # Max length = 4
    # registers must be sequential
    cmis[0x80:0x81] = 0x0102
    # same as: cmis[0x80] = 0x01, cmis[0x81] = 0x02
    # Note that 0x81 is included
    ```

* **Bits operation:**

    The register value you get from a register operation is actually an int-like, RegisterValue object. That means, you can use it as an int, but it has several additional operations.

    A RegisterValue object can be indexed or sliced for bits operations.

    * Get a register bit:

        ``` python
        # get 0x8001 bit 7, returns an int.
        cmis[0x80][7]
        ```

    * Get some register bits:

        ``` python
        # get 0x8001 bit 7~4, returns an int
        cmis[0x80][7: 4]
        ```

    * Set a register bit:

        ``` python
        # valid set values are 0 or 1
        cmis[0x80][7] = 1
        ```

    * Get some register bits:

        ``` python
        # set 0x8001 bit 7~4, note the value should not larger than 0b1111 (the bit width you set into)
        cmis[0x80][7: 4] = 0b0101
        ```

    **Note for slice operation:**

    For slice of a RegisterValue object, both start & stop bits are included in a slice. For example, `reg_val[5: 3]` includes `reg_val[5]`, `reg_val[4]`, `reg_val[3]`. Bit `3` is not excluded.

    This expression is in compliance of CMIS Referring to Bytes and Fields -- `bank:page:byte.bit-bit`. For example, `0x80.7-3` -> `cmis[0x80][7: 3]`.
    
    On the other hand, this is more elegant. Think a case if we need bits 4~0. If stop bit is excluded, we should write `reg_val[4: -1]`, that's UGLY. 
    
    For a valid slice `reg_val[start:stop]`, `start` should larger or equal than `stop`. Param `step` is not allowed here.

    **Note for setting register bit(s):**

    There is no direct bits operation in CMIS. The atom operation unit is a register. So setting register bit(s) is actually realized by 3 steps:

    ```
    1. Read from a register.
    2. Change some bits in that value.
    3. Write modified value back to the register.
    ```

* **Page select & bank select**

    * Page select

        ``` python
        cmis.page = 10
        ```

    * Bank select

        ```
        cmis.bank = 2
        ```

        Note that according to CMIS, a page select is always required for a bank select operation to execute, even if the page number is not changed.

    * along with register operations:

        position can be any value supported.

        ``` python
        cmis[page_num, position]
        ```
        equals to:
        ``` python
        cmis.page = page_num
        cmis[position]
        ```
        ---
        ``` python
        cmis[bank_num, page_num, position]
        ```
        equals to:
        ``` python
        cmis.bank = bank_num
        cmis.page = page_num
        cmis[position]
        ```

# Interface

package exposes: `__all__ = ['CMIS', 'HW_TYPE']`

`HW_TYPE`: enum, defined in '/constants.py'

`CMIS`: the CMIS complied object. see '/CMIS.py'

## Inherit

* **Initialize**

    ``` python
    CMIS(hw_type)
    ```

    `hw_type`: Enum HW_TYPE. This parameter defines hardware specification of the CMIS object, which determins the hardware pin map of the CMIS object.

Operates on CMIS objects with index/slice operator. There is no need to call methods.

CMIS has several formal interfaces so that CMIS should be inherited, and these methods should be overrode. Please refer to `CMIS.py` for more information.

If one of these methods is not overrode, a `NotImplementedError` will be raised.

* `set_pin_state(pin_name, is_high_level)`

* `get_pin_state(pin_name)`

* `write_twi_register(twi_addr, data)`

* `read_twi_register(twi_addr)`