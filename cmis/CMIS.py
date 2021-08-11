from abc import ABC, abstractmethod
from .constants import HW_TYPE, HW_SIG_PINS, GENERIC_SIG_MAPS
from .cdb_apis import CdbApi
from ._utils import check_range
from ._types import RegisterValue, RegisterSequence
from typing import Iterable
import re
import time


class CDB:
    def __init__(self, cmis, cdb_idx):
        """
        cmis: CMIS object to execute cdb
        cdb_idx: 1 or 2, CDB block index. cdb1->bank0, cdb2->bank1
        """
        self.__cmis = cmis
        self.__cdb_idx = cdb_idx
        self.__cdb_bank = self.__cdb_idx - 1
        self.__status_field_addr = 36 + cdb_idx # cdb1: 37, cdb2: 38
        self.__l_cdb_complete_bit = 5 + cdb_idx # cdb1: bit6, cdb2: bit7
    
    @ property
    def complete_flag(self):
        """
        L-CDB block complete flag, clear on read.
        return: bool
        """
        flag = self.__cmis[8][self.__l_cdb_complete_bit]
        return bool(flag)

    @ property
    def STS_BUSY(self):
        """
        STS_BUSY is a status bit in CDB Status fields.
        indicating the availability of the CDB interface.
        """
        status = self.__cmis[self.__status_field_addr][7]
        return bool(status)

    @ property
    def STS_FAIL(self):
        """
        STS_FAIL is a status bit in CDB Status fields.
        indicating if last triggered CDB command completed successfully.
        """
        status = self.__cmis[self.__status_field_addr][6]
        return bool(status)

    @ property
    def last_command_result(self):
        """
        result code of last triggered CDB command.
        refer to CMIS specification for details.
        """
        res = self.__cmis[self.__status_field_addr][5:0]
        return res

    def __calc_check_code(self, *_bytes):
        _bytes_sum = sum(b''.join(_bytes))
        check_code = (0xFF^_bytes_sum)&0xFF
        return check_code

    def __calc_cdb_check_code(self, cmd, lpl, epl):
        """
        cmd: bytes
        lpl: bytes
        epl: bytes
        return: int
        """
        cmd = cmd.to_bytes(2, 'big')
        bytes_len_lpl = len(lpl).to_bytes(1, 'big')
        bytes_len_epl = len(epl).to_bytes(2, 'big')
        return self.__calc_check_code(cmd, bytes_len_lpl, bytes_len_epl, lpl)

    def __calc_rlpl_check_code(self, rlpl):
        return self.__calc_check_code(rlpl)

    def __call__(self, cmd, lpl=b'', epl=b'', timeout=0, _async=False):
        """
        cmd: int
        epl: bytes
        lpl: bytes
        timeout: timeout to wait CDB complete
        """
        return self.execute(cmd, lpl, epl, timeout, _async)

    def execute(self, cmd, lpl=b'', epl=b'', timeout=0, _async=False):
        """
        cmd: int
        epl: bytes
        lpl: bytes
        timeout: timeout to wait CDB complete
        """
        # check param type & length
        if not isinstance(cmd, int) or not 0 <= cmd <= 0xFFFF:
            raise ValueError('Invalid type or value of cmd. Should be a 2-byte unsigned int.')
        for p in lpl, epl:
            if not isinstance(p, bytes):
                raise TypeError('cmd, lpl and epl should be bytes.')
        len_lpl = len(lpl)
        len_epl = len(epl)
        if len_lpl > 120:
            raise ValueError('length of lpl exceed max-length of 120 bytes.')
        if len_epl > 2048:
            raise ValueError('length of epl exceed max-length of 2048 bytes.')
        # 0.check STS_BUSY signal and clear L-CDB block complete flag
        if self.STS_BUSY:
            raise PermissionError('CDB is in STS_BUSY and can not receive new command now. Please try later.')
        s = self.complete_flag  # clear
        s = self.complete_flag  # get flag state
        if s:
            raise ValueError('can not clear L-CDB block%d complete latch' % self.__cdb_idx)
        # 1.write EPL
        if epl:
            # divide into pages of 128 bytes
            r = re.compile(b'.{1, 128}')
            paged_epl = r.findall(epl)
            for i in range(len(paged_epl)):
                self.__cmis.select_bank_page(self.__cdb_bank, 0xA0+i)
                self.__cmis.write_twi_register(128, paged_epl[i])
        # 2.write LPL
        if lpl:
            self.__cmis.select_bank_page(self.__cdb_bank, 0x9F)
            self.__cmis.write_twi_register(bytes([136]), lpl)
        # 3.write payloads length
        self.__cmis.select_bank_page(self.__cdb_bank, 0x9F)
        self.__cmis[130:131] = len_epl
        self.__cmis[132] = len_lpl
        # 4.calc & write cdbCheckCode
        self.__cmis[133] = self.__calc_cdb_check_code(cmd, lpl, epl)
        # 5.write cmd to trigger module to execute the command
        self.__cmis[128:129] = cmd
        # 6.wait for CDB complete and return results if not async
        if not _async:
            self.wait_for_complete(timeout=timeout)
            success = not self.STS_FAIL
            result = self.last_command_result
            return success, result
        
    def wait_for_complete(self, interval=0.1, timeout=0):
        start_time = time.time()
        while True:
            if self.complete_flag:
                break
            elif timeout:
                current_time = time.time()
                time_spend = current_time - start_time
                if time_spend > timeout:
                    raise TimeoutError('Timeout waiting for CDB complete flag: timeout={t}s'.format(t=timeout))
            time.sleep(interval)

    def read_rlpl(self):
        self.__cmis.select_bank_page(self.__cdb_bank, 0x9F)
        rlpl_len = self.__cmis[134]
        rlpl_chkcode = self.__cmis[135]
        if rlpl_len:
            if rlpl_len > 120:
                raise ValueError('Invalid RLPLLen to read RLPL data')
            rlpl = self.__cmis[136:136+rlpl_len-1]
            if self.__calc_rlpl_check_code(rlpl) != rlpl_chkcode:
                raise ValueError('RLPLChkCode verification failed.')
            return rlpl
        else:
            return b''

    def read_epl(self, d_len):
        # TODO: not implemented in module for now
        raise NotImplementedError

class CMIS(ABC):
    def __init__(self, hw_type):
        """
        :Params:
            - **hw_type** - <enum 'HW_TYPE'> CMIS hardware type, OSFP/...
        """
        # information
        self.hw_type = hw_type
        # hardware pin map
        self.hw_pin = HW_SIG_PINS[hw_type]
        self.__generic_sig_map = GENERIC_SIG_MAPS[hw_type]
        self.__page_select_addr = 0x7F
        self.__bank_select_addr = 0x7E
        self.__cdb1 = CDB(self, 1)
        self.__cdb2 = CDB(self, 2)
        self.__cdb1_api = CdbApi(self.__cdb1)
        self.__cdb2_api = CdbApi(self.__cdb2)

    @ property
    def page(self):
        return self[self.__page_select_addr]

    @ page.setter
    def page(self, value):
        if not isinstance(value, int):
            raise TypeError('CMIS page should be an int.')
        self[self.__page_select_addr] = value

    @ property
    def bank(self):
        return self[self.__bank_select_addr]

    @ bank.setter
    def bank(self, value):
        raise PermissionError('bank select should be operated with page select in a single twi transaction. use select_bank_page method instead.')

    @ property
    def cdb1(self):
        return self.__cdb1

    @ property
    def cdb2(self):
        return self.__cdb2

    @ property
    def cdb1_api(self):
        return self.__cdb1_api

    @ property
    def cdb2_api(self):
        return self.__cdb2_api

    def __getitem__(self, position):
        if isinstance(position, int):
            if not 0 <= position <= 0xFF:
                raise IndexError('TWI register address should between 0x00 and 0xFF.')
            reg_addr_bytes = position.to_bytes(1, 'big')
            int_value = int.from_bytes(self.read_twi_register(reg_addr_bytes), 'big')
            return RegisterValue(position, int_value, self)
        if isinstance(position, slice):
            start, stop, step = position.start, position.stop, position.step
            if step is None:
                step = 1
            if step != 1:
                raise ValueError('only sequential register addresses are valid.')
            if not 0 <= start <= stop <= 0xFF:
                raise IndexError('TWI register address should between 0x00 and 0xFF.')
            reg_addr_bytes = start.to_bytes(1, 'big')
            d_len = stop-start+1
            return RegisterSequence(self.read_twi_register(reg_addr_bytes, d_len))
        if isinstance(position, str):
            if position in self.hw_pin:
                state = self.get_pin_state(position)
            elif position in self.__generic_sig_map._fields:
                state = self.get_generic_signal_state(position)
            else:
                raise KeyError('Invalid signal name: %s' % position)
            return state
        if isinstance(position, tuple):
            if len(position) == 2:
                page, sub_position = position
                self.page = page
                return self[sub_position]
            elif len(position) == 3:
                bank, page, sub_position = position
                self.select_bank_page(bank, page)
                return self[sub_position]
            else:
                raise KeyError('invalid key: %r' % position)

        raise TypeError('indices should be int, str, slice or tuple')

    def __setitem__(self, position, value):
        if isinstance(position, int):
            if not 0 <= position <= 0xFF:
                raise IndexError('TWI register address should between 0x00 and 0xFF.')
            if not isinstance(value, int):
                raise TypeError('Register value should be int')
            if not 0 <= value <= 0xFF:
                raise ValueError('TWI register value should between 0x00 and 0xFF.')
            reg_addr_bytes = position.to_bytes(1, 'big')
            data_bytes = value.to_bytes(1, 'big')
            self.write_twi_register(reg_addr_bytes, data_bytes, data_len=1)
        elif isinstance(position, str):
            if not isinstance(value, bool):
                raise TypeError('pin state setting value should be bool')
            if position in self.hw_pin:
                pin_name, writtable = self.hw_pin[position]
                if not writtable:
                    raise PermissionError('Module signal %s is read-only.' % position)
                return self.set_pin_state(position, value)
            elif position in self.__generic_sig_map._fields:
                return self.set_generic_signal_state(position, value)
            else:
                raise KeyError('Invalid signal name: %s' % position)
        elif isinstance(position, slice):
            start, stop, step = position.start, position.stop, position.step
            if step is None:
                step = 1
            if step != 1:
                raise ValueError('only sequential register addresses are valid.')
            if not 0 <= start <= stop <= 0xFF:
                raise IndexError('TWI register address should between 0x00 and 0xFF.')
            start_addr_bytes = start.to_bytes(1, 'big')
            data_len = stop - start + 1
            if isinstance(value, int):
                data_bytes = value.to_bytes(data_len, 'big')
            elif isinstance(value, Iterable):
                data_bytes = bytes(value)
            else:
                raise TypeError('value should be int, bytes, or other Iterable of int that can be converted to bytes.')
            self.write_twi_register(start_addr_bytes, data_bytes, data_len)
        elif isinstance(position, tuple):
            if len(position) == 2:
                page, sub_position = position
                self.page = page
                self[sub_position] = value
            elif len(position) == 3:
                bank, page, sub_position = position
                self.select_bank_page(bank, page)
                self[sub_position] = value
            else:
                raise KeyError('invalid key: %r' % position)

        else:
            raise TypeError('indices should be int or str or slice')

    # BASIC FUNCTIONS (L1)
    # HW signal/CMIS generic signal management, TWI R/W operations
    # Some functions must be override when extended.
    @ abstractmethod
    def set_pin_state(self, pin_name, is_high_level):
        """
        pin_name: str, pin name defined in corresponding HW spec
        is_high_level: bool, True for high pin level and False for low pin level
        """

    @ abstractmethod
    def get_pin_state(self, pin_name):
        """
        pin_name: str, pin name defined in corresponding HW spec
        returns a bool, True for high pin level and False for low pin level
        """

    def set_generic_signal_state(self, sig_name, is_high_level):
        try:
            pin_name, pol = getattr(self.__generic_sig_map, sig_name)
        except KeyError:
            raise KeyError('Invalid signal name: %s' % sig_name)
        return self.set_pin_state(pin_name, not is_high_level^pol)

    def get_generic_signal_state(self, sig_name):
        try:
            pin_name, pol = getattr(self.__generic_sig_map, sig_name)
        except KeyError:
            raise KeyError('Invalid signal name: %s' % sig_name)
        sig_state = not pol^self.get_pin_state(pin_name)
        return sig_state

    @ abstractmethod
    def write_twi_register(self, twi_addr, data, data_len=None):
        """
        random write of twi register.
        twi_addr: a 1-byte bytes. twi register address.
        data: bytes.
        data_len: size of data in bytes. if given, length of param 'data' will be confirmed.
                  otherwise, the length of data is used.
        """

    @ abstractmethod
    def read_twi_register(self, twi_addr, data_len=1):
        """
        random read of twi register
        twi_addr: a 1-byte bytes. twi register address.
        data_len: size of data to read in bytes.
        Returns: bytes
        """

    def select_page(self, page):
        self.page = page

    def select_bank_page(self, bank, page):
        self[self.__bank_select_addr:self.__page_select_addr] = bytes([bank, page])
