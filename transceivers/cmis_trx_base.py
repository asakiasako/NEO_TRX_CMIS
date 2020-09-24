from ..evb import CmisEVB
from ..cmis import CMIS
from .components.canopus_api import CanopusApi
from .components.canopus_com import CanopusCom
from .components.vdm import Vdm
from .components.ddm import Ddm
from .components.flag import Flag
import time
import math

class CMISTrxBase(CMIS):
    def __init__(self, ip, trx_type):
        if not isinstance(ip, str):
            raise TypeError('ip should be a str in ip address format')
        CMIS.__init__(self, trx_type)
        self.__ip = ip
        self.__evb = CmisEVB(host=ip, timeout=5)
        self.__dsp = CanopusApi(CanopusCom(self))
        self.__vdm = Vdm(self)
        self.__ddm = Ddm(self)
        self.__flag = Flag(self)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def __repr__(self):
        return '<{classname} ip={ip}>'.format(classname=self.__class__.__name__, ip=self.__ip)

    @property
    def evb(self):
        return self.__evb

    @property
    def dsp(self):
        return self.__dsp
    
    @property
    def vdm(self):
        return self.__vdm

    @property
    def ddm(self):
        return self.__ddm

    @property
    def flag(self):
        return self.__flag

    def connect(self):
        self.__evb.connect()

    def disconnect(self):
        self.__evb.disconnect()

    def set_pin_state(self, pin_name, is_high_level):
        raise NotImplementedError

    def get_pin_state(self, pin_name):
        raise NotImplementedError

    def write_twi_register(self, twi_addr, data, data_len=None):
        return self.__evb.twi_write(twi_addr, data, data_len)

    def read_twi_register(self, twi_addr, data_len=1):
        return self.__evb.twi_read(twi_addr, data_len)

    def get_vcc_setting(self):
        """
        return: <float> Vcc setting value
        """
        return self.__evb.get_vcc_setting()

    def get_vcc_monitor(self):
        """
        return: <float> Vcc monitor value
        """
        return self.__evb.get_vcc_monitor()

    def set_vcc(self, value):
        """
        value: <int|float> Vcc setting value
        """
        self.__evb.set_vcc(value)

    def get_icc_monitor(self):
        """
        return: <float> Icc monitor
        """
        return self.__evb.get_icc_monitor()

    def get_power_consumption(self):
        """
        return: <float> power consumption
        """
        return self.get_vcc_monitor() * self.get_icc_monitor()

    # --- Applications ---
    def get_pn(self):
        return self[0, 0x00, 148:163].decode().strip()

    def get_sn(self):
        return self[0, 0x00, 166:181].decode().strip()

    def write_password(self, psw=0x00001011):
        '''
        Write password to Password Entry Area.
        If psw is not explicitly defined, default host system manufacturer 
        password 0x00001011 is write.
        '''
        self[122:125] = psw

    def write_cdb_password(self):
        self.write_password(0xA55A5AA5)

    def change_password(self, psw):
        '''
        Change the host system manufacturer password.
        Valid password in the range of 00000000h to 7FFFFFFFh.
        '''
        if not isinstance(psw, int) or not 0 <= psw <= 0x7FFFFFFF:
            raise TypeError('Param psw should be an int in the range of 00000000h to 7FFFFFFFh.')
        self[118:121] = psw

    def get_module_state(self):
        # 0.00h.3.3-1
        state_code = self[3][3:1]
        state_code_map = {
            0b001: 'ModuleLowPwr',
            0b010: 'ModulePwrUp',
            0b011: 'ModuleReady',
            0b100: 'ModulePwrDn',
            0b101: 'Fault',
        }
        return state_code_map.get(state_code, 'Undefined: 0b{:03b}'.format(state_code))
    
    def get_data_path_state(self, n_lane):
        # each bank contains 8 host lanes
        bank = math.ceil(n_lane/8)-1
        page = 0x11
        idx_in_bank = 1 + (n_lane-1) % 8
        addr = math.ceil(idx_in_bank/2)+128-1
        bits_section = slice(3, 0) if idx_in_bank % 2 else slice(7, 4)
        state_code = self[bank, page, addr][bits_section]
        state_code_map = {
            0x1: 'DataPathDeactivated',
            0x2: 'DataPathInit',
            0x3: 'DataPathDeinit',
            0x4: 'DataPathActivated',
            0x5: 'DataPathTxTurnOn',
            0x6: 'DataPathTxTurnOff',
            0x7: 'DataPathInitialized',
        }
        return state_code_map.get(state_code, 'Undefined: %Xh' % state_code)

    def get_frequency_channel(self, lane):
        """
        * lane: <int> lane
        return:
            * ch_num: <int> channel number
        """
        return self[0, 0x12, 136+(lane-1)*2:136+(lane-1)*2+1].to_signed()

    def set_frequency_channel(self, lane, ch_num):
        """
        * lane: <int> lane
        * ch_num: <int> channel number
        """
        self[0, 0x12, 136+(lane-1)*2:136+(lane-1)*2+1] = ch_num if ch_num >=0 else ch_num+0x10000

    def get_current_frequency(self, lane):
        """
        * lane: <int> lane
        return:
            * <float> frequency in THz
        """
        ms_bytes = (168+4*(lane-1), 169+4*(lane-1))  # THz
        ls_bytes = (170+4*(lane-1), 171+4*(lane-1))  # 0.05GHz
        self.select_bank_page(bank=0, page=0x12)
        return self[slice(*ms_bytes)].to_unsigned() + self[slice(*ls_bytes)].to_unsigned()*0.05*10**(-3)
