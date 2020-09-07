from ..evb import CmisEVB
import time

class CMISTrxBase():
    def __init__(self, ip):
        if not isinstance(ip, str):
            raise TypeError('ip should be a str in ip address format')
        self.__ip = ip
        self.__evb = CmisEVB(host=ip, timeout=5)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def __repr__(self):
        return '<{classname} ip={ip}>'.format(classname=self.__class__.__name__, ip=self.__ip)

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

    def get_sn(self):
        return self[0, 0x00, 166:181].decode().strip()

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

    def write_cdb_password(self, psw=b'\xa5\x5a\x5a\xa5'):
        self[122:125] = psw