import socket
from . import id_maps
from .constants import CLIENT_CONF, ERROR_CODES
import re

class CmisEVB(object):
    
    def __init__(self, host=CLIENT_CONF['host'], port=CLIENT_CONF['port'], timeout=3):
        """
        host: string, hostname or ip address
        port: int
        """
        self.__timeout = timeout
        self.__socket = None
        self.__is_connected = False
        self.__id_maps = id_maps.id_maps
        self.host = host
        self.port = port
    
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """
        When release port when connection ends.
        """
        if self.is_connected:
            self.disconnect()

    # === Layer 1: basic communication layer ===
    @ property
    def host(self):
        return self.__host
    
    @ host.setter
    def host(self, value):
        if self.is_connected:
            raise PermissionError('changing host is not allowed when connected.')
        else:
            if not isinstance(value, str):
                raise TypeError('host should be a string of hostname or ip address.')
            self.__host = value

    @ property
    def port(self):
        return self.__port

    @ port.setter
    def port(self, value):
        if self.is_connected:
            raise PermissionError('changing port is not allowed when connected.')
        else:
            if not isinstance(value, int):
                raise TypeError('port must be int.')
            if not 0 <= value <= 65535:
                raise ValueError('port out of range: %d' % value)
            self.__port = value

    @ property
    def is_connected(self):
        return self.__is_connected

    def connect(self):
        if self.is_connected:
            return
        try:
            self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__socket.settimeout(self.__timeout)
            self.__socket.connect((self.host, self.port))
            prompt = self.__socket.recv(1024).decode('gbk')
            self.__is_connected = True
            print(prompt)
        except Exception:
            raise ConnectionError('Unable to connect DUT. host=%r, port=%r' % (self.host, self.port))

    def disconnect(self):
        if not self.is_connected:
            return
        self.__socket.close()
        self.__socket = None
        self.__is_connected = False

    def command(self, cmd, *params):
        """
        cmd: str, cmd to send to EVB.
        *params: str or int. int will convert to str on base of 10.
        NOTE: because any command should have a reply, you should always use query method
        to clear the reply
        """
        if not self.is_connected:
            raise ConnectionError('OSFP host EVB is not connected.')
        if not isinstance(cmd, str):
            raise TypeError('cmd should be string.')
        prefix = '*'
        tx = '%s%s' % (prefix, cmd)
        for i in params:
            if not isinstance(i, (int, str)):
                raise TypeError('params should be int or str.')
            else:
                tx += ' %s' % i
        self.__socket.send(tx.encode())

    def read_reply(self):
        """
        return: list of str, replied values from EVB
        """
        rx = self.__socket.recv(1024).decode('gbk')

        m = re.match(r'\$(\w{4});(<[\w*\- ]*>){0,1}(.*)', rx)
        if not m:
            raise ValueError('Unexpected reply from host board. Reply: %s' % rx)
        err_code = int(m.group(1))
        if err_code != 0:
            err_msg = ERROR_CODES.get(err_code, 'Unknown')
            raise ValueError('EVB Command Error: [0x%04X] %s' % (err_code, err_msg))
        reply_str = m.group(3)
        reply = reply_str.split(',')
        return reply

    def query(self, cmd, *params):
        """
        return: list of str, replied values from EVB
        """
        params = [str(param) for param in params if isinstance(param, (float, int))]
        self.command(cmd, *params)
        return self.read_reply()

    # === Layer 2: management data transfer layer ===

    # NOTE that these 'ain' 'din' below describes voltages on host
    # board, not in module. 

    def get_ain(self, pin_name):
        """
        read analog input into MCU.
        pin_name: str
        return: adc_val(int), real_val(float)
        """
        pin_id = self.__id_maps['ain'][pin_name]
        cmd = 'ain'
        reply = self.query(cmd, pin_id)
        d_val = int(reply[0])
        a_val = float(reply[1])
        return d_val, a_val

    def get_aout(self, pin_name):
        """
        read analog output setting value from MCU.
        pin_name: str
        return: float, real_value
        """
        pin_id = self.__id_maps['aout'][pin_name]
        cmd = 'aout'
        reply = self.query(cmd, pin_id)
        set_val = float(reply[0])
        mon_val = float(reply[1])
        return set_val, mon_val

    def set_aout(self, pin_name, value):
        """
        set analog output value from MCU.
        pin_name: str
        value: float, int
        """
        if not isinstance(value, (float, int)):
            raise TypeError('aout setting value should be type int or float')
        pin_id = self.__id_maps['aout'][pin_name]
        cmd = 'aout'
        ndigits = 4
        value = round(value, ndigits)
        self.query(cmd, pin_id, value)

    def get_din(self, pin_name):
        """
        get digital input value into MCU.
        pin_name: str
        return: bool
        """
        pin_id = self.__id_maps['din'][pin_name]
        cmd = 'din'
        reply = self.query(cmd, pin_id)
        val = bool(int(reply[0]))
        return val

    def get_dout(self, pin_name):
        """
        get digital output setting value from MCU.
        pin_name: str
        return: bool
        """
        pin_id = self.__id_maps['dout'][pin_name]
        cmd = 'dout'
        reply = self.query(cmd, pin_id)
        val = bool(int(reply[0]))
        return val

    def set_dout(self, pin_name, value):
        """
        set digital output value from MCU.
        pin_name: str
        value: bool
        """
        if not isinstance(value, bool):
            raise TypeError('dout setting value should be type bool')
        pin_id = self.__id_maps['dout'][pin_name]
        cmd = 'dout'
        self.query(cmd, pin_id, int(value))

    def twi_read(self, reg_addr=None, data_len=1):
        """
        reg_addr: bytes, register address
        data_len: int, number of bytes to read
        return: bytes, register(s) data value
        NOTE: 
            - if reg_addr is not specified, read current address.
        """
        if not isinstance(data_len, int):
            raise TypeError('data_len should be type int.')
        if not 1 <= data_len <= 256:
            raise ValueError('data_len should between 1 and 256.')

        if reg_addr:
            # random read
            if not isinstance(reg_addr, bytes):
                raise TypeError('reg_addr should be type bytes.')
            reg_addr_int = int.from_bytes(reg_addr, 'big')
            if not 0 <= reg_addr_int <= 255:
                raise ValueError('reg_addr should between 0 and 255.')
            reply = self.query('twi', data_len, reg_addr_int)
        else:
            # read current address
            reply = self.query('twi', data_len)

        return b''.join([int(i).to_bytes(1, 'big') for i in reply])

    def twi_write(self, reg_addr, data, data_len=None):
        """
        reg_addr: bytes, register address
        data: bytes, register(s) data value
        NOTE:
            - if length of data > 1, it will be write to multiple registers.
            - data_len is the supposed register length. it is not required.
              if given, len(data) will be checked if it equals to data_len.
        """
        
        if not isinstance(reg_addr, bytes):
            raise TypeError('reg_addr should be type bytes.')
        if not isinstance(data, bytes):
            raise TypeError('data should be type bytes.')
        reg_addr_int = int.from_bytes(reg_addr, 'big')
        if not 0 <= reg_addr_int <= 255:
            raise ValueError('reg_addr should between 0 and 255.')

        # data_len = len(data)
        if data_len:
            if data_len != len(data):
                raise ValueError('length of data does not match data_len')
        else:
            data_len = len(data)
        self.query('twi', data_len, reg_addr_int, *data)

    # === Layer 3: application layer ===
    def get_vcc_monitor(self):
        return self.get_ain('P3V3_OSFP_CON')[1]

    def get_vcc_setting(self):
        return self.get_aout('P3V3_OSFP')[1]

    def set_vcc(self, value):
        if not isinstance(value, (int, float)):
            raise TypeError('Vcc value should be int or float.')
        if value >= 4:
            raise ValueError('Vcc should less than 4 for security.')
        self.set_aout('P3V3_OSFP', value)

    def get_icc_monitor(self):
        return self.get_ain('P3V3_OSFP_CURR_CHECK')[1]
