import struct
import time
import ctypes

class Dac:
    KEYS = [
        'DRIVER_VGC_XI',
        'DRIVER_VGC_YI',
        'DRIVER_VGC_XQ',
        'DRIVER_VGC_YQ',
        'MCU1_TX_VOA_X',
        'MCU1_TX_VOA_Y',
        'DRIVER_VT',
        'MCU1_DAC_TX_PN_BIAS',
        'COSA_VOFE_FB',
        'P0V55_DSP_FB',

        'MCU2_TXIH1_AC',
        'MCU2_TXIH1_DC',
        'MCU2_TXQH1_DC',
        'MCU2_TYIH1_DC',
        'MCU2_TYQH1_DC',
        'MCU2_TXQH1_AC',
        'MCU2_TYIH1_AC',
        'MCU2_TYQH1_AC',
        'MCU2_TXPH1_DC',
        'MCU2_TYPH1_DC',
        'MCU2_TXPH1_AC',
        'MCU2_TYPH1_AC',

        'DAC_TIA_VOA_YI',
        'DAC_TIA_VOA_XI',
        'DAC_TIA_VOA_YQ',
        'DAC_TIA_VOA_XQ',

        'DAC_RX_VOA_X',
        'DAC_RX_VOA_Y',

        'DAC_RX_IQ_PH_X',
        'DAC_RX_IQ_PH_Y',

        'ABC_VGA_R',
    ]

    def __init__(self, trx):
        self.__trx = trx

    def calc_cdb_chkcode(self, vals):
        chkcode = ctypes.c_ubyte(0)
        for b in vals:
            chkcode.value += b
        chkcode.value = - chkcode.value - 1
        return chkcode.value

    def __getitem__(self, slice):
        if isinstance(slice, str):
            key = slice
            mode = 'a'
        elif isinstance(slice, (tuple, list)):
            key = slice[0]
            mode = slice[1]
        else:
            raise TypeError
        return self.get(key, mode)

    def __setitem__(self, slice, v):
        if isinstance(slice, str):
            key = slice
            mode = 'a'
        elif isinstance(slice, (tuple, list)):
            key = slice[0]
            mode = slice[1]
        else:
            raise TypeError
        return self.set(key, v, mode)

    def get(self, key, mode='a'):
        if key not in self.KEYS:
            raise KeyError('Invalid key for DAC: {key}'.format(key=key))
        _id = self.KEYS.index(key)
        while self.__trx.cdb1.STS_BUSY:
            pass
        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x04\x00\x00\x00\x0f\x05\x00\x01')
        cmd[-2] = _id
        cmd[133-128] = self.calc_cdb_chkcode(cmd)
        data = cmd[2:]
        self.__trx[130: 130+len(data)-1] = data
        self.__trx[128:129] = cmd[:2]
        time.sleep(0.5)
        while self.__trx.cdb1.STS_BUSY or self.__trx[37] == 0:
            pass

        if (not self.__trx.cdb1.STS_BUSY) and (not self.__trx.cdb1.STS_FAIL):
            rlplen = self.__trx[134]
            rlp_chkcode = self.__trx[135]
            rlp = self.__trx[136:136+rlplen-1]
            if self.calc_cdb_chkcode(rlp) == rlp_chkcode:
                _dval = struct.unpack('>1H', rlp[0:2])[0]       
                _aval = struct.unpack('<1f', rlp[2:6])[0]
                _raw_aval = struct.unpack('<1f', rlp[6:])[0]
            else:
                raise ValueError('CDB Checkcode failed for RLP')
        else:
            raise ValueError('CDB Command not success.')
        
        if mode == 'a':
            return _aval
        elif mode == 'd':
            return _dval
        elif mode == 'r':
            return _raw_aval
        else:
            raise ValueError('Invalid mode to get DAC: {mode}'.format(mode=mode))

    def set(self, key, v, mode='a'):
        if key not in self.KEYS:
            raise KeyError('Invalid key for DAC: {key}'.format(key=key))
        _id = self.KEYS.index(key)
        while self.__trx.cdb1.STS_BUSY:
            pass
        self.__trx.select_bank_page(0, 0x9F)
        if mode == 'a':
            cmd = bytearray(b'\x80\x00\x00\x00\x08\x00\x00\x00\x0f\x05\x00\x03\x00\x00\x00\x00')
            cmd[-6] = _id
            # print(v)
            vs = struct.pack('<1f', v)
            # print(vs)
            cmd[-4] = vs[0]
            cmd[-3] = vs[1]
            cmd[-2] = vs[2]
            cmd[-1] = vs[3]
            cmd[133-128] = self.calc_cdb_chkcode(cmd)
        elif mode == 'd':
            cmd = bytearray(b'\x80\x00\x00\x00\x06\x00\x00\x00\x0f\x05\x00\x02\x00\x00')
            cmd[-4] = _id
            cmd[-2] = v >> 8
            cmd[-1] = v & 0xff
            cmd[133-128] = self.calc_cdb_chkcode(cmd)
        else:
            raise ValueError('Invalid mode to set DAC: {mode}'.format(mode=mode))

        data = cmd[2:]
        self.__trx[130: 130+len(data)-1] = data
        self.__trx[128:129] = cmd[:2]
        time.sleep(0.5)
        while self.__trx.cdb1.STS_BUSY or self.__trx[37] == 0:
            pass
