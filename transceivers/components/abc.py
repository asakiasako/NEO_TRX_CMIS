import ctypes

class AutoBiasControl:

    def __init__(self, trx):
        self.__trx = trx
        self.__PHASE_MAPPING = {
            'XP': 0,
            'XI': 1,
            'XQ': 2,
            'YP': 3,
            'YI': 4,
            'YQ': 5
        }

    def calc_cdb_chkcode(self, vals):
        chkcode = ctypes.c_ubyte(0)
        for b in vals:
            chkcode.value += b
        chkcode.value = - chkcode.value - 1
        return chkcode.value

    def polarity_set(self, ph, val):
        if not ph in self.__PHASE_MAPPING:
            raise KeyError('Invalid phase for ABC: {!r}'.format(ph))
        if not isinstance(val, bool):
            raise TypeError('Polarity value should be bool')

        ph = self.__PHASE_MAPPING[ph]

        while self.__trx.cdb1.STS_BUSY:
            pass

        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x09\x00\x00\x00\x0f\x08\x0b\x00\x04\x00\x00\x00\x00')
        cmd[-4] = (ph >> 8) & 0xff
        cmd[-3] = ph & 0xff
        cmd[-2] = (val >> 8) & 0xff
        cmd[-1] = val & 0xff
        cmd[133-128] = self.calc_cdb_chkcode(cmd)
        data = cmd[2:]
        self.__trx[130: 130+len(data)-1] = data
        self.__trx[128:129] = cmd[:2]
        while self.__trx.cdb1.STS_BUSY or self.__trx[37] == 0:
            pass

    def polarity_get(self, ph):
        if not ph in self.__PHASE_MAPPING:
            raise KeyError('Invalid phase for ABC: {!r}'.format(ph))

        ph = self.__PHASE_MAPPING[ph]

        while self.__trx.cdb1.STS_BUSY:
            pass

        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x07\x00\x00\x00\x0f\x08\x0b\x00\x04\x00\x00')
        cmd[-2] = (ph >> 8) & 0xff
        cmd[-1] = ph & 0xff    
        cmd[133-128] = self.calc_cdb_chkcode(cmd)
        data = cmd[2:]
        self.__trx[130: 130+len(data)-1] = data
        self.__trx[128:129] = cmd[:2]
        while self.__trx.cdb1.STS_BUSY or self.__trx[37] == 0:
            pass

        if not self.__trx.cdb1.STS_BUSY and not self.__trx.cdb1.STS_FAIL:
            rlplen = self.__trx[134]
            rlp_chkcode = self.__trx[135]
            rlp = self.__trx[136:136+rlplen-1]
            if self.calc_cdb_chkcode(rlp) == rlp_chkcode:
                polarity = bool((rlp[0] << 8) | rlp[1])
        else:
            raise ValueError('CDB Command Fail')

        return polarity