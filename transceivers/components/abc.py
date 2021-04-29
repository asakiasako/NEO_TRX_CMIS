import ctypes
import struct

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

    def is_enabled(self):
        return bool(self.service_get())

    def enable(self, state=True):
        if state:
            self.service_set(0x3F)
        else:
            self.service_set(0)

    def disable(self):
        return self.enable(state=False)

    def calc_cdb_chkcode(self, vals):
        chkcode = ctypes.c_ubyte(0)
        for b in vals:
            chkcode.value += b
        chkcode.value = - chkcode.value - 1
        return chkcode.value

    def verify_cdb_chkcode(self, vals, expected):
        chkcode = self.calc_cdb_chkcode(vals)
        if chkcode != expected:
            raise ValueError('Check code verify failed.')

    def service_get(self):
        while self.__trx.cdb1.STS_BUSY:
            pass

        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x03\x00\x00\x00\x0f\x08\x06')
        cmd[133-128] = self.calc_cdb_chkcode(cmd)
        data = cmd[2:]
        self.__trx[130: 130+len(data)-1] = data
        self.__trx[128: 129] = cmd[:2]

        while self.__trx.cdb1.STS_BUSY or self.__trx[37] == 0:
            pass

        if not self.__trx.cdb1.STS_BUSY and not self.__trx.cdb1.STS_FAIL:

            rlplen = self.__trx[134]
            rlp_chkcode = self.__trx[135]
            rlp = self.__trx[136:136+rlplen-1]
            if self.calc_cdb_chkcode(rlp) == rlp_chkcode:
                return (rlp[0] << 8) | rlp[1]

    def service_set(self, val):
        while self.__trx.cdb1.STS_BUSY:
            pass
        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x05\x00\x00\x00\x0f\x08\x05\x00\x00')
        cmd[-2] = (val >> 8) & 0xff
        cmd[-1] = val & 0xff
        cmd[133-128] = self.calc_cdb_chkcode(cmd)
        data = cmd[2:]
        self.__trx[130: 130+len(data)-1] = data
        self.__trx[128: 129] = cmd[:2]
        while self.__trx.cdb1.STS_BUSY or self.__trx[37] == 0:
            pass



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
            self.verify_cdb_chkcode(rlp, rlp_chkcode)
            polarity = bool((rlp[0] << 8) | rlp[1])
        else:
            raise ValueError('CDB Command Fail')

        return polarity

    def pid_set(self, phase, p, i, d, i_min, i_max):
        """
        phase: <str>, 'XP'|'XI'|'XQ'|'YP'|'YI'|'YQ'
        """
        if not phase in self.__PHASE_MAPPING:
            raise KeyError('Invalid phase for ABC: {!r}'.format(phase))

        idx_ph = self.__PHASE_MAPPING[phase]

        while self.__trx.cdb1.STS_BUSY:
            pass

        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x19\x00\x00\x00\x0f\x08\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        cmd[-22] = (idx_ph >> 8) & 0xff
        cmd[-21] = idx_ph & 0xff

        vs = struct.pack('<1f', p)
        cmd[-20] = vs[0]
        cmd[-19] = vs[1]
        cmd[-18] = vs[2]
        cmd[-17] = vs[3]

        vs = struct.pack('<1f', i)
        cmd[-16] = vs[0]
        cmd[-15] = vs[1]
        cmd[-14] = vs[2]
        cmd[-13] = vs[3]

        vs = struct.pack('<1f', d)
        cmd[-12] = vs[0]
        cmd[-11] = vs[1]
        cmd[-10] = vs[2]
        cmd[-9] = vs[3]

        vs = struct.pack('<1f', i_min)
        cmd[-8] = vs[0]
        cmd[-7] = vs[1]
        cmd[-6] = vs[2]
        cmd[-5] = vs[3]

        vs = struct.pack('<1f', i_max)
        cmd[-4] = vs[0]
        cmd[-3] = vs[1]
        cmd[-2] = vs[2]
        cmd[-1] = vs[3]

        cmd[133-128] = self.calc_cdb_chkcode(cmd)
        data = cmd[2:]
        self.__trx[130: 130+len(data)-1] = data
        self.__trx[128:129] = cmd[:2]
        while self.__trx.cdb1.STS_BUSY or self.__trx[37] == 0:
            pass

    def pid_get(self, phase):
        """
        phase: <str>, 'XP'|'XI'|'XQ'|'YP'|'YI'|'YQ'
        return: <floats> p, i, d, i_min, i_max
        """
        
        if not phase in self.__PHASE_MAPPING:
            raise KeyError('Invalid phase for ABC: {!r}'.format(phase))

        idx_ph = self.__PHASE_MAPPING[phase]

        while self.__trx.cdb1.STS_BUSY:
            pass

        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x05\x00\x00\x00\x0f\x08\x04\x00\x00')
        cmd[-2] = (idx_ph >> 8) & 0xff
        cmd[-1] = idx_ph & 0xff

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
            self.verify_cdb_chkcode(rlp, rlp_chkcode)
            p = struct.unpack('<1f', rlp[0:4])[0]
            i = struct.unpack('<1f', rlp[4:8])[0]
            d = struct.unpack('<1f', rlp[8:12])[0]
            i_min = struct.unpack('<1f', rlp[12:16])[0]
            i_max = struct.unpack('<1f', rlp[16:20])[0]
        else:
            raise ValueError('CDB Command Fail')

        return p, i, d, i_min, i_max

    def target_get(self, phase):
        """
        phase: <str> 'XP'|'XI'|'XQ'|'YP'|'YI'|'YQ'
        return: <float> ABC target
        """
        
        if not phase in self.__PHASE_MAPPING:
            raise KeyError('Invalid phase for ABC: {!r}'.format(phase))

        idx_ph = self.__PHASE_MAPPING[phase]

        while self.__trx.cdb1.STS_BUSY:
            pass

        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x07\x00\x00\x00\x0f\x08\x0b\x00\x0d\x00\x00')
        cmd[-2] = (idx_ph >> 8) & 0xff
        cmd[-1] = idx_ph & 0xff

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
            self.verify_cdb_chkcode(rlp, rlp_chkcode)
            b = bytearray()
            b.append(rlp[1])
            b.append(rlp[0])
            b.append(rlp[3])
            b.append(rlp[2])
            target = struct.unpack('<f', b)[0]
        else:
            raise ValueError('CDB Command Fail')

        return target

    def target_set(self, phase, target):
        """
        phase: <str> 'XP'|'XI'|'XQ'|'YP'|'YI'|'YQ'
        target: <Real> ABC target
        """
        if not phase in self.__PHASE_MAPPING:
            raise KeyError('Invalid phase for ABC: {!r}'.format(phase))

        idx_ph = self.__PHASE_MAPPING[phase]

        while self.__trx.cdb1.STS_BUSY:
            pass

        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x0b\x00\x00\x00\x0f\x08\x0b\x00\x0d\x00\x00\x00\x00\x00\x00')
        cmd[-6] = (idx_ph >> 8) & 0xff
        cmd[-5] = idx_ph & 0xff

        vs = struct.pack('<1f', target)
        cmd[-4] = vs[1]
        cmd[-3] = vs[0]   
        cmd[-2] = vs[3]
        cmd[-1] = vs[2]   

        cmd[133-128] = self.calc_cdb_chkcode(cmd)
        data = cmd[2:]
        self.__trx[130: 130+len(data)-1] = data
        self.__trx[128:129] = cmd[:2]
        while self.__trx.cdb1.STS_BUSY or self.__trx[37] == 0:
            pass

    def current_demod_get(self, phase):
        """
        phase: <str> 'XP'|'XI'|'XQ'|'YP'|'YI'|'YQ'
        return: <float> ABC current demod value
        """
        
        if not phase in self.__PHASE_MAPPING:
            raise KeyError('Invalid phase for ABC: {!r}'.format(phase))

        idx_ph = self.__PHASE_MAPPING[phase]

        while self.__trx.cdb1.STS_BUSY:
            pass

        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x07\x00\x00\x00\x0f\x08\x0b\x00\x0b\x00\x00')
        cmd[-2] = (idx_ph >> 8) & 0xff
        cmd[-1] = idx_ph & 0xff

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
            self.verify_cdb_chkcode(rlp, rlp_chkcode)
            b = bytearray()
            b.append(rlp[1])
            b.append(rlp[0])
            b.append(rlp[3])
            b.append(rlp[2])
            demod = struct.unpack('<1f', b)[0] 
        else:
            raise ValueError('CDB Command Fail')

        return demod

    def method_get(self, phase):
        
        if not phase in self.__PHASE_MAPPING:
            raise KeyError('Invalid phase for ABC: {!r}'.format(phase))

        idx_ph = self.__PHASE_MAPPING[phase]

        while self.__trx.cdb1.STS_BUSY:
            pass

        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x05\x00\x00\x00\x0f\x08\x08\x00\x00')
        cmd[-2] = (idx_ph >> 8) & 0xff
        cmd[-1] = idx_ph & 0xff

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
            self.verify_cdb_chkcode(rlp, rlp_chkcode)
            method = (rlp[0] << 8) | rlp[1]
        else:
            raise ValueError('CDB Command Fail')

        return method
        

    def method_set(self, phase, val):

        if not phase in self.__PHASE_MAPPING:
            raise KeyError('Invalid phase for ABC: {!r}'.format(phase))

        idx_ph = self.__PHASE_MAPPING[phase]

        while self.__trx.cdb1.STS_BUSY:
            pass

        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x07\x00\x00\x00\x0f\x08\x07\x00\x00\x00\x00')
        cmd[-4] = (idx_ph >> 8) & 0xff
        cmd[-3] = idx_ph & 0xff        
        cmd[-2] = (val >> 8) & 0xff
        cmd[-1] = val & 0xff

        cmd[133-128] = self.calc_cdb_chkcode(cmd)
        data = cmd[2:]
        self.__trx[130: 130+len(data)-1] = data
        self.__trx[128:129] = cmd[:2]
        while self.__trx.cdb1.STS_BUSY or self.__trx[37] == 0:
            pass
