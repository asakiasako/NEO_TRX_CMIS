import struct
import time
import ctypes

class Adc:
    KEYS = [
        "TX_DRIVER_PI_XI",
        "TX_DRIVER_PI_XQ",
        "TX_DRIVER_PI_YI",
        "TX_DRIVER_PI_YQ",
        "COSA_TEMP_OUT",
        "TX_DRV_VOCM",
        "RX_TIA_PI_XI",
        "VOFE_CURRENT_SEN",
        "MCU1_RX_TIA_PI_YI",
        "TX_VOA_X",
        "TX_VOA_Y",
        "REF2V5_MCU_ABC",
        "TX_VOA_X_I",
        "TX_VOA_Y_I",
        "MCU1INTERNAL_TEMP_SNS",
        "MCU1INTERNAL_AVDD",
        "MCU1INTERNAL_IOVDD0",
        "MCU1INTERNAL_IOVDD1",

        "P0V55_DSP_VDDC",
        "P0V75_DSP_VDDM",
        "P0V94_DSP_VDDA",
        "P1V8_DSP_VDDA18",
        "P1V2_DSP_VDDA12",
        "P3V_ABC_TXMPD",
        "PCB_TEMP_ADC",
        "DSP_TEMP",

        "POST_MPDX_DC_MCU2ADC",
        "POST_MPDY_DC_MCU2ADC",
        "POST_MPDXY_AC_MCU2ADC",
        "RX_VOA_X",
        "TIA_PD_BIAS",
        "TIA_VCC",
        "RX_VOA_Y",
        "RX_MPD_X_MCU2",
        "RX_TIA_PI_XQ",
        "RX_TIA_PI_YI",
        "RX_TIA_PI_YQ",
        "RX_VOA_X_I",
        "RX_MPD_Y_MCU2",
        "RX_VOA_Y_I",
        "MCU2INTERNAL_TEMP_SNS",
        "MCU2INTERNAL_AVDD",
        "MCU2INTERNAL_IOVDD0",
        "MCU2INTERNAL_IOVDD1",

        "ADC_TIA_VGC_YQ",
        "ADC_TIA_VGC_YI",
        "ADC_TIA_VGC_XQ",
        "ADC_TIA_VGC_XI",
        "TX_DRV_VCC",
        "P5V8_DRIVER_VOFE",
        "P6V_VOA",
        "COSA_PH_BIAS",
    ]

    def __init__(self, trx):
        self.__trx = trx

    def calc_cdb_chkcode(self, vals):
        chkcode = ctypes.c_ubyte(0)
        for b in vals:
            chkcode.value += b
        chkcode.value = - chkcode.value - 1
        return chkcode.value

    def get(self, key, mode='a'):
        if key not in self.KEYS:
            raise KeyError('Invalid key for ADC: {key}'.format(key=key))
        _id = self.KEYS.index(key)
        while self.__trx.cdb1.STS_BUSY:
            pass
        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x03\x00\x00\x00\x0f\x04\x00')
        cmd[-1] = _id
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
            rlp = self.__trx[136, 136+rlplen-1]
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
            raise ValueError('Invalid mode to get ADC: {mode}'.format(mode=mode))
