import ctypes

class DPin:

    def __init__(self, trx):
        self.__trx = trx

    KEYS = [
        "MCU1_DSP_SPI_CS",
        "MCU1_FLASH_SPI_CS",
        "MCU1_ADC3_SPI_CS",
        "ADC4_SPI_CS",
        "DSP_LINE_LOS",
        "DSP_INTN_0",
        "CLK_SEC",
        "DSP_INTN_1",
        "M_LPWN",
        "M_INT",
        "MCU2_MCU1_INTN_I",
        "MCU1_FLASH_RSTN",
        "MCU1_OUT_RST_N",
        "MCU1_DSP_RSTN",
        "P0V55_DSP_EN",
        "P1V8_DSP_EN",
        "P1V2_DSP_EN",
        "PS_EN",
        "COSA_VOFE_EN",
        "TX_DRIVER_VCC_EN",
        "P0V94_DSP_EN",
        "P0V75_DSP_EN",
        
        "MCU2_MCU1_INTN_O",
        "M_LPWN_ABC",
        "MCU2_ADC12_SPI_CS1",
        "MCU2_ADC12_SPI_CS2",
        "RX_TIA_BWH",
        "RX_TIA_BWL",
        "RX_TIA_SD",
        "RX_TIA_MC",
        "ITLA_OIF_MS_N",
        "ITLA_OIF_SRQ_N",
        "ITLA_OIF_DIS_N",
        "ITLA_OIF_RST_N",
        "RX_TIA_VCC_XY_EN",
        "COSA_VPD_EN",
        "P6V_EN",
        "COSA_PH_BIAS_EN",
    ]

    def __getitem__(self, key):
        return self.get(key)

    def __setitem__(self, key, val):
        return self.set(key, val)

    def __get_id_by_key(self, key):
        return self.KEYS.index(key)

    def calc_cdb_chkcode(self, vals):
        chkcode = ctypes.c_ubyte(0)
        for b in vals:
            chkcode.value += b
        chkcode.value = - chkcode.value - 1
        return chkcode.value

    def get(self, key):
        if key not in self.KEYS:
            raise KeyError('Invalid key for Dpin: {key}'.format(key=key))
        _id = self.__get_id_by_key(key)
        while self.__trx.cdb1.STS_BUSY:
            pass
        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x03\x00\x00\x00\x0f\x02\x00')
        cmd[-1] = _id
        cmd[133-128] = self.calc_cdb_chkcode(cmd)
        data = cmd[2:]
        self.__trx[130: 130+len(data)-1] = data
        self.__trx[128:129] = cmd[:2]
        while self.__trx.cdb1.STS_BUSY or self.__trx[37] == 0:
            pass
        if (not self.__trx.cdb1.STS_BUSY) and (not self.__trx.cdb1.STS_FAIL):
            rlplen = self.__trx[134]
            rlp_chkcode = self.__trx[135]
            rlp = self.__trx[136:136+rlplen-1]
            if self.calc_cdb_chkcode(rlp) == rlp_chkcode:
                state = bool(rlp[0])
            else:
                raise ValueError('CDB Checkcode failed for RLP')
        else:
            raise ValueError('CDB Command not success.')
        return state

    def set(self, key, state: bool):
        if key not in self.KEYS:
            raise KeyError('Invalid key for ADC: {key}'.format(key=key))
        _id = self.__get_id_by_key(key)
        state = bool(state)
        while self.__trx.cdb1.STS_BUSY:
            pass
        self.__trx.select_bank_page(0, 0x9F)
        cmd = bytearray(b'\x80\x00\x00\x00\x04\x00\x00\x00\x0f\x03\x00\x00')
        cmd[-2] = _id
        cmd[-1] = state
        cmd[133-128] = self.calc_cdb_chkcode(cmd)
        data = cmd[2:]
        self.__trx[130: 130+len(data)-1] = data
        self.__trx[128:129] = cmd[:2]
        while self.__trx.cdb1.STS_BUSY or self.__trx[37] == 0:
            pass

    