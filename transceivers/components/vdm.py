import time
from types import MappingProxyType
from collections import namedtuple
import math

VdmInfo = namedtuple('VdmInfo', 'index data_type dimension')

class Vdm:
    """
    call Vdm.init_vdm_mapping() once before any vdm operation
    # VDM Config pages: 20h, 21h, 22h, 23h
    # VDM Real Value pages: 24h, 25h, 26h, 27h
    """
    DATA_TYPE_U16 = 1
    DATA_TYPE_S16 = 2
    DATA_TYPE_F16 = 3

    CONFIG_CODE_MAPPING = MappingProxyType({
        # config_code: [data_type, key, dimension]
        9:   [DATA_TYPE_F16, "Media Pre-FEC Minimum", 1],
        11:  [DATA_TYPE_F16, "Media Pre-FEC Maximum", 1],
        13:  [DATA_TYPE_F16, "Media Pre-FEC Average", 1],
        15:  [DATA_TYPE_F16, "Media Pre-FEC Current", 1],
        17:  [DATA_TYPE_F16, "Media Post-FEC Minimum", 1],
        19:  [DATA_TYPE_F16, "Media Post-FEC Maximum", 1],
        21:  [DATA_TYPE_F16, "Media Post-FEC Average", 1],
        23:  [DATA_TYPE_F16, "Media Post-FEC Current", 1],

        10:  [DATA_TYPE_F16, "Host Pre-FEC Minimum", 1],
        12:  [DATA_TYPE_F16, "Host Pre-FEC Maximum", 1],
        14:  [DATA_TYPE_F16, "Host Pre-FEC Average", 1],
        16:  [DATA_TYPE_F16, "Host Pre-FEC Current", 1],
        18:  [DATA_TYPE_F16, "Host Post-FEC Minimum", 1],
        20:  [DATA_TYPE_F16, "Host Post-FEC Maximum", 1],
        22:  [DATA_TYPE_F16, "Host Post-FEC Average", 1],
        24:  [DATA_TYPE_F16, "Host Post-FEC Current", 1],

        134: [DATA_TYPE_S16, "CD", 1],
        136: [DATA_TYPE_U16, "DGD", 0.01],
        138: [DATA_TYPE_U16, "PDL", 0.1],
        141: [DATA_TYPE_S16, "CFO", 1],
        142: [DATA_TYPE_U16, "EVM", 100/65535],
        139: [DATA_TYPE_U16, "OSNR", 0.1],
        140: [DATA_TYPE_U16, "ESNR", 0.1],

        4:   [DATA_TYPE_S16, "Laser Temp", 1/256],
        143: [DATA_TYPE_S16, "Tx Power", 0.01],
        144: [DATA_TYPE_S16, "Rx Total Power", 0.01],
        145: [DATA_TYPE_S16, "Rx Signal Power", 0.01],
        128: [DATA_TYPE_U16, "BIAS_XI", 100/65535],
        129: [DATA_TYPE_U16, "BIAS_XQ", 100/65535],
        132: [DATA_TYPE_U16, "BIAS_XP", 100/65535],
        130: [DATA_TYPE_U16, "BIAS_YI", 100/65535],
        131: [DATA_TYPE_U16, "BIAS_YQ", 100/65535],
        133: [DATA_TYPE_U16, "BIAS_YP", 100/65535],
    })

    def __init__(self, trx):
        self.__trx = trx
        self.__vdm_mapping = None
    
    def __getitem__(self, key):
        return self.__get_vdm(key)

    def init_vdm_mapping(self):
        config_pages = [0x20, 0x21, 0x22, 0x23]
        vdm_mapping = {}
        for idx_page, page in enumerate(config_pages):
            self.__trx.select_bank_page(0, page)
            b_full_page = self.__trx[128:255]
            config_codes = [int.from_bytes(b_full_page[2*i+1: 2*i+2], 'big') for i in range(64)]
            for idx_config, i_code in enumerate(config_codes):
                if i_code in self.CONFIG_CODE_MAPPING:
                    d_type, key, dim = self.CONFIG_CODE_MAPPING[i_code]
                    vdm_mapping[key] = VdmInfo(
                        index=idx_config+idx_page*64+1,
                        data_type=d_type,
                        dimension=dim
                    )
        self.__vdm_mapping = vdm_mapping

    @property
    def mapping(self):
        if self.__vdm_mapping is None:
            raise ValueError('Please call init_vdm_mapping before any vdm operation.')
        else:
            return self.__vdm_mapping

    @property
    def keys(self):
        return self.mapping.keys()

    @property
    def FreezeRequest(self):
        flag = self.__trx[0, 0x2F, 144][7]
        freeze = bool(flag)
        return freeze

    @FreezeRequest.setter
    def FreezeRequest(self, freezed):
        if not freezed in (True, False):
            raise ValueError('Parameter freezed should be bool.')
        self.__trx[0, 0x2F, 144][7] = int(freezed)

    @property
    def FreezeDone(self):
        flag = self.__trx[0, 0x2F, 145][7]
        done = bool(flag)
        return done

    @property
    def UnfreezeDone(self):
        flag = self.__trx[0, 0x2F, 145][6]
        done = bool(flag)
        return done

    def freezeUntilDone(self):
        self.FreezeRequest = True
        while not self.FreezeDone:
            time.sleep(0.05)

    def unfreezeUntilDone(self):
        self.FreezeRequest = False
        while not self.UnfreezeDone:
            time.sleep(0.05)

    def __parse_data(self, raw, data_type, dimension):
        if data_type == self.DATA_TYPE_U16:
            val = raw.to_unsigned()
        elif data_type == self.DATA_TYPE_S16:
            val = raw.to_signed()
        elif data_type == self.DATA_TYPE_F16:
            u_int_val = raw.to_unsigned()
            val = (u_int_val & 0x7FF) * 10**((u_int_val >> 11) - 24)
        else:
            raise ValueError('Invalid data_type: {:!r}'.format(data_type))
        if val != 1:
            val *= dimension
        return val

    def __calc_page_reg_from_vdm_index(self, index):
        page = math.ceil(index/64) + 0x24 - 1
        reg_addr = ((index-1) % 64) * 2 + 128
        return page, reg_addr

    def __get_vdm(self, key):
        if key not in self.keys:
            raise KeyError('Invalid key for VDM: {key}. Not configured in VDM Configuration pages.'.format(key=key))
        vdm_info = self.mapping[key]
        index, data_type, dimension = vdm_info
        page, reg_addr = self.__calc_page_reg_from_vdm_index(index)
        raw = self.__trx[0, page, reg_addr: reg_addr+1]
        val = self.__parse_data(raw, data_type, dimension)
        return val
