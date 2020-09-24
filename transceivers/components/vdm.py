class Vdm:

    def __init__(self, trx):
        self.__trx = trx
        self.__keys = (
            'Media Min Pre',
            'Media Max Pre',
            'Media Avg Pre',
            'Media Cur Pre',
            'Host Min Pre',
            'Host Max Pre',
            'Host Avg Pre',
            'Host Cur Pre',
            'Media Min Post',
            'Media Max Post',
            'Media Avg Post',
            'Media Cur Post',
            'Host Min Post',
            'Host Max Post',
            'Host Avg Post',
            'Host Cur Post',
            'CD',               # ps/nm
            'DGD',              # ps
            'PDL',              # db
            'CFO',              # MHZ
            'EVM',
            'Laser Temp',       # C
            'Tx Power',         # dBm
            'Rx Sig Power',     # dBm
            'Rx Total Power',   # dBm
        )
    
    def __getitem__(self, key):
        return self.__get_vdm(key)

    @property
    def keys(self):
        return self.__keys

    def __parse_ber(self, raw):
        return (raw & 0x7ff) * 10**((raw >> 11) - 24)

    def __get_vdm(self, key):
        if key not in self.keys:
            raise KeyError('Invalid key for VDM: {key}'.format(key=key))
        # Pre-FEC BER
        if key=='Media Min Pre':
            return self.__parse_ber(self.__trx[0, 0x24, 128:129].to_unsigned())
        if key=='Media Max Pre':
            return self.__parse_ber(self.__trx[0, 0x24, 130:131].to_unsigned())
        if key=='Media Avg Pre':
            return self.__parse_ber(self.__trx[0, 0x24, 132:133].to_unsigned())
        if key=='Media Cur Pre':
            return self.__parse_ber(self.__trx[0, 0x24, 134:135].to_unsigned())
        if key=='Host Min Pre':
            return self.__parse_ber(self.__trx[0, 0x24, 136:137].to_unsigned())
        if key=='Host Max Pre':
            return self.__parse_ber(self.__trx[0, 0x24, 138:139].to_unsigned())
        if key=='Host Avg Pre':
            return self.__parse_ber(self.__trx[0, 0x24, 140:141].to_unsigned())
        if key=='Host Cur Pre':
            return self.__parse_ber(self.__trx[0, 0x24, 142:143].to_unsigned())
        # Post-FEC BER
        if key=='Media Min Post':
            return self.__parse_ber(self.__trx[0, 0x24, 162:163].to_unsigned())
        if key=='Media Max Post':
            return self.__parse_ber(self.__trx[0, 0x24, 164:165].to_unsigned())
        if key=='Media Avg Post':
            return self.__parse_ber(self.__trx[0, 0x24, 166:167].to_unsigned())
        if key=='Media Cur Post':
            return self.__parse_ber(self.__trx[0, 0x24, 168:169].to_unsigned())
        if key=='Host Min Post':
            return self.__parse_ber(self.__trx[0, 0x24, 170:171].to_unsigned())
        if key=='Host Max Post':
            return self.__parse_ber(self.__trx[0, 0x24, 172:173].to_unsigned())
        if key=='Host Avg Post':
            return self.__parse_ber(self.__trx[0, 0x24, 174:175].to_unsigned())
        if key=='Host Cur Post':
            return self.__parse_ber(self.__trx[0, 0x24, 176:177].to_unsigned())
        # Others      
        if key=='CD':
            # ps/nm
            return self.__trx[0, 0x24, 144:145].to_signed()
        if key=='DGD':
            # ps
            return self.__trx[0, 0x24, 146:147].to_unsigned()*0.01
        if key=='PDL':
            # dB
            return self.__trx[0, 0x24, 148:149].to_unsigned()*0.1
        if key=='CFO':
            # MHz
            return self.__trx[0, 0x24, 150:151].to_signed()
        if key=='EVM':
            # normalization to 1
            return self.__trx[0, 0x24, 152:153].to_unsigned()*100/65535
        if key=='Laser Temp':
            # C
            return self.__trx[0, 0x24, 154:155].to_signed()/256
        if key=='Tx Power':
            # dBm
            return self.__trx[0, 0x24, 156:157].to_signed()*0.01
        if key=='Rx Sig Power':
            # dBm
            return self.__trx[0, 0x24, 158:159].to_signed()*0.01
        if key=='Rx Total Power':
            # dBm
            return self.__trx[0, 0x24, 160:161].to_signed()*0.01
        
        raise KeyError('Method to get VDM not exist: {key}'.format(key=key))
