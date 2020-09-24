class Ddm:

    def __init__(self, trx):
        self.__trx = trx
        self.__keys = (
            'Module Temperature',   # C
            'Supply Voltage',       # V
            'Laser Temperature',    # C
            'DSP Temperature',      # C
            'Tx1 Power',            # mW
            'Tx1 Bias',             # mA
            'Rx1 Power',            # mW
        )
    
    def __getitem__(self, key):
        return self.__get_ddm(key)

    @property
    def keys(self):
        return self.__keys

    def __get_ddm(self, key):
        if key not in self.keys:
            raise KeyError('Invalid key for DDM: {key}'.format(key=key))
        # Pre-FEC BER
        if key=='Module Temperature':
            return self.__trx[14:15].to_signed()/256
        if key=='Supply Voltage':
            return self.__trx[16:17].to_unsigned()*100*10**(-6)
        if key=='Laser Temperature':
            return self.__trx[20:21].to_signed()/256
        if key=='DSP Temperature':
            return self.__trx[24:25].to_signed()/256
        if key=='Tx1 Power':
            return self.__trx[0, 0x11, 154:155].to_unsigned() * 0.1 * 10**(-3)
        if key=='Tx1 Bias':
            return self.__trx[0, 0x11, 170:171].to_unsigned() * 2 * 10**(-3)
        if key=='Rx1 Power':
            return self.__trx[0, 0x11, 186:187].to_unsigned() * 0.1 * 10**(-3)
        
        raise KeyError('Method to get DDM not exist: {key}'.format(key=key))
