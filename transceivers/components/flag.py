class Flag:

    def __init__(self, trx):
        self.__trx = trx
        self.__mapping = {
            'L-Rx1LOS': [(0, 0x11, 147), 0],
        }

    @property
    def mapping(self):
        return self.__mapping

    def __getitem__(self, key):
        address, bit = self.mapping[key]
        return self.__trx[address][bit]

    def __setitem__(self, key, asserted):
        if isinstance(asserted, bool):
            asserted = int(asserted)
        elif isinstance(asserted, int):
            if not 0 <= asserted <= 1:
                raise ValueError('Invalid value: {value}'.format(value=asserted))
        else:
            raise TypeError('Invalid value: {value}'.format(value=asserted))
        address, bit = self.mapping[key]
        self.__trx[address][bit] = asserted


