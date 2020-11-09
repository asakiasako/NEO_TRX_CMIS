def check_type(params, types):
    if not isinstance(params, (list, tuple)):
        params = [params]
    if not isinstance(types, (list, tuple)):
        types = (types,)
    types = tuple(types)
    for i in params:
        if not isinstance(i, types):
            raise TypeError('Param type check failed.')


def check_range(params, min, max):
    if not isinstance(params, (list, tuple)):
        params = [params]
    for i in params:
        if not min <= i <= max:
            raise ValueError('Param out of range.')
