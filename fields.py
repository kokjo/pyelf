import const

class BitField(int):
    bits = []
    def __repr__(self):
        f = int(self)
        names = []
        for b, n in self.bits:
            if f & b:
                names.append(n)
            f &= ~b 
        if names:
            s = "|".join(names)
            if f:
                s += "+" + str(f)
            return s
        else:
            return str(f)

class IntConst(int):
    consts = {}
    def __repr__(self):
        try:
            return self.consts[int(self)]
        except KeyError:
            return str(self)

def foo(mod, prefix):
    return {getattr(mod, v): v for v in dir(mod) if v.startswith(prefix)}

class Machine(IntConst):
    consts = foo(const, "EM_")

class ELFType(IntConst):
    consts = foo(const, "ET_")

class SectionType(IntConst):
    consts = foo(const, "SHT_")

class SectionFlags(BitField):
    bits = foo(const, "SHF_").items()

class ProgHdrType(IntConst):
    consts = foo(const, "PT_")

class ProgHdrFlags(BitField):
    bits = foo(const, "PF_").items()

