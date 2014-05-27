import struct
from const import *
from fields import *
class Packer(object):
    fields_desc = []
    __fmtstring_cache = None
    __fields_cache = None
    __decos_cache = None
    def __init__(self, **kwargs):
        for k,v in kwargs.items():
            setattr(self, k, v)

    @classmethod
    def fmtstring(cls):
        if cls.__fmtstring_cache:
            return cls.__fmtstring_cache
        fmt = "<"+"".join(f for (_, f, _) in cls.fields_desc)
        cls.__fmtstring_cache = fmt
        return fmt

    @classmethod
    def fmtsize(cls):
        return struct.calcsize(cls.fmtstring())

    @classmethod
    def fields(cls):
        if cls.__fields_cache:
            return cls.__fields_cache
        fields = [f for  (f, _, _) in cls.fields_desc]
        cls.__fields_cache = fields
        return fields

    @classmethod
    def decos(cls):
        if cls.__decos_cache:
            return cls.__decos_cache
        decos = [f for (_, _, f) in cls.fields_desc]
        cls.__decos_cache = decos
        return decos

    @classmethod
    def decode(cls, data, check=True):
        s = struct.unpack(cls.fmtstring(), data[:cls.fmtsize()])
        self = cls(**dict(zip(cls.fields(), (f and f(d) or d for (f,d) in zip(cls.decos(), s)))))
        if check:
            self.check()
        return self

    def encode(self):
        values = [getattr(self, f) for f in self.fields()]
        return struct.pack(self.fmtstring(), *values)

    def check(self):
        pass

    def __repr__(self):
        r = "<%s" % self.__class__.__name__
        for f in self.fields():
            v = getattr(self, f, None)
            if type(v) == str:
                r += " %s:%s" % (f, v.encode("hex"))
            elif type(v) == int:
                r += " %s:0x%x" % (f, v)
            else:
                r += " %s:%r"  % (f, v)
        r += ">"
        return r

class ParseError(Exception):
    pass

class ELF32(Packer):
    fields_desc = [
        ("ident", "16s", None),
        ("type", "H", ELFType),
        ("machine", "H", Machine),
        ("version", "L", None),
        ("entry", "L", None),
        ("phoff", "L", None),
        ("shoff", "L", None),
        ("flags", "L", None),
        ("ehsize", "H", None),
        ("phentsize", "H", None),
        ("phnum", "H", None),
        ("shentsize", "H", None),
        ("shnum", "H", None),
        ("shstrndx", "H", None)]

    def check(self):
        if self.ident[:4] != ELFMAG:
            raise ParseError("Does not contain ELF header")
        if ord(self.ident[EI_CLASS]) != ELFCLASS32:
            raise ParseError("ELF file it is not 32-bit")
        if ord(self.ident[EI_DATA]) != ELFDATA2LSB:
            raise ParseError("ELF file is not encoded in LSB")
        if ord(self.ident[EI_VERSION]) != EV_CURRENT:
            raise ParseError("ELF file is not the corrent version (?)")

class SHDR32(Packer):
    fields_desc = [
        ("namendx", "L", None),
        ("type", "L", SectionType),
        ("flags", "L", SectionFlags),
        ("addr", "L", None),
        ("offset", "L", None),
        ("size", "L", None),
        ("link", "L", None),
        ("info", "L", None),
        ("addralign", "L", None),
        ("entsize", "L", None)]

class SYM32(Packer):
    fields_desc = [
        ("namendx", "L", None),
        ("value", "L", None),
        ("size", "L", None),
        ("info", "B", None),
        ("other", "B", None),
        ("shndx", "H", None)]

class PHDR32(Packer):
    fields_desc = [
        ("type", "L", ProgHdrType),
        ("offset", "L", None),
        ("vaddr", "L", None),
        ("paddr", "L", None),
        ("filesz", "L", None),
        ("memsz", "L", None),
        ("flags", "L", ProgHdrFlags),
        ("align", "L", None)]

class REL32(Packer):
    fields_desc = [
        ("offset", "L", None),
        ("info", "L", None)]

class RELA32(Packer):
    fields_desc = [
        ("offset", "L", None),
        ("info", "L", None),
        ("addend", "l", None)]

class DYN32(Packer):
    fields_desc = [
        ("tag", "L", DynTag),
        ("valptr", "L", None)]
