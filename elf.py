import structures
from structures import ParseError
from const import *

class Section(structures.SHDR32):
    def _set_elffile(self, elffile):
        self.elffile = elffile

    def __repr__(self):
        return "<Section %s: 0x%x:0x%x type:%r flags:%r>" % (self.name,
                self.addr, self.size, self.type, self.flags)

    @property
    def data(self):
        if self.type == SHT_NOBITS:
            return "\x00"*self.size
        return self.elffile.data[self.offset:][:self.size]

    @property
    def name(self):
        return self.elffile.lookupshname(self.namendx)

    def __getitem__(self, key):
        pass

    def lookupstring(self, index):
        try:
            return self.data[index:].split("\x00",1)[0]
        except IndexError:
            return "*unknown*"

class ProgramHeader(structures.PHDR32):
    def _set_elffile(self, elffile):
        self.elffile = elffile

    def __repr__(self):
        return "<ProgramHeader 0x%x:0x%x(0x%x) type:%r flags:%r>" % (self.vaddr,
                self.memsz, self.filesz, self.type, self.flags)

class Symbol(structures.SYM32):
    def _set_symsection(self, section):
        self.symsection = section

    def _set_elffile(self, elffile):
        self.elffile = elffile

    @property
    def name(self):
        strtab = self.elffile.sections[self.symsection.link]
        return strtab.lookupstring(self.namendx)

    def __repr__(self):
        section_name = self.section and self.section.name or "*NO SECTION*"
        return "<Symbol %s 0x%x:0x%x section: %s>" % (self.name, self.value, self.size, section_name)
    @property
    def section(self):
        return self.elffile.sections[self.shndx]

    @property
    def type(self):
        return self.info & 0xf

    @type.setter
    def type(self, value):
        self.info = (self.bind << 4) | (value & 0xf)

    @property
    def bind(self):
        return (self.info >> 4) & 0xf

    @bind.setter
    def bind(self, value):
        self.info = (value << 4) | (self.type & 0xf)

class ELFFile(object):
    def __init__(self, fp):
        self.data = fp.read()
        self.header = structures.ELF32.decode(self.data)
        self.__load_sections()
        self.__load_program_headers()
        self.__load_symbols()

    def __load_sections(self):
        shoff = self.header.shoff
        shentsize = self.header.shentsize
        shlen = self.header.shentsize*self.header.shnum
        self.shdata = self.data[shoff:][:shlen]
        if len(self.shdata) != shlen:
            raise ParseError("length of section headers is out of bound")

        self.sections = []
        for i in range(self.header.shnum):
            section = Section.decode(
                    self.shdata[i*shentsize:][:shentsize])
            section._set_elffile(self)
            self.sections.append(section)

    def __load_program_headers(self):
        phoff = self.header.phoff
        phentsize = self.header.phentsize
        phlen = self.header.shentsize*self.header.shnum
        self.phdata = self.data[phoff:][:phlen]

        self.proghdrs = []
        if len(self.phdata) != phlen:
            raise ParseError("length of program headers is out of bound")
        for i in range(self.header.phnum):
            proghdr = ProgramHeader.decode(
                    self.phdata[i*phentsize:][:phentsize])
            proghdr._set_elffile(self)
            self.proghdrs.append(proghdr)

    def __load_symbols(self):
        symtab = self.getsection(".symtab")
        self.symbols = []
        if not symtab:
            return
        for i in range(symtab.size/symtab.entsize):
            sym = Symbol.decode(
                    symtab.data[i*symtab.entsize:][:symtab.entsize])
            sym._set_elffile(self)
            sym._set_symsection(symtab)
            self.symbols.append(sym)

    def lookupshname(self, index):
        try:
            return self.sections[self.header.shstrndx].lookupstring(index)
        except IndexError:
            return "*Unknown*"

    def lookupsymbol(self, name):
        for sym in self.symbols:
            if sym.name == name:
                return sym
        return None

    def getsection(self, name):
        for sec in self.sections:
            if sec.name == name:
                return sec
        return None

if __name__ == "__main__":
    import sys
    fp = open(sys.argv[1])
    elf = ELFFile(fp)
    print "ELF header:"
    print elf.header
    print "Sections:"
    for sec in elf.sections:
        print sec
    print "Program Headers:"
    for proghdr in elf.proghdrs:
        print proghdr
    print "Symbols:"
    for sym in elf.symbols:
        if sym.type in (STT_FUNC, STT_OBJECT):
            print sym
