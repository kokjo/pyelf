import structures
from structures import ParseError
from const import *
from fields import *

def split_n(l, n, decode=lambda x: x):
    while len(l) >= n:
        yield decode(l[:n])
        l = l[n:]

class Section(structures.SHDR32):
    def _set_elffile(self, elffile):
        self.elffile = elffile

    def __repr__(self):
        return "<Section %s: 0x%x:0x%x offset:0x%x type:%r flags:%r, link:%r>" % (self.name,
                self.addr, self.size, self.offset, self.type, self.flags, self.link)

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
        return "<ProgramHeader 0x%x:0x%x(0x%x:0x%x) type:%r flags:%r>" % (self.vaddr,
                self.memsz, self.offset, self.filesz, self.type, self.flags)

    @property
    def sections(self):
        if self.type == PT_PHDR:
            return []
        secs = []
        for sec in self.elffile.sections:
            if self.offset <= sec.offset <= self.offset + self.filesz:
                secs.append(sec)
        secs.sort(key=lambda sec: sec.offset)
        return secs

    @property
    def data(self):
        if self.type == PT_LOAD:
            return self.elffile.data[self.offset:][:self.filesz]+"\x00"*(self.memsz-self.filesz)
        return ""

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
        return "<Symbol info:%r:%r %s 0x%x:0x%x section: %s>" % (self.type, self.bind, self.name, self.value, self.size, section_name)

    @property
    def section(self):
        try:
            return self.elffile.sections[self.shndx]
        except IndexError:
            return None

    @property
    def type(self):
        return SymbolType(self.info & 0xf)

    @type.setter
    def type(self, value):
        self.info = (self.bind << 4) | (value & 0xf)

    @property
    def bind(self):
        return SymbolBindingType((self.info >> 4) & 0xf)

    @bind.setter
    def bind(self, value):
        self.info = (value << 4) | (self.type & 0xf)

class Relocation(structures.REL32):
    def _set_relsection(self, section):
        self.relsection = section
    def _set_elffile(self, elffile):
        self.elffile = elffile

    @property
    def symndx(self):
        return self.info >> 8

    @symndx.setter
    def symndx(self, value):
        self.info = ((value << 8) | self.type) & 0xffffffff

    @property
    def type(self):
        return self.info & 0xff

    @type.setter
    def type(self, value):
        self.info = ((self.symndx << 8) | (value & 0xff)) & 0xffffffff

class MemoryViewer:
    def __init__(self, elffile):
        self.elffile = elffile
        self.segments = elffile.loadable_segments

    def __getitem__(self, slc):
        if type(slc) == int:
            slc = slice(slc, slc+1)
        if slc.step != None:
            raise IndexError("steps not supported")
        data = ""
        for seg in self.segments:
            if seg.vaddr <= slc.start and seg.vaddr <= slc.stop:
                off = slc.start-seg.vaddr
                size = min(seg.filesz-off, slc.stop-slc.start)
                data += seg.data[off:off+size]
                slc = slice(slc.start+size, slc.stop)
                if slc.stop <= slc.start:
                    break
        return data

class ELFFile(object):
    def __init__(self, fp):
        self.data = fp.read()
        self.header = structures.ELF32.decode(self.data)
        self.__load_sections()
        self.__load_program_headers()
        self.__load_symbols()
        self.__load_dynamic()
        self.__load_reloc()

    def __load_sections(self):
        shoff = self.header.shoff
        shlen = self.header.shentsize*self.header.shnum
        self.shdata = self.data[shoff:][:shlen]

        if len(self.shdata) != shlen:
            raise ParseError("length of section headers is out of bound")

        self.sections = []
        for ent in split_n(self.shdata, self.header.shentsize):
            section = Section.decode(ent)
            section._set_elffile(self)
            self.sections.append(section)

    def __load_program_headers(self):
        phoff = self.header.phoff
        phlen = self.header.phentsize*self.header.phnum
        self.phdata = self.data[phoff:][:phlen]

        self.proghdrs = []

        if not self.phdata:
            return

        if len(self.phdata) != phlen:
            raise ParseError("length of program headers is wrong")

        for proghdr in split_n(self.phdata, self.header.phentsize, ProgramHeader.decode):
            proghdr._set_elffile(self)
            self.proghdrs.append(proghdr)

    def __load_symbols(self):
        symtab = self.getsection(".symtab")
        self.symbols = []
        if not symtab:
            return
        for ent in split_n(symtab.data, symtab.entsize):
            sym = Symbol.decode(ent)
            sym._set_elffile(self)
            sym._set_symsection(symtab)
            self.symbols.append(sym)

    def __load_dynamic(self):
        dynamic = self.getsection(".dynamic")

        self.dynamic = []

        if not dynamic:
            return

        for ent in split_n(dynamic.data, dynamic.entsize):
            dyn = structures.DYN32.decode(ent)
            self.dynamic.append(dyn)

    def __load_reloc(self):
        self.relocations = {}
        for section in self.sections:
            if section.type != SHT_REL:
                continue

            rels = []

            for rel in split_n(section.data, section.entsize, Relocation.decode):
                rel._set_relsection(section)
                rel._set_elffile(self)
                rels.append(rel)

            self.relocations[section.name] = rels

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

    @property
    def loadable_segments(self):
        return [phdr for phdr in self.proghdrs if phdr.type == PT_LOAD]

    @property
    def memory(self):
        return MemoryViewer(self)


if __name__ == "__main__":
    import sys
    fp = open(sys.argv[1])
    elf = ELFFile(fp)
    print "ELF header:"
    print elf.header
    print "Sections:"
    for i, sec in enumerate(elf.sections):
        print "  ", i, ":", sec
    print "Program Headers:"
    for i, proghdr in enumerate(elf.proghdrs):
        print "  ", i, ":", proghdr
        print "Sections contained:"+" ".join(sec.name for sec in proghdr.sections)
    print "Symbols:"
    for i, sym in enumerate(elf.symbols):
        print "  ", i, ":", sym
    print "Dynamic:"
    for i, dyn in enumerate(elf.dynamic):
        print "  ", i, ":", dyn
    print "Relocations:"
    for i, relsection in enumerate(elf.relocations):
        print "  ", i, relsection, ":"
        for n, rel in enumerate(elf.relocations[relsection]):
            print n, ":", rel

    print "Data at extrypoint:"
    print elf.memory[elf.header.entry:elf.header.entry+16].encode("hex")

