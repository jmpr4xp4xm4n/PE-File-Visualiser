"""pefile, Portable Executable reader module


All the PE file basic structures are available with their default names
as attributes of the instance returned.

Processed elements such as the import table are made available with lowercase
names, to differentiate them from the upper case basic structure names.

pefile has been tested against the limits of valid PE headers, that is, malware.
Lots of packed malware attempt to abuse the format way beyond its standard use.
To the best of my knowledge most of the abuses are handled gracefully.

Copyright (c) 2005-2011 Ero Carrera <ero.carrera@gmail.com>

All rights reserved.

For detailed copyright information see the file COPYING in
the root of the distribution archive.
"""
__revision__ = '$LastChangedRevision: 114 $'
__author__ = 'Ero Carrera'
__version__ = '1.2.10-%d' % int(__revision__[21:-2])
__contact__ = 'ero.carrera@gmail.com'
import os
import struct
import time
import math
import re
import exceptions
import string
import array
import mmap
sha1, sha256, sha512, md5 = (None, None, None, None)
try:
    import hashlib
    sha1 = hashlib.sha1
    sha256 = hashlib.sha256
    sha512 = hashlib.sha512
    md5 = hashlib.md5
except ImportError:
    try:
        import sha
        sha1 = sha.new
    except ImportError:
        pass

    try:
        import md5
        md5 = md5.new
    except ImportError:
        pass

try:
    enumerate
except NameError:

    def enumerate(iter):
        L = list(iter)
        return zip(range(0, len(L)), L)


fast_load = False
MAX_STRING_LENGTH = 1048576
IMAGE_DOS_SIGNATURE = 23117
IMAGE_DOSZM_SIGNATURE = 19802
IMAGE_NE_SIGNATURE = 17742
IMAGE_LE_SIGNATURE = 17740
IMAGE_LX_SIGNATURE = 22604
IMAGE_NT_SIGNATURE = 17744
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_ORDINAL_FLAG = 2147483648L
IMAGE_ORDINAL_FLAG64 = 9223372036854775808L
OPTIONAL_HEADER_MAGIC_PE = 267
OPTIONAL_HEADER_MAGIC_PE_PLUS = 523
directory_entry_types = [('IMAGE_DIRECTORY_ENTRY_EXPORT', 0),
 ('IMAGE_DIRECTORY_ENTRY_IMPORT', 1),
 ('IMAGE_DIRECTORY_ENTRY_RESOURCE', 2),
 ('IMAGE_DIRECTORY_ENTRY_EXCEPTION', 3),
 ('IMAGE_DIRECTORY_ENTRY_SECURITY', 4),
 ('IMAGE_DIRECTORY_ENTRY_BASERELOC', 5),
 ('IMAGE_DIRECTORY_ENTRY_DEBUG', 6),
 ('IMAGE_DIRECTORY_ENTRY_COPYRIGHT', 7),
 ('IMAGE_DIRECTORY_ENTRY_GLOBALPTR', 8),
 ('IMAGE_DIRECTORY_ENTRY_TLS', 9),
 ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG', 10),
 ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT', 11),
 ('IMAGE_DIRECTORY_ENTRY_IAT', 12),
 ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT', 13),
 ('IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR', 14),
 ('IMAGE_DIRECTORY_ENTRY_RESERVED', 15)]
DIRECTORY_ENTRY = dict([ (e[1], e[0]) for e in directory_entry_types ] + directory_entry_types)
image_characteristics = [('IMAGE_FILE_RELOCS_STRIPPED', 1),
 ('IMAGE_FILE_EXECUTABLE_IMAGE', 2),
 ('IMAGE_FILE_LINE_NUMS_STRIPPED', 4),
 ('IMAGE_FILE_LOCAL_SYMS_STRIPPED', 8),
 ('IMAGE_FILE_AGGRESIVE_WS_TRIM', 16),
 ('IMAGE_FILE_LARGE_ADDRESS_AWARE', 32),
 ('IMAGE_FILE_16BIT_MACHINE', 64),
 ('IMAGE_FILE_BYTES_REVERSED_LO', 128),
 ('IMAGE_FILE_32BIT_MACHINE', 256),
 ('IMAGE_FILE_DEBUG_STRIPPED', 512),
 ('IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP', 1024),
 ('IMAGE_FILE_NET_RUN_FROM_SWAP', 2048),
 ('IMAGE_FILE_SYSTEM', 4096),
 ('IMAGE_FILE_DLL', 8192),
 ('IMAGE_FILE_UP_SYSTEM_ONLY', 16384),
 ('IMAGE_FILE_BYTES_REVERSED_HI', 32768)]
IMAGE_CHARACTERISTICS = dict([ (e[1], e[0]) for e in image_characteristics ] + image_characteristics)
section_characteristics = [('IMAGE_SCN_CNT_CODE', 32),
 ('IMAGE_SCN_CNT_INITIALIZED_DATA', 64),
 ('IMAGE_SCN_CNT_UNINITIALIZED_DATA', 128),
 ('IMAGE_SCN_LNK_OTHER', 256),
 ('IMAGE_SCN_LNK_INFO', 512),
 ('IMAGE_SCN_LNK_REMOVE', 2048),
 ('IMAGE_SCN_LNK_COMDAT', 4096),
 ('IMAGE_SCN_MEM_FARDATA', 32768),
 ('IMAGE_SCN_MEM_PURGEABLE', 131072),
 ('IMAGE_SCN_MEM_16BIT', 131072),
 ('IMAGE_SCN_MEM_LOCKED', 262144),
 ('IMAGE_SCN_MEM_PRELOAD', 524288),
 ('IMAGE_SCN_ALIGN_1BYTES', 1048576),
 ('IMAGE_SCN_ALIGN_2BYTES', 2097152),
 ('IMAGE_SCN_ALIGN_4BYTES', 3145728),
 ('IMAGE_SCN_ALIGN_8BYTES', 4194304),
 ('IMAGE_SCN_ALIGN_16BYTES', 5242880),
 ('IMAGE_SCN_ALIGN_32BYTES', 6291456),
 ('IMAGE_SCN_ALIGN_64BYTES', 7340032),
 ('IMAGE_SCN_ALIGN_128BYTES', 8388608),
 ('IMAGE_SCN_ALIGN_256BYTES', 9437184),
 ('IMAGE_SCN_ALIGN_512BYTES', 10485760),
 ('IMAGE_SCN_ALIGN_1024BYTES', 11534336),
 ('IMAGE_SCN_ALIGN_2048BYTES', 12582912),
 ('IMAGE_SCN_ALIGN_4096BYTES', 13631488),
 ('IMAGE_SCN_ALIGN_8192BYTES', 14680064),
 ('IMAGE_SCN_ALIGN_MASK', 15728640),
 ('IMAGE_SCN_LNK_NRELOC_OVFL', 16777216),
 ('IMAGE_SCN_MEM_DISCARDABLE', 33554432),
 ('IMAGE_SCN_MEM_NOT_CACHED', 67108864),
 ('IMAGE_SCN_MEM_NOT_PAGED', 134217728),
 ('IMAGE_SCN_MEM_SHARED', 268435456),
 ('IMAGE_SCN_MEM_EXECUTE', 536870912),
 ('IMAGE_SCN_MEM_READ', 1073741824),
 ('IMAGE_SCN_MEM_WRITE', 2147483648L)]
SECTION_CHARACTERISTICS = dict([ (e[1], e[0]) for e in section_characteristics ] + section_characteristics)
debug_types = [('IMAGE_DEBUG_TYPE_UNKNOWN', 0),
 ('IMAGE_DEBUG_TYPE_COFF', 1),
 ('IMAGE_DEBUG_TYPE_CODEVIEW', 2),
 ('IMAGE_DEBUG_TYPE_FPO', 3),
 ('IMAGE_DEBUG_TYPE_MISC', 4),
 ('IMAGE_DEBUG_TYPE_EXCEPTION', 5),
 ('IMAGE_DEBUG_TYPE_FIXUP', 6),
 ('IMAGE_DEBUG_TYPE_OMAP_TO_SRC', 7),
 ('IMAGE_DEBUG_TYPE_OMAP_FROM_SRC', 8),
 ('IMAGE_DEBUG_TYPE_BORLAND', 9),
 ('IMAGE_DEBUG_TYPE_RESERVED10', 10)]
DEBUG_TYPE = dict([ (e[1], e[0]) for e in debug_types ] + debug_types)
subsystem_types = [('IMAGE_SUBSYSTEM_UNKNOWN', 0),
 ('IMAGE_SUBSYSTEM_NATIVE', 1),
 ('IMAGE_SUBSYSTEM_WINDOWS_GUI', 2),
 ('IMAGE_SUBSYSTEM_WINDOWS_CUI', 3),
 ('IMAGE_SUBSYSTEM_OS2_CUI', 5),
 ('IMAGE_SUBSYSTEM_POSIX_CUI', 7),
 ('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', 9),
 ('IMAGE_SUBSYSTEM_EFI_APPLICATION', 10),
 ('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', 11),
 ('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', 12),
 ('IMAGE_SUBSYSTEM_EFI_ROM', 13),
 ('IMAGE_SUBSYSTEM_XBOX', 14)]
SUBSYSTEM_TYPE = dict([ (e[1], e[0]) for e in subsystem_types ] + subsystem_types)
machine_types = [('IMAGE_FILE_MACHINE_UNKNOWN', 0),
 ('IMAGE_FILE_MACHINE_AM33', 467),
 ('IMAGE_FILE_MACHINE_AMD64', 34404),
 ('IMAGE_FILE_MACHINE_ARM', 448),
 ('IMAGE_FILE_MACHINE_EBC', 3772),
 ('IMAGE_FILE_MACHINE_I386', 332),
 ('IMAGE_FILE_MACHINE_IA64', 512),
 ('IMAGE_FILE_MACHINE_MR32', 36929),
 ('IMAGE_FILE_MACHINE_MIPS16', 614),
 ('IMAGE_FILE_MACHINE_MIPSFPU', 870),
 ('IMAGE_FILE_MACHINE_MIPSFPU16', 1126),
 ('IMAGE_FILE_MACHINE_POWERPC', 496),
 ('IMAGE_FILE_MACHINE_POWERPCFP', 497),
 ('IMAGE_FILE_MACHINE_R4000', 358),
 ('IMAGE_FILE_MACHINE_SH3', 418),
 ('IMAGE_FILE_MACHINE_SH3DSP', 419),
 ('IMAGE_FILE_MACHINE_SH4', 422),
 ('IMAGE_FILE_MACHINE_SH5', 424),
 ('IMAGE_FILE_MACHINE_THUMB', 450),
 ('IMAGE_FILE_MACHINE_WCEMIPSV2', 361)]
MACHINE_TYPE = dict([ (e[1], e[0]) for e in machine_types ] + machine_types)
relocation_types = [('IMAGE_REL_BASED_ABSOLUTE', 0),
 ('IMAGE_REL_BASED_HIGH', 1),
 ('IMAGE_REL_BASED_LOW', 2),
 ('IMAGE_REL_BASED_HIGHLOW', 3),
 ('IMAGE_REL_BASED_HIGHADJ', 4),
 ('IMAGE_REL_BASED_MIPS_JMPADDR', 5),
 ('IMAGE_REL_BASED_SECTION', 6),
 ('IMAGE_REL_BASED_REL', 7),
 ('IMAGE_REL_BASED_MIPS_JMPADDR16', 9),
 ('IMAGE_REL_BASED_IA64_IMM64', 9),
 ('IMAGE_REL_BASED_DIR64', 10),
 ('IMAGE_REL_BASED_HIGH3ADJ', 11)]
RELOCATION_TYPE = dict([ (e[1], e[0]) for e in relocation_types ] + relocation_types)
dll_characteristics = [('IMAGE_DLL_CHARACTERISTICS_RESERVED_0x0001', 1),
 ('IMAGE_DLL_CHARACTERISTICS_RESERVED_0x0002', 2),
 ('IMAGE_DLL_CHARACTERISTICS_RESERVED_0x0004', 4),
 ('IMAGE_DLL_CHARACTERISTICS_RESERVED_0x0008', 8),
 ('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', 64),
 ('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', 128),
 ('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', 256),
 ('IMAGE_DLL_CHARACTERISTICS_NO_ISOLATION', 512),
 ('IMAGE_DLL_CHARACTERISTICS_NO_SEH', 1024),
 ('IMAGE_DLL_CHARACTERISTICS_NO_BIND', 2048),
 ('IMAGE_DLL_CHARACTERISTICS_RESERVED_0x1000', 4096),
 ('IMAGE_DLL_CHARACTERISTICS_WDM_DRIVER', 8192),
 ('IMAGE_DLL_CHARACTERISTICS_TERMINAL_SERVER_AWARE', 32768)]
DLL_CHARACTERISTICS = dict([ (e[1], e[0]) for e in dll_characteristics ] + dll_characteristics)
resource_type = [('RT_CURSOR', 1),
 ('RT_BITMAP', 2),
 ('RT_ICON', 3),
 ('RT_MENU', 4),
 ('RT_DIALOG', 5),
 ('RT_STRING', 6),
 ('RT_FONTDIR', 7),
 ('RT_FONT', 8),
 ('RT_ACCELERATOR', 9),
 ('RT_RCDATA', 10),
 ('RT_MESSAGETABLE', 11),
 ('RT_GROUP_CURSOR', 12),
 ('RT_GROUP_ICON', 14),
 ('RT_VERSION', 16),
 ('RT_DLGINCLUDE', 17),
 ('RT_PLUGPLAY', 19),
 ('RT_VXD', 20),
 ('RT_ANICURSOR', 21),
 ('RT_ANIICON', 22),
 ('RT_HTML', 23),
 ('RT_MANIFEST', 24)]
RESOURCE_TYPE = dict([ (e[1], e[0]) for e in resource_type ] + resource_type)
lang = [('LANG_NEUTRAL', 0),
 ('LANG_INVARIANT', 127),
 ('LANG_AFRIKAANS', 54),
 ('LANG_ALBANIAN', 28),
 ('LANG_ARABIC', 1),
 ('LANG_ARMENIAN', 43),
 ('LANG_ASSAMESE', 77),
 ('LANG_AZERI', 44),
 ('LANG_BASQUE', 45),
 ('LANG_BELARUSIAN', 35),
 ('LANG_BENGALI', 69),
 ('LANG_BULGARIAN', 2),
 ('LANG_CATALAN', 3),
 ('LANG_CHINESE', 4),
 ('LANG_CROATIAN', 26),
 ('LANG_CZECH', 5),
 ('LANG_DANISH', 6),
 ('LANG_DIVEHI', 101),
 ('LANG_DUTCH', 19),
 ('LANG_ENGLISH', 9),
 ('LANG_ESTONIAN', 37),
 ('LANG_FAEROESE', 56),
 ('LANG_FARSI', 41),
 ('LANG_FINNISH', 11),
 ('LANG_FRENCH', 12),
 ('LANG_GALICIAN', 86),
 ('LANG_GEORGIAN', 55),
 ('LANG_GERMAN', 7),
 ('LANG_GREEK', 8),
 ('LANG_GUJARATI', 71),
 ('LANG_HEBREW', 13),
 ('LANG_HINDI', 57),
 ('LANG_HUNGARIAN', 14),
 ('LANG_ICELANDIC', 15),
 ('LANG_INDONESIAN', 33),
 ('LANG_ITALIAN', 16),
 ('LANG_JAPANESE', 17),
 ('LANG_KANNADA', 75),
 ('LANG_KASHMIRI', 96),
 ('LANG_KAZAK', 63),
 ('LANG_KONKANI', 87),
 ('LANG_KOREAN', 18),
 ('LANG_KYRGYZ', 64),
 ('LANG_LATVIAN', 38),
 ('LANG_LITHUANIAN', 39),
 ('LANG_MACEDONIAN', 47),
 ('LANG_MALAY', 62),
 ('LANG_MALAYALAM', 76),
 ('LANG_MANIPURI', 88),
 ('LANG_MARATHI', 78),
 ('LANG_MONGOLIAN', 80),
 ('LANG_NEPALI', 97),
 ('LANG_NORWEGIAN', 20),
 ('LANG_ORIYA', 72),
 ('LANG_POLISH', 21),
 ('LANG_PORTUGUESE', 22),
 ('LANG_PUNJABI', 70),
 ('LANG_ROMANIAN', 24),
 ('LANG_RUSSIAN', 25),
 ('LANG_SANSKRIT', 79),
 ('LANG_SERBIAN', 26),
 ('LANG_SINDHI', 89),
 ('LANG_SLOVAK', 27),
 ('LANG_SLOVENIAN', 36),
 ('LANG_SPANISH', 10),
 ('LANG_SWAHILI', 65),
 ('LANG_SWEDISH', 29),
 ('LANG_SYRIAC', 90),
 ('LANG_TAMIL', 73),
 ('LANG_TATAR', 68),
 ('LANG_TELUGU', 74),
 ('LANG_THAI', 30),
 ('LANG_TURKISH', 31),
 ('LANG_UKRAINIAN', 34),
 ('LANG_URDU', 32),
 ('LANG_UZBEK', 67),
 ('LANG_VIETNAMESE', 42),
 ('LANG_GAELIC', 60),
 ('LANG_MALTESE', 58),
 ('LANG_MAORI', 40),
 ('LANG_RHAETO_ROMANCE', 23),
 ('LANG_SAAMI', 59),
 ('LANG_SORBIAN', 46),
 ('LANG_SUTU', 48),
 ('LANG_TSONGA', 49),
 ('LANG_TSWANA', 50),
 ('LANG_VENDA', 51),
 ('LANG_XHOSA', 52),
 ('LANG_ZULU', 53),
 ('LANG_ESPERANTO', 143),
 ('LANG_WALON', 144),
 ('LANG_CORNISH', 145),
 ('LANG_WELSH', 146),
 ('LANG_BRETON', 147)]
LANG = dict(lang + [ (e[1], e[0]) for e in lang ])
sublang = [('SUBLANG_NEUTRAL', 0),
 ('SUBLANG_DEFAULT', 1),
 ('SUBLANG_SYS_DEFAULT', 2),
 ('SUBLANG_ARABIC_SAUDI_ARABIA', 1),
 ('SUBLANG_ARABIC_IRAQ', 2),
 ('SUBLANG_ARABIC_EGYPT', 3),
 ('SUBLANG_ARABIC_LIBYA', 4),
 ('SUBLANG_ARABIC_ALGERIA', 5),
 ('SUBLANG_ARABIC_MOROCCO', 6),
 ('SUBLANG_ARABIC_TUNISIA', 7),
 ('SUBLANG_ARABIC_OMAN', 8),
 ('SUBLANG_ARABIC_YEMEN', 9),
 ('SUBLANG_ARABIC_SYRIA', 10),
 ('SUBLANG_ARABIC_JORDAN', 11),
 ('SUBLANG_ARABIC_LEBANON', 12),
 ('SUBLANG_ARABIC_KUWAIT', 13),
 ('SUBLANG_ARABIC_UAE', 14),
 ('SUBLANG_ARABIC_BAHRAIN', 15),
 ('SUBLANG_ARABIC_QATAR', 16),
 ('SUBLANG_AZERI_LATIN', 1),
 ('SUBLANG_AZERI_CYRILLIC', 2),
 ('SUBLANG_CHINESE_TRADITIONAL', 1),
 ('SUBLANG_CHINESE_SIMPLIFIED', 2),
 ('SUBLANG_CHINESE_HONGKONG', 3),
 ('SUBLANG_CHINESE_SINGAPORE', 4),
 ('SUBLANG_CHINESE_MACAU', 5),
 ('SUBLANG_DUTCH', 1),
 ('SUBLANG_DUTCH_BELGIAN', 2),
 ('SUBLANG_ENGLISH_US', 1),
 ('SUBLANG_ENGLISH_UK', 2),
 ('SUBLANG_ENGLISH_AUS', 3),
 ('SUBLANG_ENGLISH_CAN', 4),
 ('SUBLANG_ENGLISH_NZ', 5),
 ('SUBLANG_ENGLISH_EIRE', 6),
 ('SUBLANG_ENGLISH_SOUTH_AFRICA', 7),
 ('SUBLANG_ENGLISH_JAMAICA', 8),
 ('SUBLANG_ENGLISH_CARIBBEAN', 9),
 ('SUBLANG_ENGLISH_BELIZE', 10),
 ('SUBLANG_ENGLISH_TRINIDAD', 11),
 ('SUBLANG_ENGLISH_ZIMBABWE', 12),
 ('SUBLANG_ENGLISH_PHILIPPINES', 13),
 ('SUBLANG_FRENCH', 1),
 ('SUBLANG_FRENCH_BELGIAN', 2),
 ('SUBLANG_FRENCH_CANADIAN', 3),
 ('SUBLANG_FRENCH_SWISS', 4),
 ('SUBLANG_FRENCH_LUXEMBOURG', 5),
 ('SUBLANG_FRENCH_MONACO', 6),
 ('SUBLANG_GERMAN', 1),
 ('SUBLANG_GERMAN_SWISS', 2),
 ('SUBLANG_GERMAN_AUSTRIAN', 3),
 ('SUBLANG_GERMAN_LUXEMBOURG', 4),
 ('SUBLANG_GERMAN_LIECHTENSTEIN', 5),
 ('SUBLANG_ITALIAN', 1),
 ('SUBLANG_ITALIAN_SWISS', 2),
 ('SUBLANG_KASHMIRI_SASIA', 2),
 ('SUBLANG_KASHMIRI_INDIA', 2),
 ('SUBLANG_KOREAN', 1),
 ('SUBLANG_LITHUANIAN', 1),
 ('SUBLANG_MALAY_MALAYSIA', 1),
 ('SUBLANG_MALAY_BRUNEI_DARUSSALAM', 2),
 ('SUBLANG_NEPALI_INDIA', 2),
 ('SUBLANG_NORWEGIAN_BOKMAL', 1),
 ('SUBLANG_NORWEGIAN_NYNORSK', 2),
 ('SUBLANG_PORTUGUESE', 2),
 ('SUBLANG_PORTUGUESE_BRAZILIAN', 1),
 ('SUBLANG_SERBIAN_LATIN', 2),
 ('SUBLANG_SERBIAN_CYRILLIC', 3),
 ('SUBLANG_SPANISH', 1),
 ('SUBLANG_SPANISH_MEXICAN', 2),
 ('SUBLANG_SPANISH_MODERN', 3),
 ('SUBLANG_SPANISH_GUATEMALA', 4),
 ('SUBLANG_SPANISH_COSTA_RICA', 5),
 ('SUBLANG_SPANISH_PANAMA', 6),
 ('SUBLANG_SPANISH_DOMINICAN_REPUBLIC', 7),
 ('SUBLANG_SPANISH_VENEZUELA', 8),
 ('SUBLANG_SPANISH_COLOMBIA', 9),
 ('SUBLANG_SPANISH_PERU', 10),
 ('SUBLANG_SPANISH_ARGENTINA', 11),
 ('SUBLANG_SPANISH_ECUADOR', 12),
 ('SUBLANG_SPANISH_CHILE', 13),
 ('SUBLANG_SPANISH_URUGUAY', 14),
 ('SUBLANG_SPANISH_PARAGUAY', 15),
 ('SUBLANG_SPANISH_BOLIVIA', 16),
 ('SUBLANG_SPANISH_EL_SALVADOR', 17),
 ('SUBLANG_SPANISH_HONDURAS', 18),
 ('SUBLANG_SPANISH_NICARAGUA', 19),
 ('SUBLANG_SPANISH_PUERTO_RICO', 20),
 ('SUBLANG_SWEDISH', 1),
 ('SUBLANG_SWEDISH_FINLAND', 2),
 ('SUBLANG_URDU_PAKISTAN', 1),
 ('SUBLANG_URDU_INDIA', 2),
 ('SUBLANG_UZBEK_LATIN', 1),
 ('SUBLANG_UZBEK_CYRILLIC', 2),
 ('SUBLANG_DUTCH_SURINAM', 3),
 ('SUBLANG_ROMANIAN', 1),
 ('SUBLANG_ROMANIAN_MOLDAVIA', 2),
 ('SUBLANG_RUSSIAN', 1),
 ('SUBLANG_RUSSIAN_MOLDAVIA', 2),
 ('SUBLANG_CROATIAN', 1),
 ('SUBLANG_LITHUANIAN_CLASSIC', 2),
 ('SUBLANG_GAELIC', 1),
 ('SUBLANG_GAELIC_SCOTTISH', 2),
 ('SUBLANG_GAELIC_MANX', 3)]
SUBLANG = dict(sublang + [ (e[1], e[0]) for e in sublang ])
SUBLANG = dict(sublang)
for sublang_name, sublang_value in sublang:
    if SUBLANG.has_key(sublang_value):
        SUBLANG[sublang_value].append(sublang_name)
    else:
        SUBLANG[sublang_value] = [sublang_name]

def get_sublang_name_for_lang(lang_value, sublang_value):
    lang_name = LANG.get(lang_value, '*unknown*')
    for sublang_name in SUBLANG.get(sublang_value, list()):
        if lang_name in sublang_name:
            return sublang_name

    return SUBLANG.get(sublang_value, ['*unknown*'])[0]


def parse_strings(data, counter, l):
    i = 0
    error_count = 0
    while i < len(data):
        data_slice = data[i:i + 2]
        if len(data_slice) < 2:
            break
        len_ = struct.unpack('<h', data_slice)[0]
        i += 2
        if len_ != 0 and 0 <= len_ * 2 <= len(data):
            try:
                l[counter] = data[i:i + len_ * 2].decode('utf-16')
            except UnicodeDecodeError:
                error_count += 1

            if error_count >= 3:
                break
            i += len_ * 2
        counter += 1


def retrieve_flags(flag_dict, flag_filter):
    """Read the flags from a dictionary and return them in a usable form.
    
    Will return a list of (flag, value) for all flags in "flag_dict"
    matching the filter "flag_filter".
    """
    return [ (f[0], f[1]) for f in flag_dict.items() if isinstance(f[0], str) and f[0].startswith(flag_filter) ]


def set_flags(obj, flag_field, flags):
    """Will process the flags and set attributes in the object accordingly.
    
    The object "obj" will gain attributes named after the flags provided in
    "flags" and valued True/False, matching the results of applying each
    flag value from "flags" to flag_field.
    """
    for flag in flags:
        if flag[1] & flag_field:
            obj.__dict__[flag[0]] = True
        else:
            obj.__dict__[flag[0]] = False


def power_of_two(val):
    return val != 0 and val & val - 1 == 0


FILE_ALIGNEMNT_HARDCODED_VALUE = 512
FileAlignment_Warning = False
SectionAlignment_Warning = False

class UnicodeStringWrapperPostProcessor:
    """This class attempts to help the process of identifying strings
    that might be plain Unicode or Pascal. A list of strings will be
    wrapped on it with the hope the overlappings will help make the
    decision about their type."""

    def __init__(self, pe, rva_ptr):
        self.pe = pe
        self.rva_ptr = rva_ptr
        self.string = None

    def get_rva(self):
        """Get the RVA of the string."""
        return self.rva_ptr

    def __str__(self):
        """Return the escaped ASCII representation of the string."""

        def convert_char(char):
            if char in string.printable:
                return char
            else:
                return '\\x%02x' % ord(char)

        if self.string:
            return ''.join([ convert_char(c) for c in self.string ])
        return ''

    def invalidate(self):
        """Make this instance None, to express it's no known string type."""
        self = None

    def render_pascal_16(self):
        self.string = self.pe.get_string_u_at_rva(self.rva_ptr + 2, max_length=self.__get_pascal_16_length())

    def ask_pascal_16(self, next_rva_ptr):
        """The next RVA is taken to be the one immediately following this one.
        
        Such RVA could indicate the natural end of the string and will be checked
        with the possible length contained in the first word.
        """
        length = self.__get_pascal_16_length()
        if length == (next_rva_ptr - (self.rva_ptr + 2)) / 2:
            self.length = length
            return True
        return False

    def __get_pascal_16_length(self):
        return self.__get_word_value_at_rva(self.rva_ptr)

    def __get_word_value_at_rva(self, rva):
        try:
            data = self.pe.get_data(self.rva_ptr, 2)
        except PEFormatError as e:
            return False

        if len(data) < 2:
            return False
        return struct.unpack('<H', data)[0]

    def ask_unicode_16(self, next_rva_ptr):
        """The next RVA is taken to be the one immediately following this one.
        
        Such RVA could indicate the natural end of the string and will be checked
        to see if there's a Unicode NULL character there.
        """
        if self.__get_word_value_at_rva(next_rva_ptr - 2) == 0:
            self.length = next_rva_ptr - self.rva_ptr
            return True
        return False

    def render_unicode_16(self):
        """"""
        self.string = self.pe.get_string_u_at_rva(self.rva_ptr)


class PEFormatError(Exception):
    """Generic PE format error exception."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Dump:
    """Convenience class for dumping the PE information."""

    def __init__(self):
        self.text = list()

    def add_lines(self, txt, indent = 0):
        """Adds a list of lines.
        
        The list can be indented with the optional argument 'indent'.
        """
        for line in txt:
            self.add_line(line, indent)

    def add_line(self, txt, indent = 0):
        """Adds a line.
        
        The line can be indented with the optional argument 'indent'.
        """
        self.add(txt + '\n', indent)

    def add(self, txt, indent = 0):
        """Adds some text, no newline will be appended.
        
        The text can be indented with the optional argument 'indent'.
        """
        if isinstance(txt, unicode):
            try:
                txt = str(txt)
            except UnicodeEncodeError:
                s = []
                for c in txt:
                    try:
                        s.append(str(c))
                    except UnicodeEncodeError:
                        s.append(repr(c))

                txt = ''.join(s)

        self.text.append(' ' * indent + txt)

    def add_header(self, txt):
        """Adds a header element."""
        self.add_line('----------' + txt + '----------' + '\n')

    def add_newline(self):
        """Adds a newline."""
        self.text.append('\n')

    def get_text(self):
        """Get the text in its current state."""
        return ''.join(self.text)


STRUCT_SIZEOF_TYPES = {'x': 1,
 'c': 1,
 'b': 1,
 'B': 1,
 'h': 2,
 'H': 2,
 'i': 4,
 'I': 4,
 'l': 4,
 'L': 4,
 'f': 4,
 'q': 8,
 'Q': 8,
 'd': 8,
 's': 1}

class Structure:
    """Prepare structure object to extract members from data.
    
    Format is a list containing definitions for the elements
    of the structure.
    """

    def __init__(self, format, name = None, file_offset = None):
        self.__format__ = '<'
        self.__keys__ = []
        self.__format_length__ = 0
        self.__field_offsets__ = dict()
        self.__set_format__(format[1])
        self.__all_zeroes__ = False
        self.__unpacked_data_elms__ = None
        self.__file_offset__ = file_offset
        if name:
            self.name = name
        else:
            self.name = format[0]

    def __get_format__(self):
        return self.__format__

    def get_field_absolute_offset(self, field_name):
        """Return the offset within the field for the requested field in the structure."""
        return self.__file_offset__ + self.__field_offsets__[field_name]

    def get_field_relative_offset(self, field_name):
        """Return the offset within the structure for the requested field."""
        return self.__field_offsets__[field_name]

    def get_file_offset(self):
        return self.__file_offset__

    def set_file_offset(self, offset):
        self.__file_offset__ = offset

    def all_zeroes(self):
        """Returns true is the unpacked data is all zeroes."""
        return self.__all_zeroes__

    def sizeof_type(self, t):
        count = 1
        _t = t
        if t[0] in string.digits:
            count = int(''.join([ d for d in t if d in string.digits ]))
            _t = ''.join([ d for d in t if d not in string.digits ])
        return STRUCT_SIZEOF_TYPES[_t] * count

    def __set_format__(self, format):
        offset = 0
        for elm in format:
            if ',' in elm:
                elm_type, elm_name = elm.split(',', 1)
                self.__format__ += elm_type
                elm_names = elm_name.split(',')
                names = []
                for elm_name in elm_names:
                    if elm_name in self.__keys__:
                        search_list = [ x[:len(elm_name)] for x in self.__keys__ ]
                        occ_count = search_list.count(elm_name)
                        elm_name = elm_name + '_' + str(occ_count)
                    names.append(elm_name)
                    self.__field_offsets__[elm_name] = offset

                offset += self.sizeof_type(elm_type)
                self.__keys__.append(names)

        self.__format_length__ = struct.calcsize(self.__format__)

    def sizeof(self):
        """Return size of the structure."""
        return self.__format_length__

    def __unpack__(self, data):
        if len(data) > self.__format_length__:
            data = data[:self.__format_length__]
        elif len(data) < self.__format_length__:
            raise PEFormatError('Data length less than expected header length.')
        if data.count(chr(0)) == len(data):
            self.__all_zeroes__ = True
        self.__unpacked_data_elms__ = struct.unpack(self.__format__, data)
        for i in xrange(len(self.__unpacked_data_elms__)):
            for key in self.__keys__[i]:
                setattr(self, key, self.__unpacked_data_elms__[i])

    def __pack__(self):
        new_values = []
        for i in xrange(len(self.__unpacked_data_elms__)):
            for key in self.__keys__[i]:
                new_val = getattr(self, key)
                old_val = self.__unpacked_data_elms__[i]
                if new_val != old_val:
                    break

            new_values.append(new_val)

        return struct.pack(self.__format__, *new_values)

    def __str__(self):
        return '\n'.join(self.dump())

    def __repr__(self):
        return '<Structure: %s>' % ' '.join([ ' '.join(s.split()) for s in self.dump() ])

    def dump(self, indentation = 0):
        """Returns a string representation of the structure."""
        dump = []
        dump.append('[%s]' % self.name)
        for keys in self.__keys__:
            for key in keys:
                val = getattr(self, key)
                if isinstance(val, int) or isinstance(val, long):
                    val_str = '0x%-8X' % val
                    if key == 'TimeDateStamp' or key == 'dwTimeStamp':
                        try:
                            val_str += ' [%s UTC]' % time.asctime(time.gmtime(val))
                        except exceptions.ValueError as e:
                            val_str += ' [INVALID TIME]'

                else:
                    val_str = ''.join(filter(lambda c: c != '\x00', str(val)))
                dump.append('0x%-8X 0x%-3X %-30s %s' % (self.__field_offsets__[key] + self.__file_offset__,
                 self.__field_offsets__[key],
                 key + ':',
                 val_str))

        return dump


class SectionStructure(Structure):
    """Convenience section handling class."""

    def __init__(self, *argl, **argd):
        if 'pe' in argd:
            self.pe = argd['pe']
            del argd['pe']
        Structure.__init__(self, *argl, **argd)

    def get_data(self, start = None, length = None):
        """Get data chunk from a section.
        
        Allows to query data from the section by passing the
        addresses where the PE file would be loaded by default.
        It is then possible to retrieve code and data by its real
        addresses as it would be if loaded.
        """
        PointerToRawData_adj = self.pe.adjust_FileAlignment(self.PointerToRawData, self.pe.OPTIONAL_HEADER.FileAlignment)
        VirtualAddress_adj = self.pe.adjust_SectionAlignment(self.VirtualAddress, self.pe.OPTIONAL_HEADER.SectionAlignment, self.pe.OPTIONAL_HEADER.FileAlignment)
        if start is None:
            offset = PointerToRawData_adj
        else:
            offset = start - VirtualAddress_adj + PointerToRawData_adj
        if length is not None:
            end = offset + length
        else:
            end = offset + self.SizeOfRawData
        if end > self.PointerToRawData + self.SizeOfRawData:
            end = self.PointerToRawData + self.SizeOfRawData
        return self.pe.__data__[offset:end]

    def __setattr__(self, name, val):
        if name == 'Characteristics':
            section_flags = retrieve_flags(SECTION_CHARACTERISTICS, 'IMAGE_SCN_')
            set_flags(self, val, section_flags)
        elif 'IMAGE_SCN_' in name and hasattr(self, name):
            if val:
                self.__dict__['Characteristics'] |= SECTION_CHARACTERISTICS[name]
            else:
                self.__dict__['Characteristics'] ^= SECTION_CHARACTERISTICS[name]
        self.__dict__[name] = val

    def get_rva_from_offset(self, offset):
        return offset - self.pe.adjust_FileAlignment(self.PointerToRawData, self.pe.OPTIONAL_HEADER.FileAlignment) + self.pe.adjust_SectionAlignment(self.VirtualAddress, self.pe.OPTIONAL_HEADER.SectionAlignment, self.pe.OPTIONAL_HEADER.FileAlignment)

    def get_offset_from_rva(self, rva):
        return rva - self.pe.adjust_SectionAlignment(self.VirtualAddress, self.pe.OPTIONAL_HEADER.SectionAlignment, self.pe.OPTIONAL_HEADER.FileAlignment) + self.pe.adjust_FileAlignment(self.PointerToRawData, self.pe.OPTIONAL_HEADER.FileAlignment)

    def contains_offset(self, offset):
        """Check whether the section contains the file offset provided."""
        if self.PointerToRawData is None:
            return False
        return self.pe.adjust_FileAlignment(self.PointerToRawData, self.pe.OPTIONAL_HEADER.FileAlignment) <= offset < self.pe.adjust_FileAlignment(self.PointerToRawData, self.pe.OPTIONAL_HEADER.FileAlignment) + self.SizeOfRawData

    def contains_rva(self, rva):
        """Check whether the section contains the address provided."""
        if len(self.pe.__data__) - self.pe.adjust_FileAlignment(self.PointerToRawData, self.pe.OPTIONAL_HEADER.FileAlignment) < self.SizeOfRawData:
            size = self.Misc_VirtualSize
        else:
            size = max(self.SizeOfRawData, self.Misc_VirtualSize)
        VirtualAddress_adj = self.pe.adjust_SectionAlignment(self.VirtualAddress, self.pe.OPTIONAL_HEADER.SectionAlignment, self.pe.OPTIONAL_HEADER.FileAlignment)
        return VirtualAddress_adj <= rva < VirtualAddress_adj + size

    def contains(self, rva):
        return self.contains_rva(rva)

    def get_entropy(self):
        """Calculate and return the entropy for the section."""
        return self.entropy_H(self.get_data())

    def get_hash_sha1(self):
        """Get the SHA-1 hex-digest of the section's data."""
        if sha1 is not None:
            return sha1(self.get_data()).hexdigest()

    def get_hash_sha256(self):
        """Get the SHA-256 hex-digest of the section's data."""
        if sha256 is not None:
            return sha256(self.get_data()).hexdigest()

    def get_hash_sha512(self):
        """Get the SHA-512 hex-digest of the section's data."""
        if sha512 is not None:
            return sha512(self.get_data()).hexdigest()

    def get_hash_md5(self):
        """Get the MD5 hex-digest of the section's data."""
        if md5 is not None:
            return md5(self.get_data()).hexdigest()

    def entropy_H(self, data):
        """Calculate the entropy of a chunk of data."""
        if len(data) == 0:
            return 0.0
        occurences = array.array('L', [0] * 256)
        for x in data:
            occurences[ord(x)] += 1

        entropy = 0
        for x in occurences:
            if x:
                p_x = float(x) / len(data)
                entropy -= p_x * math.log(p_x, 2)

        return entropy


class DataContainer:
    """Generic data container."""

    def __init__(self, **args):
        for key, value in args.items():
            setattr(self, key, value)


class ImportDescData(DataContainer):
    """Holds import descriptor information.
    
    dll:        name of the imported DLL
    imports:    list of imported symbols (ImportData instances)
    struct:     IMAGE_IMPORT_DESCRIPTOR structure
    """
    pass


class ImportData(DataContainer):
    """Holds imported symbol's information.
    
    ordinal:    Ordinal of the symbol
    name:       Name of the symbol
    bound:      If the symbol is bound, this contains
                the address.
    """

    def __setattr__(self, name, val):
        if hasattr(self, 'ordinal') and hasattr(self, 'bound') and hasattr(self, 'name'):
            if name == 'ordinal':
                if self.pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
                    ordinal_flag = IMAGE_ORDINAL_FLAG
                elif self.pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
                    ordinal_flag = IMAGE_ORDINAL_FLAG64
                self.struct_table.Ordinal = ordinal_flag | val & 65535
                self.struct_table.AddressOfData = self.struct_table.Ordinal
                self.struct_table.Function = self.struct_table.Ordinal
                self.struct_table.ForwarderString = self.struct_table.Ordinal
            elif name == 'bound':
                if self.struct_iat is not None:
                    self.struct_iat.AddressOfData = val
                    self.struct_iat.AddressOfData = self.struct_iat.AddressOfData
                    self.struct_iat.Function = self.struct_iat.AddressOfData
                    self.struct_iat.ForwarderString = self.struct_iat.AddressOfData
            elif name == 'address':
                self.struct_table.AddressOfData = val
                self.struct_table.Ordinal = self.struct_table.AddressOfData
                self.struct_table.Function = self.struct_table.AddressOfData
                self.struct_table.ForwarderString = self.struct_table.AddressOfData
            elif name == 'name':
                if self.name_offset:
                    name_rva = self.pe.get_rva_from_offset(self.name_offset)
                    self.pe.set_dword_at_offset(self.ordinal_offset, 0 | name_rva)
                    if len(val) > len(self.name):
                        pass
                    self.pe.set_bytes_at_offset(self.name_offset, val)
        self.__dict__[name] = val


class ExportDirData(DataContainer):
    """Holds export directory information.
        
        struct:     IMAGE_EXPORT_DIRECTORY structure
        symbols:    list of exported symbols (ExportData instances)
    """
    pass


class ExportData(DataContainer):
    """Holds exported symbols' information.
    
    ordinal:    ordinal of the symbol
    address:    address of the symbol
    name:       name of the symbol (None if the symbol is
                exported by ordinal only)
    forwarder:  if the symbol is forwarded it will
                contain the name of the target symbol,
                None otherwise.
    """

    def __setattr__(self, name, val):
        if hasattr(self, 'ordinal') and hasattr(self, 'address') and hasattr(self, 'forwarder') and hasattr(self, 'name'):
            if name == 'ordinal':
                self.pe.set_word_at_offset(self.ordinal_offset, val)
            elif name == 'address':
                self.pe.set_dword_at_offset(self.address_offset, val)
            elif name == 'name':
                if len(val) > len(self.name):
                    pass
                self.pe.set_bytes_at_offset(self.name_offset, val)
            elif name == 'forwarder':
                if len(val) > len(self.forwarder):
                    pass
                self.pe.set_bytes_at_offset(self.forwarder_offset, val)
        self.__dict__[name] = val


class ResourceDirData(DataContainer):
    """Holds resource directory information.
    
    struct:     IMAGE_RESOURCE_DIRECTORY structure
    entries:    list of entries (ResourceDirEntryData instances)
    """
    pass


class ResourceDirEntryData(DataContainer):
    """Holds resource directory entry data.
    
    struct:     IMAGE_RESOURCE_DIRECTORY_ENTRY structure
    name:       If the resource is identified by name this
                attribute will contain the name string. None
                otherwise. If identified by id, the id is
                available at 'struct.Id'
    id:         the id, also in struct.Id
    directory:  If this entry has a lower level directory
                this attribute will point to the
                ResourceDirData instance representing it.
    data:       If this entry has no further lower directories
                and points to the actual resource data, this
                attribute will reference the corresponding
                ResourceDataEntryData instance.
    (Either of the 'directory' or 'data' attribute will exist,
    but not both.)
    """
    pass


class ResourceDataEntryData(DataContainer):
    """Holds resource data entry information.
    
    struct:     IMAGE_RESOURCE_DATA_ENTRY structure
    lang:       Primary language ID
    sublang:    Sublanguage ID
    """
    pass


class DebugData(DataContainer):
    """Holds debug information.
    
    struct:     IMAGE_DEBUG_DIRECTORY structure
    """
    pass


class BaseRelocationData(DataContainer):
    """Holds base relocation information.
    
    struct:     IMAGE_BASE_RELOCATION structure
    entries:    list of relocation data (RelocationData instances)
    """
    pass


class RelocationData(DataContainer):
    """Holds relocation information.
    
    type:       Type of relocation
                The type string is can be obtained by
                RELOCATION_TYPE[type]
    rva:        RVA of the relocation
    """

    def __setattr__(self, name, val):
        if hasattr(self, 'struct'):
            word = self.struct.Data
            if name == 'type':
                word = val << 12 | word & 4095
            elif name == 'rva':
                offset = val - self.base_rva
                if offset < 0:
                    offset = 0
                word = word & 61440 | offset & 4095
            self.struct.Data = word
        self.__dict__[name] = val


class TlsData(DataContainer):
    """Holds TLS information.
    
    struct:     IMAGE_TLS_DIRECTORY structure
    """
    pass


class BoundImportDescData(DataContainer):
    """Holds bound import descriptor data.
    
    This directory entry will provide with information on the
    DLLs this PE files has been bound to (if bound at all).
    The structure will contain the name and timestamp of the
    DLL at the time of binding so that the loader can know
    whether it differs from the one currently present in the
    system and must, therefore, re-bind the PE's imports.
    
    struct:     IMAGE_BOUND_IMPORT_DESCRIPTOR structure
    name:       DLL name
    entries:    list of entries (BoundImportRefData instances)
                the entries will exist if this DLL has forwarded
                symbols. If so, the destination DLL will have an
                entry in this list.
    """
    pass


class LoadConfigData(DataContainer):
    """Holds Load Config data.
    
    struct:     IMAGE_LOAD_CONFIG_DIRECTORY structure
    name:       dll name
    """
    pass


class BoundImportRefData(DataContainer):
    """Holds bound import forwarder reference data.
    
    Contains the same information as the bound descriptor but
    for forwarded DLLs, if any.
    
    struct:     IMAGE_BOUND_FORWARDER_REF structure
    name:       dll name
    """
    pass


allowed_filename = string.lowercase + string.uppercase + string.digits + "!#$%&'()-@^_`{}~+,.;=[]" + ''.join([ chr(i) for i in range(128, 256) ])

def is_valid_dos_filename(s):
    if s is None or not isinstance(s, str):
        return False
    for c in s:
        if c not in allowed_filename:
            return False

    return True


allowed_function_name = string.lowercase + string.uppercase + string.digits + '_?@$()'

def is_valid_function_name(s):
    if s is None or not isinstance(s, str):
        return False
    for c in s:
        if c not in allowed_function_name:
            return False

    return True


class PE:
    """A Portable Executable representation.
    
    This class provides access to most of the information in a PE file.
    
    It expects to be supplied the name of the file to load or PE data
    to process and an optional argument 'fast_load' (False by default)
    which controls whether to load all the directories information,
    which can be quite time consuming.
    
    pe = pefile.PE('module.dll')
    pe = pefile.PE(name='module.dll')
    
    would load 'module.dll' and process it. If the data would be already
    available in a buffer the same could be achieved with:
    
    pe = pefile.PE(data=module_dll_data)
    
    The "fast_load" can be set to a default by setting its value in the
    module itself by means,for instance, of a "pefile.fast_load = True".
    That will make all the subsequent instances not to load the
    whole PE structure. The "full_load" method can be used to parse
    the missing data at a later stage.
    
    Basic headers information will be available in the attributes:
    
    DOS_HEADER
    NT_HEADERS
    FILE_HEADER
    OPTIONAL_HEADER
    
    All of them will contain among their attributes the members of the
    corresponding structures as defined in WINNT.H
    
    The raw data corresponding to the header (from the beginning of the
    file up to the start of the first section) will be available in the
    instance's attribute 'header' as a string.
    
    The sections will be available as a list in the 'sections' attribute.
    Each entry will contain as attributes all the structure's members.
    
    Directory entries will be available as attributes (if they exist):
    (no other entries are processed at this point)
    
    DIRECTORY_ENTRY_IMPORT (list of ImportDescData instances)
    DIRECTORY_ENTRY_EXPORT (ExportDirData instance)
    DIRECTORY_ENTRY_RESOURCE (ResourceDirData instance)
    DIRECTORY_ENTRY_DEBUG (list of DebugData instances)
    DIRECTORY_ENTRY_BASERELOC (list of BaseRelocationData instances)
    DIRECTORY_ENTRY_TLS
    DIRECTORY_ENTRY_BOUND_IMPORT (list of BoundImportData instances)
    
    The following dictionary attributes provide ways of mapping different
    constants. They will accept the numeric value and return the string
    representation and the opposite, feed in the string and get the
    numeric constant:
    
    DIRECTORY_ENTRY
    IMAGE_CHARACTERISTICS
    SECTION_CHARACTERISTICS
    DEBUG_TYPE
    SUBSYSTEM_TYPE
    MACHINE_TYPE
    RELOCATION_TYPE
    RESOURCE_TYPE
    LANG
    SUBLANG
    """
    __IMAGE_DOS_HEADER_format__ = ('IMAGE_DOS_HEADER', ('H,e_magic',
      'H,e_cblp',
      'H,e_cp',
      'H,e_crlc',
      'H,e_cparhdr',
      'H,e_minalloc',
      'H,e_maxalloc',
      'H,e_ss',
      'H,e_sp',
      'H,e_csum',
      'H,e_ip',
      'H,e_cs',
      'H,e_lfarlc',
      'H,e_ovno',
      '8s,e_res',
      'H,e_oemid',
      'H,e_oeminfo',
      '20s,e_res2',
      'I,e_lfanew'))
    __IMAGE_FILE_HEADER_format__ = ('IMAGE_FILE_HEADER', ('H,Machine',
      'H,NumberOfSections',
      'I,TimeDateStamp',
      'I,PointerToSymbolTable',
      'I,NumberOfSymbols',
      'H,SizeOfOptionalHeader',
      'H,Characteristics'))
    __IMAGE_DATA_DIRECTORY_format__ = ('IMAGE_DATA_DIRECTORY', ('I,VirtualAddress', 'I,Size'))
    __IMAGE_OPTIONAL_HEADER_format__ = ('IMAGE_OPTIONAL_HEADER', ('H,Magic',
      'B,MajorLinkerVersion',
      'B,MinorLinkerVersion',
      'I,SizeOfCode',
      'I,SizeOfInitializedData',
      'I,SizeOfUninitializedData',
      'I,AddressOfEntryPoint',
      'I,BaseOfCode',
      'I,BaseOfData',
      'I,ImageBase',
      'I,SectionAlignment',
      'I,FileAlignment',
      'H,MajorOperatingSystemVersion',
      'H,MinorOperatingSystemVersion',
      'H,MajorImageVersion',
      'H,MinorImageVersion',
      'H,MajorSubsystemVersion',
      'H,MinorSubsystemVersion',
      'I,Reserved1',
      'I,SizeOfImage',
      'I,SizeOfHeaders',
      'I,CheckSum',
      'H,Subsystem',
      'H,DllCharacteristics',
      'I,SizeOfStackReserve',
      'I,SizeOfStackCommit',
      'I,SizeOfHeapReserve',
      'I,SizeOfHeapCommit',
      'I,LoaderFlags',
      'I,NumberOfRvaAndSizes'))
    __IMAGE_OPTIONAL_HEADER64_format__ = ('IMAGE_OPTIONAL_HEADER64', ('H,Magic',
      'B,MajorLinkerVersion',
      'B,MinorLinkerVersion',
      'I,SizeOfCode',
      'I,SizeOfInitializedData',
      'I,SizeOfUninitializedData',
      'I,AddressOfEntryPoint',
      'I,BaseOfCode',
      'Q,ImageBase',
      'I,SectionAlignment',
      'I,FileAlignment',
      'H,MajorOperatingSystemVersion',
      'H,MinorOperatingSystemVersion',
      'H,MajorImageVersion',
      'H,MinorImageVersion',
      'H,MajorSubsystemVersion',
      'H,MinorSubsystemVersion',
      'I,Reserved1',
      'I,SizeOfImage',
      'I,SizeOfHeaders',
      'I,CheckSum',
      'H,Subsystem',
      'H,DllCharacteristics',
      'Q,SizeOfStackReserve',
      'Q,SizeOfStackCommit',
      'Q,SizeOfHeapReserve',
      'Q,SizeOfHeapCommit',
      'I,LoaderFlags',
      'I,NumberOfRvaAndSizes'))
    __IMAGE_NT_HEADERS_format__ = ('IMAGE_NT_HEADERS', ('I,Signature',))
    __IMAGE_SECTION_HEADER_format__ = ('IMAGE_SECTION_HEADER', ('8s,Name',
      'I,Misc,Misc_PhysicalAddress,Misc_VirtualSize',
      'I,VirtualAddress',
      'I,SizeOfRawData',
      'I,PointerToRawData',
      'I,PointerToRelocations',
      'I,PointerToLinenumbers',
      'H,NumberOfRelocations',
      'H,NumberOfLinenumbers',
      'I,Characteristics'))
    __IMAGE_DELAY_IMPORT_DESCRIPTOR_format__ = ('IMAGE_DELAY_IMPORT_DESCRIPTOR', ('I,grAttrs',
      'I,szName',
      'I,phmod',
      'I,pIAT',
      'I,pINT',
      'I,pBoundIAT',
      'I,pUnloadIAT',
      'I,dwTimeStamp'))
    __IMAGE_IMPORT_DESCRIPTOR_format__ = ('IMAGE_IMPORT_DESCRIPTOR', ('I,OriginalFirstThunk,Characteristics',
      'I,TimeDateStamp',
      'I,ForwarderChain',
      'I,Name',
      'I,FirstThunk'))
    __IMAGE_EXPORT_DIRECTORY_format__ = ('IMAGE_EXPORT_DIRECTORY', ('I,Characteristics',
      'I,TimeDateStamp',
      'H,MajorVersion',
      'H,MinorVersion',
      'I,Name',
      'I,Base',
      'I,NumberOfFunctions',
      'I,NumberOfNames',
      'I,AddressOfFunctions',
      'I,AddressOfNames',
      'I,AddressOfNameOrdinals'))
    __IMAGE_RESOURCE_DIRECTORY_format__ = ('IMAGE_RESOURCE_DIRECTORY', ('I,Characteristics',
      'I,TimeDateStamp',
      'H,MajorVersion',
      'H,MinorVersion',
      'H,NumberOfNamedEntries',
      'H,NumberOfIdEntries'))
    __IMAGE_RESOURCE_DIRECTORY_ENTRY_format__ = ('IMAGE_RESOURCE_DIRECTORY_ENTRY', ('I,Name', 'I,OffsetToData'))
    __IMAGE_RESOURCE_DATA_ENTRY_format__ = ('IMAGE_RESOURCE_DATA_ENTRY', ('I,OffsetToData',
      'I,Size',
      'I,CodePage',
      'I,Reserved'))
    __VS_VERSIONINFO_format__ = ('VS_VERSIONINFO', ('H,Length', 'H,ValueLength', 'H,Type'))
    __VS_FIXEDFILEINFO_format__ = ('VS_FIXEDFILEINFO', ('I,Signature',
      'I,StrucVersion',
      'I,FileVersionMS',
      'I,FileVersionLS',
      'I,ProductVersionMS',
      'I,ProductVersionLS',
      'I,FileFlagsMask',
      'I,FileFlags',
      'I,FileOS',
      'I,FileType',
      'I,FileSubtype',
      'I,FileDateMS',
      'I,FileDateLS'))
    __StringFileInfo_format__ = ('StringFileInfo', ('H,Length', 'H,ValueLength', 'H,Type'))
    __StringTable_format__ = ('StringTable', ('H,Length', 'H,ValueLength', 'H,Type'))
    __String_format__ = ('String', ('H,Length', 'H,ValueLength', 'H,Type'))
    __Var_format__ = ('Var', ('H,Length', 'H,ValueLength', 'H,Type'))
    __IMAGE_THUNK_DATA_format__ = ('IMAGE_THUNK_DATA', ('I,ForwarderString,Function,Ordinal,AddressOfData',))
    __IMAGE_THUNK_DATA64_format__ = ('IMAGE_THUNK_DATA', ('Q,ForwarderString,Function,Ordinal,AddressOfData',))
    __IMAGE_DEBUG_DIRECTORY_format__ = ('IMAGE_DEBUG_DIRECTORY', ('I,Characteristics',
      'I,TimeDateStamp',
      'H,MajorVersion',
      'H,MinorVersion',
      'I,Type',
      'I,SizeOfData',
      'I,AddressOfRawData',
      'I,PointerToRawData'))
    __IMAGE_BASE_RELOCATION_format__ = ('IMAGE_BASE_RELOCATION', ('I,VirtualAddress', 'I,SizeOfBlock'))
    __IMAGE_BASE_RELOCATION_ENTRY_format__ = ('IMAGE_BASE_RELOCATION_ENTRY', ('H,Data',))
    __IMAGE_TLS_DIRECTORY_format__ = ('IMAGE_TLS_DIRECTORY', ('I,StartAddressOfRawData',
      'I,EndAddressOfRawData',
      'I,AddressOfIndex',
      'I,AddressOfCallBacks',
      'I,SizeOfZeroFill',
      'I,Characteristics'))
    __IMAGE_TLS_DIRECTORY64_format__ = ('IMAGE_TLS_DIRECTORY', ('Q,StartAddressOfRawData',
      'Q,EndAddressOfRawData',
      'Q,AddressOfIndex',
      'Q,AddressOfCallBacks',
      'I,SizeOfZeroFill',
      'I,Characteristics'))
    __IMAGE_LOAD_CONFIG_DIRECTORY_format__ = ('IMAGE_LOAD_CONFIG_DIRECTORY', ('I,Size',
      'I,TimeDateStamp',
      'H,MajorVersion',
      'H,MinorVersion',
      'I,GlobalFlagsClear',
      'I,GlobalFlagsSet',
      'I,CriticalSectionDefaultTimeout',
      'I,DeCommitFreeBlockThreshold',
      'I,DeCommitTotalFreeThreshold',
      'I,LockPrefixTable',
      'I,MaximumAllocationSize',
      'I,VirtualMemoryThreshold',
      'I,ProcessHeapFlags',
      'I,ProcessAffinityMask',
      'H,CSDVersion',
      'H,Reserved1',
      'I,EditList',
      'I,SecurityCookie',
      'I,SEHandlerTable',
      'I,SEHandlerCount'))
    __IMAGE_LOAD_CONFIG_DIRECTORY64_format__ = ('IMAGE_LOAD_CONFIG_DIRECTORY', ('I,Size',
      'I,TimeDateStamp',
      'H,MajorVersion',
      'H,MinorVersion',
      'I,GlobalFlagsClear',
      'I,GlobalFlagsSet',
      'I,CriticalSectionDefaultTimeout',
      'Q,DeCommitFreeBlockThreshold',
      'Q,DeCommitTotalFreeThreshold',
      'Q,LockPrefixTable',
      'Q,MaximumAllocationSize',
      'Q,VirtualMemoryThreshold',
      'Q,ProcessAffinityMask',
      'I,ProcessHeapFlags',
      'H,CSDVersion',
      'H,Reserved1',
      'Q,EditList',
      'Q,SecurityCookie',
      'Q,SEHandlerTable',
      'Q,SEHandlerCount'))
    __IMAGE_BOUND_IMPORT_DESCRIPTOR_format__ = ('IMAGE_BOUND_IMPORT_DESCRIPTOR', ('I,TimeDateStamp', 'H,OffsetModuleName', 'H,NumberOfModuleForwarderRefs'))
    __IMAGE_BOUND_FORWARDER_REF_format__ = ('IMAGE_BOUND_FORWARDER_REF', ('I,TimeDateStamp', 'H,OffsetModuleName', 'H,Reserved'))

    def __init__(self, name = None, data = None, fast_load = None):
        self.sections = []
        self.__warnings = []
        self.PE_TYPE = None
        if not name and not data:
            return
        self.__structures__ = []
        self.__from_file = None
        if not fast_load:
            fast_load = globals()['fast_load']
        try:
            self.__parse__(name, data, fast_load)
        except:
            self.close()
            raise

    def close(self):
        if self.__from_file is True and hasattr(self, '__data__') and (isinstance(mmap.mmap, type) and isinstance(self.__data__, mmap.mmap) or 'mmap.mmap' in repr(type(self.__data__))):
            self.__data__.close()

    def __unpack_data__(self, format, data, file_offset):
        """Apply structure format to raw data.
        
        Returns and unpacked structure object if successful, None otherwise.
        """
        structure = Structure(format, file_offset=file_offset)
        try:
            structure.__unpack__(data)
        except PEFormatError as err:
            self.__warnings.append('Corrupt header "%s" at file offset %d. Exception: %s' % (format[0], file_offset, str(err)))
            return None

        self.__structures__.append(structure)
        return structure

    def __parse__(self, fname, data, fast_load):
        """Parse a Portable Executable file.
        
        Loads a PE file, parsing all its structures and making them available
        through the instance's attributes.
        """
        if fname:
            stat = os.stat(fname)
            if stat.st_size == 0:
                raise PEFormatError('The file is empty')
            try:
                fd = file(fname, 'rb')
                self.fileno = fd.fileno()
                self.__data__ = mmap.mmap(self.fileno, 0, access=mmap.ACCESS_READ)
                self.__from_file = True
            finally:
                fd.close()

        elif data:
            self.__data__ = data
            self.__from_file = False
        dos_header_data = self.__data__[:64]
        if len(dos_header_data) != 64:
            raise PEFormatError('Unable to read the DOS Header, possibly a truncated file.')
        self.DOS_HEADER = self.__unpack_data__(self.__IMAGE_DOS_HEADER_format__, dos_header_data, file_offset=0)
        if self.DOS_HEADER.e_magic == IMAGE_DOSZM_SIGNATURE:
            raise PEFormatError('Probably a ZM Executable (not a PE file).')
        if not self.DOS_HEADER or self.DOS_HEADER.e_magic != IMAGE_DOS_SIGNATURE:
            raise PEFormatError('DOS Header magic not found.')
        if self.DOS_HEADER.e_lfanew > len(self.__data__):
            raise PEFormatError('Invalid e_lfanew value, probably not a PE file')
        nt_headers_offset = self.DOS_HEADER.e_lfanew
        self.NT_HEADERS = self.__unpack_data__(self.__IMAGE_NT_HEADERS_format__, self.__data__[nt_headers_offset:nt_headers_offset + 8], file_offset=nt_headers_offset)
        if not self.NT_HEADERS or not self.NT_HEADERS.Signature:
            raise PEFormatError('NT Headers not found.')
        if 65535 & self.NT_HEADERS.Signature == IMAGE_NE_SIGNATURE:
            raise PEFormatError('Invalid NT Headers signature. Probably a NE file')
        if 65535 & self.NT_HEADERS.Signature == IMAGE_LE_SIGNATURE:
            raise PEFormatError('Invalid NT Headers signature. Probably a LE file')
        if 65535 & self.NT_HEADERS.Signature == IMAGE_LX_SIGNATURE:
            raise PEFormatError('Invalid NT Headers signature. Probably a LX file')
        if self.NT_HEADERS.Signature != IMAGE_NT_SIGNATURE:
            raise PEFormatError('Invalid NT Headers signature.')
        self.FILE_HEADER = self.__unpack_data__(self.__IMAGE_FILE_HEADER_format__, self.__data__[nt_headers_offset + 4:nt_headers_offset + 4 + 32], file_offset=nt_headers_offset + 4)
        image_flags = retrieve_flags(IMAGE_CHARACTERISTICS, 'IMAGE_FILE_')
        if not self.FILE_HEADER:
            raise PEFormatError('File Header missing')
        set_flags(self.FILE_HEADER, self.FILE_HEADER.Characteristics, image_flags)
        optional_header_offset = nt_headers_offset + 4 + self.FILE_HEADER.sizeof()
        sections_offset = optional_header_offset + self.FILE_HEADER.SizeOfOptionalHeader
        self.OPTIONAL_HEADER = self.__unpack_data__(self.__IMAGE_OPTIONAL_HEADER_format__, self.__data__[optional_header_offset:], file_offset=optional_header_offset)
        MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE = 69
        if self.OPTIONAL_HEADER is None and len(self.__data__[optional_header_offset:optional_header_offset + 512]) >= MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE:
            padding_length = 128
            padded_data = self.__data__[optional_header_offset:optional_header_offset + 512] + '\x00' * padding_length
            self.OPTIONAL_HEADER = self.__unpack_data__(self.__IMAGE_OPTIONAL_HEADER_format__, padded_data, file_offset=optional_header_offset)
        if self.OPTIONAL_HEADER is not None:
            if self.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE:
                self.PE_TYPE = OPTIONAL_HEADER_MAGIC_PE
            elif self.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE_PLUS:
                self.PE_TYPE = OPTIONAL_HEADER_MAGIC_PE_PLUS
                self.OPTIONAL_HEADER = self.__unpack_data__(self.__IMAGE_OPTIONAL_HEADER64_format__, self.__data__[optional_header_offset:optional_header_offset + 512], file_offset=optional_header_offset)
                MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE = 73
                if self.OPTIONAL_HEADER is None and len(self.__data__[optional_header_offset:optional_header_offset + 512]) >= MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE:
                    padding_length = 128
                    padded_data = self.__data__[optional_header_offset:optional_header_offset + 512] + '\x00' * padding_length
                    self.OPTIONAL_HEADER = self.__unpack_data__(self.__IMAGE_OPTIONAL_HEADER64_format__, padded_data, file_offset=optional_header_offset)
        if not self.FILE_HEADER:
            raise PEFormatError('File Header missing')
        if self.PE_TYPE is None or self.OPTIONAL_HEADER is None:
            raise PEFormatError('No Optional Header found, invalid PE32 or PE32+ file')
        dll_characteristics_flags = retrieve_flags(DLL_CHARACTERISTICS, 'IMAGE_DLL_CHARACTERISTICS_')
        set_flags(self.OPTIONAL_HEADER, self.OPTIONAL_HEADER.DllCharacteristics, dll_characteristics_flags)
        self.OPTIONAL_HEADER.DATA_DIRECTORY = []
        offset = optional_header_offset + self.OPTIONAL_HEADER.sizeof()
        self.NT_HEADERS.FILE_HEADER = self.FILE_HEADER
        self.NT_HEADERS.OPTIONAL_HEADER = self.OPTIONAL_HEADER
        if self.OPTIONAL_HEADER.NumberOfRvaAndSizes > 16:
            self.__warnings.append('Suspicious NumberOfRvaAndSizes in the Optional Header. ' + 'Normal values are never larger than 0x10, the value is: 0x%x' % self.OPTIONAL_HEADER.NumberOfRvaAndSizes)
        MAX_ASSUMED_VALID_NUMBER_OF_RVA_AND_SIZES = 256
        for i in xrange(int(2147483647L & self.OPTIONAL_HEADER.NumberOfRvaAndSizes)):
            if len(self.__data__) - offset == 0:
                break
            if len(self.__data__) - offset < 8:
                data = self.__data__[offset:] + '\x00\x00\x00\x00\x00\x00\x00\x00'
            else:
                data = self.__data__[offset:offset + MAX_ASSUMED_VALID_NUMBER_OF_RVA_AND_SIZES]
            dir_entry = self.__unpack_data__(self.__IMAGE_DATA_DIRECTORY_format__, data, file_offset=offset)
            if dir_entry is None:
                break
            try:
                dir_entry.name = DIRECTORY_ENTRY[i]
            except (KeyError, AttributeError):
                break

            offset += dir_entry.sizeof()
            self.OPTIONAL_HEADER.DATA_DIRECTORY.append(dir_entry)
            if offset >= optional_header_offset + self.OPTIONAL_HEADER.sizeof() + 128:
                break

        offset = self.parse_sections(sections_offset)
        rawDataPointers = [ self.adjust_FileAlignment(s.PointerToRawData, self.OPTIONAL_HEADER.FileAlignment) for s in self.sections if s.PointerToRawData > 0 ]
        if len(rawDataPointers) > 0:
            lowest_section_offset = min(rawDataPointers)
        else:
            lowest_section_offset = None
        if not lowest_section_offset or lowest_section_offset < offset:
            self.header = self.__data__[:offset]
        else:
            self.header = self.__data__[:lowest_section_offset]
        if self.get_section_by_rva(self.OPTIONAL_HEADER.AddressOfEntryPoint) is not None:
            ep_offset = self.get_offset_from_rva(self.OPTIONAL_HEADER.AddressOfEntryPoint)
            if ep_offset > len(self.__data__):
                self.__warnings.append('Possibly corrupt file. AddressOfEntryPoint lies outside the file. ' + 'AddressOfEntryPoint: 0x%x' % self.OPTIONAL_HEADER.AddressOfEntryPoint)
        else:
            self.__warnings.append("AddressOfEntryPoint lies outside the sections' boundaries. " + 'AddressOfEntryPoint: 0x%x' % self.OPTIONAL_HEADER.AddressOfEntryPoint)
        if not fast_load:
            self.parse_data_directories()

            class RichHeader:
                pass

            rich_header = self.parse_rich_header()
            if rich_header:
                self.RICH_HEADER = RichHeader()
                self.RICH_HEADER.checksum = rich_header.get('checksum', None)
                self.RICH_HEADER.values = rich_header.get('values', None)
            else:
                self.RICH_HEADER = None

    def parse_rich_header(self):
        """Parses the rich header
        see http://www.ntcore.com/files/richsign.htm for more information
        
        Structure:
        00 DanS ^ checksum, checksum, checksum, checksum
        10 Symbol RVA ^ checksum, Symbol size ^ checksum...
        ...
        XX Rich, checksum, 0, 0,...
        """
        DANS = 1399742788
        RICH = 1751345490
        try:
            data = list(struct.unpack('<32I', self.get_data(128, 128)))
        except:
            return None

        checksum = data[1]
        if data[0] ^ checksum != DANS or data[2] != checksum or data[3] != checksum:
            return None
        result = {'checksum': checksum}
        headervalues = []
        result['values'] = headervalues
        data = data[4:]
        for i in xrange(len(data) / 2):
            if data[2 * i] == RICH:
                if data[2 * i + 1] != checksum:
                    self.__warnings.append('Rich Header corrupted')
                break
            headervalues += [data[2 * i] ^ checksum, data[2 * i + 1] ^ checksum]

        return result

    def get_warnings(self):
        """Return the list of warnings.
        
        Non-critical problems found when parsing the PE file are
        appended to a list of warnings. This method returns the
        full list.
        """
        return self.__warnings

    def show_warnings(self):
        """Print the list of warnings.
        
        Non-critical problems found when parsing the PE file are
        appended to a list of warnings. This method prints the
        full list to standard output.
        """
        for warning in self.__warnings:
            print '>', warning

    def full_load(self):
        """Process the data directories.
        
        This method will load the data directories which might not have
        been loaded if the "fast_load" option was used.
        """
        self.parse_data_directories()

    def write(self, filename = None):
        """Write the PE file.
        
        This function will process all headers and components
        of the PE file and include all changes made (by just
        assigning to attributes in the PE objects) and write
        the changes back to a file whose name is provided as
        an argument. The filename is optional, if not 
        provided the data will be returned as a 'str' object.
        """
        file_data = list(self.__data__)
        for structure in self.__structures__:
            struct_data = list(structure.__pack__())
            offset = structure.get_file_offset()
            file_data[offset:offset + len(struct_data)] = struct_data

        if hasattr(self, 'VS_VERSIONINFO'):
            if hasattr(self, 'FileInfo'):
                for entry in self.FileInfo:
                    if hasattr(entry, 'StringTable'):
                        for st_entry in entry.StringTable:
                            for key, entry in st_entry.entries.items():
                                offsets = st_entry.entries_offsets[key]
                                lengths = st_entry.entries_lengths[key]
                                if len(entry) > lengths[1]:
                                    l = list()
                                    for idx, c in enumerate(entry):
                                        if ord(c) > 256:
                                            l.extend([chr(ord(c) & 255), chr((ord(c) & 65280) >> 8)])
                                        else:
                                            l.extend([chr(ord(c)), '\x00'])

                                    file_data[offsets[1]:offsets[1] + lengths[1] * 2] = l
                                else:
                                    l = list()
                                    for idx, c in enumerate(entry):
                                        if ord(c) > 256:
                                            l.extend([chr(ord(c) & 255), chr((ord(c) & 65280) >> 8)])
                                        else:
                                            l.extend([chr(ord(c)), '\x00'])

                                    file_data[offsets[1]:offsets[1] + len(entry) * 2] = l
                                    remainder = lengths[1] - len(entry)
                                    file_data[offsets[1] + len(entry) * 2:offsets[1] + lengths[1] * 2] = [u'\x00'] * remainder * 2

        new_file_data = ''.join([ chr(ord(c)) for c in file_data ])
        if filename:
            f = file(filename, 'wb+')
            f.write(new_file_data)
            f.close()
        else:
            return new_file_data

    def parse_sections(self, offset):
        """Fetch the PE file sections.
        
        The sections will be readily available in the "sections" attribute.
        Its attributes will contain all the section information plus "data"
        a buffer containing the section's data.
        
        The "Characteristics" member will be processed and attributes
        representing the section characteristics (with the 'IMAGE_SCN_'
        string trimmed from the constant's names) will be added to the
        section instance.
        
        Refer to the SectionStructure class for additional info.
        """
        self.sections = []
        for i in xrange(self.FILE_HEADER.NumberOfSections):
            section = SectionStructure(self.__IMAGE_SECTION_HEADER_format__, pe=self)
            if not section:
                break
            section_offset = offset + section.sizeof() * i
            section.set_file_offset(section_offset)
            section.__unpack__(self.__data__[section_offset:section_offset + section.sizeof()])
            self.__structures__.append(section)
            if section.SizeOfRawData > len(self.__data__):
                self.__warnings.append('Error parsing section %d. ' % i + 'SizeOfRawData is larger than file.')
            if self.adjust_FileAlignment(section.PointerToRawData, self.OPTIONAL_HEADER.FileAlignment) > len(self.__data__):
                self.__warnings.append('Error parsing section %d. ' % i + 'PointerToRawData points beyond the end of the file.')
            if section.Misc_VirtualSize > 268435456:
                self.__warnings.append('Suspicious value found parsing section %d. ' % i + 'VirtualSize is extremely large > 256MiB.')
            if self.adjust_SectionAlignment(section.VirtualAddress, self.OPTIONAL_HEADER.SectionAlignment, self.OPTIONAL_HEADER.FileAlignment) > 268435456:
                self.__warnings.append('Suspicious value found parsing section %d. ' % i + 'VirtualAddress is beyond 0x10000000.')
            if self.OPTIONAL_HEADER.FileAlignment != 0 and section.PointerToRawData % self.OPTIONAL_HEADER.FileAlignment != 0:
                self.__warnings.append('Error parsing section %d. ' % i + 'PointerToRawData should normally be ' + 'a multiple of FileAlignment, this might imply the file ' + 'is trying to confuse tools which parse this incorrectly')
            section_flags = retrieve_flags(SECTION_CHARACTERISTICS, 'IMAGE_SCN_')
            set_flags(section, section.Characteristics, section_flags)
            if section.__dict__.get('IMAGE_SCN_MEM_WRITE', False) and section.__dict__.get('IMAGE_SCN_MEM_EXECUTE', False):
                if section.Name == 'PAGE' and self.is_driver():
                    pass
                else:
                    self.__warnings.append('Suspicious flags set for section %d. ' % i + 'Both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE are set. ' + 'This might indicate a packed executable.')
            self.sections.append(section)

        if self.FILE_HEADER.NumberOfSections > 0 and self.sections:
            return offset + self.sections[0].sizeof() * self.FILE_HEADER.NumberOfSections
        else:
            return offset

    def parse_data_directories(self, directories = None):
        """Parse and process the PE file's data directories.
        
        If the optional argument 'directories' is given, only
        the directories at the specified indices will be parsed.
        Such functionality allows parsing of areas of interest
        without the burden of having to parse all others.
        The directories can then be specified as:
        
        For export/import only:
        
          directories = [ 0, 1 ]
          
        or (more verbosely):
        
          directories = [ DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'], 
            DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'] ]
            
        If 'directories' is a list, the ones that are processed will be removed,
        leaving only the ones that are not present in the image.
        """
        directory_parsing = (('IMAGE_DIRECTORY_ENTRY_IMPORT', self.parse_import_directory),
         ('IMAGE_DIRECTORY_ENTRY_EXPORT', self.parse_export_directory),
         ('IMAGE_DIRECTORY_ENTRY_RESOURCE', self.parse_resources_directory),
         ('IMAGE_DIRECTORY_ENTRY_DEBUG', self.parse_debug_directory),
         ('IMAGE_DIRECTORY_ENTRY_BASERELOC', self.parse_relocations_directory),
         ('IMAGE_DIRECTORY_ENTRY_TLS', self.parse_directory_tls),
         ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG', self.parse_directory_load_config),
         ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT', self.parse_delay_import_directory),
         ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT', self.parse_directory_bound_imports))
        if directories is not None:
            if not isinstance(directories, (tuple, list)):
                directories = [directories]
        for entry in directory_parsing:
            try:
                directory_index = DIRECTORY_ENTRY[entry[0]]
                dir_entry = self.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index]
            except IndexError:
                break

            if directories is None or directory_index in directories:
                if dir_entry.VirtualAddress:
                    value = entry[1](dir_entry.VirtualAddress, dir_entry.Size)
                    if value:
                        setattr(self, entry[0][6:], value)
            if directories is not None and isinstance(directories, list) and entry[0] in directories:
                directories.remove(directory_index)

    def parse_directory_bound_imports(self, rva, size):
        """"""
        bnd_descr = Structure(self.__IMAGE_BOUND_IMPORT_DESCRIPTOR_format__)
        bnd_descr_size = bnd_descr.sizeof()
        start = rva
        bound_imports = []
        while True:
            bnd_descr = self.__unpack_data__(self.__IMAGE_BOUND_IMPORT_DESCRIPTOR_format__, self.__data__[rva:rva + bnd_descr_size], file_offset=rva)
            if bnd_descr is None:
                self.__warnings.append("The Bound Imports directory exists but can't be parsed.")
                return
            if bnd_descr.all_zeroes():
                break
            rva += bnd_descr.sizeof()
            forwarder_refs = []
            for idx in xrange(bnd_descr.NumberOfModuleForwarderRefs):
                bnd_frwd_ref = self.__unpack_data__(self.__IMAGE_BOUND_FORWARDER_REF_format__, self.__data__[rva:rva + bnd_descr_size], file_offset=rva)
                if not bnd_frwd_ref:
                    raise PEFormatError('IMAGE_BOUND_FORWARDER_REF cannot be read')
                rva += bnd_frwd_ref.sizeof()
                offset = start + bnd_frwd_ref.OffsetModuleName
                name_str = self.get_string_from_data(0, self.__data__[offset:offset + MAX_STRING_LENGTH])
                if not name_str:
                    break
                forwarder_refs.append(BoundImportRefData(struct=bnd_frwd_ref, name=name_str))

            offset = start + bnd_descr.OffsetModuleName
            name_str = self.get_string_from_data(0, self.__data__[offset:offset + MAX_STRING_LENGTH])
            if not name_str:
                break
            bound_imports.append(BoundImportDescData(struct=bnd_descr, name=name_str, entries=forwarder_refs))

        return bound_imports

    def parse_directory_tls(self, rva, size):
        """"""
        if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            format = self.__IMAGE_TLS_DIRECTORY_format__
        elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            format = self.__IMAGE_TLS_DIRECTORY64_format__
        try:
            tls_struct = self.__unpack_data__(format, self.get_data(rva, Structure(format).sizeof()), file_offset=self.get_offset_from_rva(rva))
        except PEFormatError:
            self.__warnings.append("Invalid TLS information. Can't read " + 'data at RVA: 0x%x' % rva)
            tls_struct = None

        if not tls_struct:
            return
        return TlsData(struct=tls_struct)

    def parse_directory_load_config(self, rva, size):
        """"""
        if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            format = self.__IMAGE_LOAD_CONFIG_DIRECTORY_format__
        elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            format = self.__IMAGE_LOAD_CONFIG_DIRECTORY64_format__
        try:
            load_config_struct = self.__unpack_data__(format, self.get_data(rva, Structure(format).sizeof()), file_offset=self.get_offset_from_rva(rva))
        except PEFormatError:
            self.__warnings.append("Invalid LOAD_CONFIG information. Can't read " + 'data at RVA: 0x%x' % rva)
            load_config_struct = None

        if not load_config_struct:
            return
        return LoadConfigData(struct=load_config_struct)

    def parse_relocations_directory(self, rva, size):
        """"""
        rlc_size = Structure(self.__IMAGE_BASE_RELOCATION_format__).sizeof()
        end = rva + size
        relocations = []
        while rva < end:
            try:
                rlc = self.__unpack_data__(self.__IMAGE_BASE_RELOCATION_format__, self.get_data(rva, rlc_size), file_offset=self.get_offset_from_rva(rva))
            except PEFormatError:
                self.__warnings.append("Invalid relocation information. Can't read " + 'data at RVA: 0x%x' % rva)
                rlc = None

            if not rlc:
                break
            if rlc.VirtualAddress > self.OPTIONAL_HEADER.SizeOfImage:
                self.__warnings.append('Invalid relocation information. VirtualAddress outside' + ' of Image: 0x%x' % rlc.VirtualAddress)
                break
            if rlc.SizeOfBlock > self.OPTIONAL_HEADER.SizeOfImage:
                self.__warnings.append('Invalid relocation information. SizeOfBlock too large' + ': %d' % rlc.SizeOfBlock)
                break
            reloc_entries = self.parse_relocations(rva + rlc_size, rlc.VirtualAddress, rlc.SizeOfBlock - rlc_size)
            relocations.append(BaseRelocationData(struct=rlc, entries=reloc_entries))
            if not rlc.SizeOfBlock:
                break
            rva += rlc.SizeOfBlock

        return relocations

    def parse_relocations(self, data_rva, rva, size):
        """"""
        data = self.get_data(data_rva, size)
        file_offset = self.get_offset_from_rva(data_rva)
        entries = []
        for idx in xrange(len(data) / 2):
            entry = self.__unpack_data__(self.__IMAGE_BASE_RELOCATION_ENTRY_format__, data[idx * 2:(idx + 1) * 2], file_offset=file_offset)
            if not entry:
                break
            word = entry.Data
            reloc_type = word >> 12
            reloc_offset = word & 4095
            entries.append(RelocationData(struct=entry, type=reloc_type, base_rva=rva, rva=reloc_offset + rva))
            file_offset += entry.sizeof()

        return entries

    def parse_debug_directory(self, rva, size):
        """"""
        dbg_size = Structure(self.__IMAGE_DEBUG_DIRECTORY_format__).sizeof()
        debug = []
        for idx in xrange(size / dbg_size):
            try:
                data = self.get_data(rva + dbg_size * idx, dbg_size)
            except PEFormatError as e:
                self.__warnings.append("Invalid debug information. Can't read " + 'data at RVA: 0x%x' % rva)
                return None

            dbg = self.__unpack_data__(self.__IMAGE_DEBUG_DIRECTORY_format__, data, file_offset=self.get_offset_from_rva(rva + dbg_size * idx))
            if not dbg:
                return None
            debug.append(DebugData(struct=dbg))

        return debug

    def parse_resources_directory(self, rva, size = 0, base_rva = None, level = 0, dirs = None):
        """Parse the resources directory.
        
        Given the RVA of the resources directory, it will process all
        its entries.
        
        The root will have the corresponding member of its structure,
        IMAGE_RESOURCE_DIRECTORY plus 'entries', a list of all the
        entries in the directory.
        
        Those entries will have, correspondingly, all the structure's
        members (IMAGE_RESOURCE_DIRECTORY_ENTRY) and an additional one,
        "directory", pointing to the IMAGE_RESOURCE_DIRECTORY structure
        representing upper layers of the tree. This one will also have
        an 'entries' attribute, pointing to the 3rd, and last, level.
        Another directory with more entries. Those last entries will
        have a new attribute (both 'leaf' or 'data_entry' can be used to
        access it). This structure finally points to the resource data.
        All the members of this structure, IMAGE_RESOURCE_DATA_ENTRY,
        are available as its attributes.
        """
        if dirs is None:
            dirs = [rva]
        if base_rva is None:
            base_rva = rva
        resources_section = self.get_section_by_rva(rva)
        try:
            data = self.get_data(rva, Structure(self.__IMAGE_RESOURCE_DIRECTORY_format__).sizeof())
        except PEFormatError as e:
            self.__warnings.append("Invalid resources directory. Can't read " + 'directory data at RVA: 0x%x' % rva)
            return

        resource_dir = self.__unpack_data__(self.__IMAGE_RESOURCE_DIRECTORY_format__, data, file_offset=self.get_offset_from_rva(rva))
        if resource_dir is None:
            self.__warnings.append("Invalid resources directory. Can't parse " + 'directory data at RVA: 0x%x' % rva)
            return
        dir_entries = []
        rva += resource_dir.sizeof()
        number_of_entries = resource_dir.NumberOfNamedEntries + resource_dir.NumberOfIdEntries
        MAX_ALLOWED_ENTRIES = 4096
        if number_of_entries > MAX_ALLOWED_ENTRIES:
            self.__warnings.append('Error parsing the resources directory, The directory contains %d entries (>%s)' % (number_of_entries, MAX_ALLOWED_ENTRIES))
            return
        strings_to_postprocess = list()
        for idx in xrange(number_of_entries):
            res = self.parse_resource_entry(rva)
            if res is None:
                self.__warnings.append('Error parsing the resources directory, Entry %d is invalid, RVA = 0x%x. ' % (idx, rva))
                break
            entry_name = None
            entry_id = None
            if idx >= resource_dir.NumberOfNamedEntries:
                entry_id = res.Name
            else:
                ustr_offset = base_rva + res.NameOffset
                try:
                    entry_name = UnicodeStringWrapperPostProcessor(self, ustr_offset)
                    strings_to_postprocess.append(entry_name)
                except PEFormatError as excp:
                    self.__warnings.append("Error parsing the resources directory, attempting to read entry name. Can't read unicode string at offset 0x%x" % ustr_offset)

            if res.DataIsDirectory:
                if base_rva + res.OffsetToDirectory in dirs:
                    break
                else:
                    entry_directory = self.parse_resources_directory(base_rva + res.OffsetToDirectory, size - (rva - base_rva), base_rva=base_rva, level=level + 1, dirs=dirs + [base_rva + res.OffsetToDirectory])
                if not entry_directory:
                    break
                strings = None
                if entry_id == RESOURCE_TYPE['RT_STRING']:
                    strings = dict()
                    for resource_id in entry_directory.entries:
                        if hasattr(resource_id, 'directory'):
                            resource_strings = dict()
                            for resource_lang in resource_id.directory.entries:
                                if resource_lang is None or not hasattr(resource_lang, 'data') or resource_lang.data.struct.Size is None or resource_id.id is None:
                                    continue
                                string_entry_rva = resource_lang.data.struct.OffsetToData
                                string_entry_size = resource_lang.data.struct.Size
                                string_entry_id = resource_id.id
                                string_entry_data = self.get_data(string_entry_rva, string_entry_size)
                                parse_strings(string_entry_data, (int(string_entry_id) - 1) * 16, resource_strings)
                                strings.update(resource_strings)

                            resource_id.directory.strings = resource_strings

                dir_entries.append(ResourceDirEntryData(struct=res, name=entry_name, id=entry_id, directory=entry_directory))
            else:
                struct = self.parse_resource_data_entry(base_rva + res.OffsetToDirectory)
                if struct:
                    entry_data = ResourceDataEntryData(struct=struct, lang=res.Name & 1023, sublang=res.Name >> 10)
                    dir_entries.append(ResourceDirEntryData(struct=res, name=entry_name, id=entry_id, data=entry_data))
                else:
                    break
            if level == 0 and res.Id == RESOURCE_TYPE['RT_VERSION']:
                if len(dir_entries) > 0:
                    last_entry = dir_entries[-1]
                rt_version_struct = None
                try:
                    rt_version_struct = last_entry.directory.entries[0].directory.entries[0].data.struct
                except:
                    pass

                if rt_version_struct is not None:
                    self.parse_version_information(rt_version_struct)
            rva += res.sizeof()

        string_rvas = [ s.get_rva() for s in strings_to_postprocess ]
        string_rvas.sort()
        for idx, s in enumerate(strings_to_postprocess):
            s.render_pascal_16()

        resource_directory_data = ResourceDirData(struct=resource_dir, entries=dir_entries)
        return resource_directory_data

    def parse_resource_data_entry(self, rva):
        """Parse a data entry from the resources directory."""
        try:
            data = self.get_data(rva, Structure(self.__IMAGE_RESOURCE_DATA_ENTRY_format__).sizeof())
        except PEFormatError as excp:
            self.__warnings.append('Error parsing a resource directory data entry, ' + 'the RVA is invalid: 0x%x' % rva)
            return None

        data_entry = self.__unpack_data__(self.__IMAGE_RESOURCE_DATA_ENTRY_format__, data, file_offset=self.get_offset_from_rva(rva))
        return data_entry

    def parse_resource_entry(self, rva):
        """Parse a directory entry from the resources directory."""
        try:
            data = self.get_data(rva, Structure(self.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__).sizeof())
        except PEFormatError as excp:
            return

        resource = self.__unpack_data__(self.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__, data, file_offset=self.get_offset_from_rva(rva))
        if resource is None:
            return
        resource.NameOffset = resource.Name & 2147483647L
        resource.__pad = resource.Name & 4294901760L
        resource.Id = resource.Name & 65535L
        resource.DataIsDirectory = (resource.OffsetToData & 2147483648L) >> 31
        resource.OffsetToDirectory = resource.OffsetToData & 2147483647L
        return resource

    def parse_version_information(self, version_struct):
        """Parse version information structure.
        
        The date will be made available in three attributes of the PE object.
        
        VS_VERSIONINFO     will contain the first three fields of the main structure:
            'Length', 'ValueLength', and 'Type'
        
        VS_FIXEDFILEINFO    will hold the rest of the fields, accessible as sub-attributes:
            'Signature', 'StrucVersion', 'FileVersionMS', 'FileVersionLS',
            'ProductVersionMS', 'ProductVersionLS', 'FileFlagsMask', 'FileFlags',
            'FileOS', 'FileType', 'FileSubtype', 'FileDateMS', 'FileDateLS'
        
        FileInfo    is a list of all StringFileInfo and VarFileInfo structures.
        
        StringFileInfo structures will have a list as an attribute named 'StringTable'
        containing all the StringTable structures. Each of those structures contains a
        dictionary 'entries' with all the key/value version information string pairs.
        
        VarFileInfo structures will have a list as an attribute named 'Var' containing
        all Var structures. Each Var structure will have a dictionary as an attribute
        named 'entry' which will contain the name and value of the Var.
        """
        start_offset = self.get_offset_from_rva(version_struct.OffsetToData)
        raw_data = self.__data__[start_offset:start_offset + version_struct.Size]
        versioninfo_struct = self.__unpack_data__(self.__VS_VERSIONINFO_format__, raw_data, file_offset=start_offset)
        if versioninfo_struct is None:
            return
        ustr_offset = version_struct.OffsetToData + versioninfo_struct.sizeof()
        try:
            versioninfo_string = self.get_string_u_at_rva(ustr_offset)
        except PEFormatError as excp:
            self.__warnings.append('Error parsing the version information, ' + "attempting to read VS_VERSION_INFO string. Can't " + 'read unicode string at offset 0x%x' % ustr_offset)
            versioninfo_string = None

        if versioninfo_string != u'VS_VERSION_INFO':
            self.__warnings.append('Invalid VS_VERSION_INFO block')
            return
        self.VS_VERSIONINFO = versioninfo_struct
        self.VS_VERSIONINFO.Key = versioninfo_string
        fixedfileinfo_offset = self.dword_align(versioninfo_struct.sizeof() + 2 * (len(versioninfo_string) + 1), version_struct.OffsetToData)
        fixedfileinfo_struct = self.__unpack_data__(self.__VS_FIXEDFILEINFO_format__, raw_data[fixedfileinfo_offset:], file_offset=start_offset + fixedfileinfo_offset)
        if not fixedfileinfo_struct:
            return
        self.VS_FIXEDFILEINFO = fixedfileinfo_struct
        stringfileinfo_offset = self.dword_align(fixedfileinfo_offset + fixedfileinfo_struct.sizeof(), version_struct.OffsetToData)
        original_stringfileinfo_offset = stringfileinfo_offset
        self.FileInfo = list()
        while True:
            stringfileinfo_struct = self.__unpack_data__(self.__StringFileInfo_format__, raw_data[stringfileinfo_offset:], file_offset=start_offset + stringfileinfo_offset)
            if stringfileinfo_struct is None:
                self.__warnings.append('Error parsing StringFileInfo/VarFileInfo struct')
                return
            ustr_offset = version_struct.OffsetToData + stringfileinfo_offset + versioninfo_struct.sizeof()
            try:
                stringfileinfo_string = self.get_string_u_at_rva(ustr_offset)
            except PEFormatError as excp:
                self.__warnings.append('Error parsing the version information, ' + "attempting to read StringFileInfo string. Can't " + 'read unicode string at offset 0x%x' % ustr_offset)
                break

            stringfileinfo_struct.Key = stringfileinfo_string
            self.FileInfo.append(stringfileinfo_struct)
            if stringfileinfo_string and stringfileinfo_string.startswith(u'StringFileInfo'):
                if stringfileinfo_struct.Type in (0, 1) and stringfileinfo_struct.ValueLength == 0:
                    stringtable_offset = self.dword_align(stringfileinfo_offset + stringfileinfo_struct.sizeof() + 2 * (len(stringfileinfo_string) + 1), version_struct.OffsetToData)
                    stringfileinfo_struct.StringTable = list()
                    while True:
                        stringtable_struct = self.__unpack_data__(self.__StringTable_format__, raw_data[stringtable_offset:], file_offset=start_offset + stringtable_offset)
                        if not stringtable_struct:
                            break
                        ustr_offset = version_struct.OffsetToData + stringtable_offset + stringtable_struct.sizeof()
                        try:
                            stringtable_string = self.get_string_u_at_rva(ustr_offset)
                        except PEFormatError as excp:
                            self.__warnings.append('Error parsing the version information, ' + "attempting to read StringTable string. Can't " + 'read unicode string at offset 0x%x' % ustr_offset)
                            break

                        stringtable_struct.LangID = stringtable_string
                        stringtable_struct.entries = dict()
                        stringtable_struct.entries_offsets = dict()
                        stringtable_struct.entries_lengths = dict()
                        stringfileinfo_struct.StringTable.append(stringtable_struct)
                        entry_offset = self.dword_align(stringtable_offset + stringtable_struct.sizeof() + 2 * (len(stringtable_string) + 1), version_struct.OffsetToData)
                        while entry_offset < stringtable_offset + stringtable_struct.Length:
                            string_struct = self.__unpack_data__(self.__String_format__, raw_data[entry_offset:], file_offset=start_offset + entry_offset)
                            if not string_struct:
                                break
                            ustr_offset = version_struct.OffsetToData + entry_offset + string_struct.sizeof()
                            try:
                                key = self.get_string_u_at_rva(ustr_offset)
                                key_offset = self.get_offset_from_rva(ustr_offset)
                            except PEFormatError as excp:
                                self.__warnings.append('Error parsing the version information, ' + "attempting to read StringTable Key string. Can't " + 'read unicode string at offset 0x%x' % ustr_offset)
                                break

                            value_offset = self.dword_align(2 * (len(key) + 1) + entry_offset + string_struct.sizeof(), version_struct.OffsetToData)
                            ustr_offset = version_struct.OffsetToData + value_offset
                            try:
                                value = self.get_string_u_at_rva(ustr_offset, max_length=string_struct.ValueLength)
                                value_offset = self.get_offset_from_rva(ustr_offset)
                            except PEFormatError as excp:
                                self.__warnings.append('Error parsing the version information, ' + 'attempting to read StringTable Value string. ' + "Can't read unicode string at offset 0x%x" % ustr_offset)
                                break

                            if string_struct.Length == 0:
                                entry_offset = stringtable_offset + stringtable_struct.Length
                            else:
                                entry_offset = self.dword_align(string_struct.Length + entry_offset, version_struct.OffsetToData)
                            key_as_char = []
                            for c in key:
                                if ord(c) >= 128:
                                    key_as_char.append('\\x%02x' % ord(c))
                                else:
                                    key_as_char.append(c)

                            key_as_char = ''.join(key_as_char)
                            setattr(stringtable_struct, key_as_char, value)
                            stringtable_struct.entries[key] = value
                            stringtable_struct.entries_offsets[key] = (key_offset, value_offset)
                            stringtable_struct.entries_lengths[key] = (len(key), len(value))

                        new_stringtable_offset = self.dword_align(stringtable_struct.Length + stringtable_offset, version_struct.OffsetToData)
                        if new_stringtable_offset == stringtable_offset:
                            break
                        stringtable_offset = new_stringtable_offset
                        if stringtable_offset >= stringfileinfo_struct.Length:
                            break

            elif stringfileinfo_string and stringfileinfo_string.startswith(u'VarFileInfo'):
                varfileinfo_struct = stringfileinfo_struct
                varfileinfo_struct.name = 'VarFileInfo'
                if varfileinfo_struct.Type in (0, 1) and varfileinfo_struct.ValueLength == 0:
                    var_offset = self.dword_align(stringfileinfo_offset + varfileinfo_struct.sizeof() + 2 * (len(stringfileinfo_string) + 1), version_struct.OffsetToData)
                    varfileinfo_struct.Var = list()
                    while True:
                        var_struct = self.__unpack_data__(self.__Var_format__, raw_data[var_offset:], file_offset=start_offset + var_offset)
                        if not var_struct:
                            break
                        ustr_offset = version_struct.OffsetToData + var_offset + var_struct.sizeof()
                        try:
                            var_string = self.get_string_u_at_rva(ustr_offset)
                        except PEFormatError as excp:
                            self.__warnings.append('Error parsing the version information, ' + 'attempting to read VarFileInfo Var string. ' + "Can't read unicode string at offset 0x%x" % ustr_offset)
                            break

                        varfileinfo_struct.Var.append(var_struct)
                        varword_offset = self.dword_align(2 * (len(var_string) + 1) + var_offset + var_struct.sizeof(), version_struct.OffsetToData)
                        orig_varword_offset = varword_offset
                        while varword_offset < orig_varword_offset + var_struct.ValueLength:
                            word1 = self.get_word_from_data(raw_data[varword_offset:varword_offset + 2], 0)
                            word2 = self.get_word_from_data(raw_data[varword_offset + 2:varword_offset + 4], 0)
                            varword_offset += 4
                            if isinstance(word1, (int, long)) and isinstance(word2, (int, long)):
                                var_struct.entry = {var_string: '0x%04x 0x%04x' % (word1, word2)}

                        var_offset = self.dword_align(var_offset + var_struct.Length, version_struct.OffsetToData)
                        if var_offset <= var_offset + var_struct.Length:
                            break

            stringfileinfo_offset = self.dword_align(stringfileinfo_struct.Length + stringfileinfo_offset, version_struct.OffsetToData)
            if stringfileinfo_struct.Length == 0 or stringfileinfo_offset >= versioninfo_struct.Length:
                break

    def parse_export_directory(self, rva, size):
        """Parse the export directory.
        
        Given the RVA of the export directory, it will process all
        its entries.
        
        The exports will be made available through a list "exports"
        containing a tuple with the following elements:
            
            (ordinal, symbol_address, symbol_name)
        
        And also through a dictionary "exports_by_ordinal" whose keys
        will be the ordinals and the values tuples of the from:
            
            (symbol_address, symbol_name)
        
        The symbol addresses are relative, not absolute.
        """
        try:
            export_dir = self.__unpack_data__(self.__IMAGE_EXPORT_DIRECTORY_format__, self.get_data(rva, Structure(self.__IMAGE_EXPORT_DIRECTORY_format__).sizeof()), file_offset=self.get_offset_from_rva(rva))
        except PEFormatError:
            self.__warnings.append('Error parsing export directory at RVA: 0x%x' % rva)
            return

        if not export_dir:
            return

        def length_until_eof(rva):
            return len(self.__data__) - self.get_offset_from_rva(rva)

        try:
            address_of_names = self.get_data(export_dir.AddressOfNames, min(length_until_eof(export_dir.AddressOfNames), export_dir.NumberOfNames * 4))
            address_of_name_ordinals = self.get_data(export_dir.AddressOfNameOrdinals, min(length_until_eof(export_dir.AddressOfNameOrdinals), export_dir.NumberOfNames * 4))
            address_of_functions = self.get_data(export_dir.AddressOfFunctions, min(length_until_eof(export_dir.AddressOfFunctions), export_dir.NumberOfFunctions * 4))
        except PEFormatError:
            self.__warnings.append('Error parsing export directory at RVA: 0x%x' % rva)
            return

        exports = []
        max_failed_entries_before_giving_up = 10
        for i in xrange(min(export_dir.NumberOfNames, length_until_eof(export_dir.AddressOfNames) / 4)):
            symbol_name_address = self.get_dword_from_data(address_of_names, i)
            if symbol_name_address is None:
                max_failed_entries_before_giving_up -= 1
                if max_failed_entries_before_giving_up <= 0:
                    break
            symbol_name = self.get_string_at_rva(symbol_name_address)
            try:
                symbol_name_offset = self.get_offset_from_rva(symbol_name_address)
            except PEFormatError:
                max_failed_entries_before_giving_up -= 1
                if max_failed_entries_before_giving_up <= 0:
                    break
                continue

            symbol_ordinal = self.get_word_from_data(address_of_name_ordinals, i)
            if symbol_ordinal is not None and symbol_ordinal * 4 < len(address_of_functions):
                symbol_address = self.get_dword_from_data(address_of_functions, symbol_ordinal)
            else:
                return
            if symbol_address is None or symbol_address == 0:
                continue
            if symbol_address >= rva and symbol_address < rva + size:
                forwarder_str = self.get_string_at_rva(symbol_address)
                try:
                    forwarder_offset = self.get_offset_from_rva(symbol_address)
                except PEFormatError:
                    continue

            else:
                forwarder_str = None
                forwarder_offset = None
            exports.append(ExportData(pe=self, ordinal=export_dir.Base + symbol_ordinal, ordinal_offset=self.get_offset_from_rva(export_dir.AddressOfNameOrdinals + 2 * i), address=symbol_address, address_offset=self.get_offset_from_rva(export_dir.AddressOfFunctions + 4 * symbol_ordinal), name=symbol_name, name_offset=symbol_name_offset, forwarder=forwarder_str, forwarder_offset=forwarder_offset))

        ordinals = [ exp.ordinal for exp in exports ]
        max_failed_entries_before_giving_up = 10
        for idx in xrange(min(export_dir.NumberOfFunctions, length_until_eof(export_dir.AddressOfFunctions) / 4)):
            if idx + export_dir.Base not in ordinals:
                try:
                    symbol_address = self.get_dword_from_data(address_of_functions, idx)
                except PEFormatError:
                    symbol_address = None

                if symbol_address is None:
                    max_failed_entries_before_giving_up -= 1
                    if max_failed_entries_before_giving_up <= 0:
                        break
                if symbol_address == 0:
                    continue
                if symbol_address >= rva and symbol_address < rva + size:
                    forwarder_str = self.get_string_at_rva(symbol_address)
                else:
                    forwarder_str = None
                exports.append(ExportData(ordinal=export_dir.Base + idx, address=symbol_address, name=None, forwarder=forwarder_str))

        return ExportDirData(struct=export_dir, symbols=exports)

    def dword_align(self, offset, base):
        return (offset + base + 3 & 4294967292L) - (base & 4294967292L)

    def parse_delay_import_directory(self, rva, size):
        """Walk and parse the delay import directory."""
        import_descs = []
        while True:
            try:
                data = self.get_data(rva, Structure(self.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__).sizeof())
            except PEFormatError as e:
                self.__warnings.append('Error parsing the Delay import directory at RVA: 0x%x' % rva)
                break

            import_desc = self.__unpack_data__(self.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__, data, file_offset=self.get_offset_from_rva(rva))
            if not import_desc or import_desc.all_zeroes():
                break
            rva += import_desc.sizeof()
            try:
                import_data = self.parse_imports(import_desc.pINT, import_desc.pIAT, None)
            except PEFormatError as e:
                self.__warnings.append('Error parsing the Delay import directory. ' + 'Invalid import data at RVA: 0x%x' % rva)
                break

            if not import_data:
                continue
            dll = self.get_string_at_rva(import_desc.szName)
            if not is_valid_dos_filename(dll):
                dll = '*invalid*'
            if dll:
                import_descs.append(ImportDescData(struct=import_desc, imports=import_data, dll=dll))

        return import_descs

    def parse_import_directory(self, rva, size):
        """Walk and parse the import directory."""
        import_descs = []
        while True:
            try:
                data = self.get_data(rva, Structure(self.__IMAGE_IMPORT_DESCRIPTOR_format__).sizeof())
            except PEFormatError as e:
                self.__warnings.append('Error parsing the import directory at RVA: 0x%x' % rva)
                break

            import_desc = self.__unpack_data__(self.__IMAGE_IMPORT_DESCRIPTOR_format__, data, file_offset=self.get_offset_from_rva(rva))
            if not import_desc or import_desc.all_zeroes():
                break
            rva += import_desc.sizeof()
            try:
                import_data = self.parse_imports(import_desc.OriginalFirstThunk, import_desc.FirstThunk, import_desc.ForwarderChain)
            except PEFormatError as excp:
                self.__warnings.append('Error parsing the import directory. ' + 'Invalid Import data at RVA: 0x%x (%s)' % (rva, str(excp)))
                break

            if not import_data:
                continue
            dll = self.get_string_at_rva(import_desc.Name)
            if not is_valid_dos_filename(dll):
                dll = '*invalid*'
            if dll:
                import_descs.append(ImportDescData(struct=import_desc, imports=import_data, dll=dll))

        suspicious_imports = set(['LoadLibrary', 'GetProcAddress'])
        suspicious_imports_count = 0
        total_symbols = 0
        for imp_dll in import_descs:
            for symbol in imp_dll.imports:
                for suspicious_symbol in suspicious_imports:
                    if symbol and symbol.name and symbol.name.startswith(suspicious_symbol):
                        suspicious_imports_count += 1
                        break

                total_symbols += 1

        if suspicious_imports_count == len(suspicious_imports) and total_symbols < 20:
            self.__warnings.append('Imported symbols contain entries typical of packed executables.')
        return import_descs

    def parse_imports(self, original_first_thunk, first_thunk, forwarder_chain):
        """Parse the imported symbols.
        
        It will fill a list, which will be available as the dictionary
        attribute "imports". Its keys will be the DLL names and the values
        all the symbols imported from that object.
        """
        imported_symbols = []
        ilt = self.get_import_table(original_first_thunk)
        iat = self.get_import_table(first_thunk)
        if (not iat or len(iat) == 0) and (not ilt or len(ilt) == 0):
            raise PEFormatError('Invalid Import Table information. ' + 'Both ILT and IAT appear to be broken.')
        table = None
        if ilt:
            table = ilt
        elif iat:
            table = iat
        else:
            return
        imp_offset = 4
        address_mask = 2147483647
        if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            ordinal_flag = IMAGE_ORDINAL_FLAG
        elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            ordinal_flag = IMAGE_ORDINAL_FLAG64
            imp_offset = 8
            address_mask = 9223372036854775807L
        for idx in xrange(len(table)):
            imp_ord = None
            imp_hint = None
            imp_name = None
            name_offset = None
            hint_name_table_rva = None
            if table[idx].AddressOfData:
                if table[idx].AddressOfData & ordinal_flag:
                    import_by_ordinal = True
                    imp_ord = table[idx].AddressOfData & 65535
                    imp_name = None
                    name_offset = None
                else:
                    import_by_ordinal = False
                    try:
                        hint_name_table_rva = table[idx].AddressOfData & address_mask
                        data = self.get_data(hint_name_table_rva, 2)
                        imp_hint = self.get_word_from_data(data, 0)
                        imp_name = self.get_string_at_rva(table[idx].AddressOfData + 2)
                        if not is_valid_function_name(imp_name):
                            imp_name = '*invalid*'
                        name_offset = self.get_offset_from_rva(table[idx].AddressOfData + 2)
                    except PEFormatError as e:
                        pass

                thunk_offset = table[idx].get_file_offset()
                thunk_rva = self.get_rva_from_offset(thunk_offset)
            imp_address = first_thunk + self.OPTIONAL_HEADER.ImageBase + idx * imp_offset
            struct_iat = None
            try:
                if iat and ilt and ilt[idx].AddressOfData != iat[idx].AddressOfData:
                    imp_bound = iat[idx].AddressOfData
                    struct_iat = iat[idx]
                else:
                    imp_bound = None
            except IndexError:
                imp_bound = None

            if imp_ord == None and imp_name == None:
                raise PEFormatError('Invalid entries in the Import Table. Aborting parsing.')
            if imp_name != '' and (imp_ord or imp_name):
                imported_symbols.append(ImportData(pe=self, struct_table=table[idx], struct_iat=struct_iat, import_by_ordinal=import_by_ordinal, ordinal=imp_ord, ordinal_offset=table[idx].get_file_offset(), hint=imp_hint, name=imp_name, name_offset=name_offset, bound=imp_bound, address=imp_address, hint_name_table_rva=hint_name_table_rva, thunk_offset=thunk_offset, thunk_rva=thunk_rva))

        return imported_symbols

    def get_import_table(self, rva):
        table = []
        if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            ordinal_flag = IMAGE_ORDINAL_FLAG
            format = self.__IMAGE_THUNK_DATA_format__
        elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            ordinal_flag = IMAGE_ORDINAL_FLAG64
            format = self.__IMAGE_THUNK_DATA64_format__
        MAX_ADDRESS_SPREAD = 128 * 1048576
        MAX_REPEATED_ADDRESSES = 15
        repeated_address = 0
        addresses_of_data_set_64 = set()
        addresses_of_data_set_32 = set()
        while True and rva:
            if repeated_address >= MAX_REPEATED_ADDRESSES:
                return []
            if addresses_of_data_set_32 and max(addresses_of_data_set_32) - min(addresses_of_data_set_32) > MAX_ADDRESS_SPREAD:
                return []
            if addresses_of_data_set_64 and max(addresses_of_data_set_64) - min(addresses_of_data_set_64) > MAX_ADDRESS_SPREAD:
                return []
            try:
                data = self.get_data(rva, Structure(format).sizeof())
            except PEFormatError as e:
                self.__warnings.append('Error parsing the import table. ' + 'Invalid data at RVA: 0x%x' % rva)
                return None

            thunk_data = self.__unpack_data__(format, data, file_offset=self.get_offset_from_rva(rva))
            if thunk_data and thunk_data.AddressOfData:
                if thunk_data.AddressOfData & ordinal_flag:
                    if thunk_data.AddressOfData & 2147483647 > 65535:
                        return []
                else:
                    if thunk_data.AddressOfData in addresses_of_data_set_32 or thunk_data.AddressOfData in addresses_of_data_set_64:
                        repeated_address += 1
                    if thunk_data.AddressOfData >= 4294967296L:
                        addresses_of_data_set_64.add(thunk_data.AddressOfData)
                    else:
                        addresses_of_data_set_32.add(thunk_data.AddressOfData)
            if not thunk_data or thunk_data.all_zeroes():
                break
            rva += thunk_data.sizeof()
            table.append(thunk_data)

        return table

    def get_memory_mapped_image(self, max_virtual_address = 268435456, ImageBase = None):
        """Returns the data corresponding to the memory layout of the PE file.
        
        The data includes the PE header and the sections loaded at offsets
        corresponding to their relative virtual addresses. (the VirtualAddress
        section header member).
        Any offset in this data corresponds to the absolute memory address
        ImageBase+offset.
        
        The optional argument 'max_virtual_address' provides with means of limiting
        which section are processed.
        Any section with their VirtualAddress beyond this value will be skipped.
        Normally, sections with values beyond this range are just there to confuse
        tools. It's a common trick to see in packed executables.
        
        If the 'ImageBase' optional argument is supplied, the file's relocations
        will be applied to the image by calling the 'relocate_image()' method. Beware
        that the relocation information is applied permanently.
        """
        if ImageBase is not None:
            original_data = self.__data__
            self.relocate_image(ImageBase)
        mapped_data = '' + self.__data__[:]
        for section in self.sections:
            if section.Misc_VirtualSize == 0 or section.SizeOfRawData == 0:
                continue
            if section.SizeOfRawData > len(self.__data__):
                continue
            if self.adjust_FileAlignment(section.PointerToRawData, self.OPTIONAL_HEADER.FileAlignment) > len(self.__data__):
                continue
            VirtualAddress_adj = self.adjust_SectionAlignment(section.VirtualAddress, self.OPTIONAL_HEADER.SectionAlignment, self.OPTIONAL_HEADER.FileAlignment)
            if VirtualAddress_adj >= max_virtual_address:
                continue
            padding_length = VirtualAddress_adj - len(mapped_data)
            if padding_length > 0:
                mapped_data += '\x00' * padding_length
            elif padding_length < 0:
                mapped_data = mapped_data[:padding_length]
            mapped_data += section.get_data()

        if ImageBase is not None:
            self.__data__ = original_data
        return mapped_data

    def get_resources_strings(self):
        """Returns a list of all the strings found withing the resources (if any).
        
        This method will scan all entries in the resources directory of the PE, if
        there is one, and will return a list() with the strings.
        
        An empty list will be returned otherwise.
        """
        resources_strings = list()
        if hasattr(self, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in self.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            if hasattr(resource_id.directory, 'strings') and resource_id.directory.strings:
                                for res_string in resource_id.directory.strings.values():
                                    resources_strings.append(res_string)

        return resources_strings

    def get_data(self, rva = 0, length = None):
        """Get data regardless of the section where it lies on.
        
        Given a RVA and the size of the chunk to retrieve, this method
        will find the section where the data lies and return the data.
        """
        s = self.get_section_by_rva(rva)
        if length:
            end = rva + length
        else:
            end = None
        if not s:
            if rva < len(self.header):
                return self.header[rva:end]
            if rva < len(self.__data__):
                return self.__data__[rva:end]
            raise PEFormatError, "data at RVA can't be fetched. Corrupt header?"
        return s.get_data(rva, length)

    def get_rva_from_offset(self, offset):
        """Get the RVA corresponding to this file offset. """
        s = self.get_section_by_offset(offset)
        if not s:
            if self.sections:
                lowest_rva = min([ self.adjust_SectionAlignment(s.VirtualAddress, self.OPTIONAL_HEADER.SectionAlignment, self.OPTIONAL_HEADER.FileAlignment) for s in self.sections ])
                if offset < lowest_rva:
                    return offset
            else:
                return offset
        return s.get_rva_from_offset(offset)

    def get_offset_from_rva(self, rva):
        """Get the file offset corresponding to this RVA.
        
        Given a RVA , this method will find the section where the
        data lies and return the offset within the file.
        """
        s = self.get_section_by_rva(rva)
        if not s:
            if rva < len(self.__data__):
                return rva
            raise PEFormatError, "data at RVA can't be fetched. Corrupt header?"
        return s.get_offset_from_rva(rva)

    def get_string_at_rva(self, rva):
        """Get an ASCII string located at the given address."""
        if rva is None:
            return
        s = self.get_section_by_rva(rva)
        if not s:
            return self.get_string_from_data(0, self.__data__[rva:rva + MAX_STRING_LENGTH])
        return self.get_string_from_data(0, s.get_data(rva, length=MAX_STRING_LENGTH))

    def get_string_from_data(self, offset, data):
        """Get an ASCII string from within the data."""
        b = None
        try:
            b = data[offset]
        except IndexError:
            return ''

        s = ''
        while ord(b):
            s += b
            offset += 1
            try:
                b = data[offset]
            except IndexError:
                break

        return s

    def get_string_u_at_rva(self, rva, max_length = 2 ** 16):
        """Get an Unicode string located at the given address."""
        try:
            data = self.get_data(rva, 2)
        except PEFormatError as e:
            return None

        s = u''
        for idx in xrange(max_length):
            try:
                uchr = struct.unpack('<H', self.get_data(rva + 2 * idx, 2))[0]
            except struct.error:
                break

            if unichr(uchr) == u'\x00':
                break
            s += unichr(uchr)

        return s

    def get_section_by_offset(self, offset):
        """Get the section containing the given file offset."""
        sections = [ s for s in self.sections if s.contains_offset(offset) ]
        if sections:
            return sections[0]

    def get_section_by_rva(self, rva):
        """Get the section containing the given address."""
        sections = [ s for s in self.sections if s.contains_rva(rva) ]
        if sections:
            return sections[0]

    def __str__(self):
        return self.dump_info()

    def print_info(self):
        """Print all the PE header information in a human readable from."""
        print self.dump_info()

    def dump_info(self, dump = None):
        """Dump all the PE header information into human readable string."""
        if dump is None:
            dump = Dump()
        warnings = self.get_warnings()
        if warnings:
            dump.add_header('Parsing Warnings')
            for warning in warnings:
                dump.add_line(warning)
                dump.add_newline()

        dump.add_header('DOS_HEADER')
        dump.add_lines(self.DOS_HEADER.dump())
        dump.add_newline()
        dump.add_header('NT_HEADERS')
        dump.add_lines(self.NT_HEADERS.dump())
        dump.add_newline()
        dump.add_header('FILE_HEADER')
        dump.add_lines(self.FILE_HEADER.dump())
        image_flags = retrieve_flags(IMAGE_CHARACTERISTICS, 'IMAGE_FILE_')
        dump.add('Flags: ')
        flags = []
        for flag in image_flags:
            if getattr(self.FILE_HEADER, flag[0]):
                flags.append(flag[0])

        dump.add_line(', '.join(flags))
        dump.add_newline()
        if hasattr(self, 'OPTIONAL_HEADER') and self.OPTIONAL_HEADER is not None:
            dump.add_header('OPTIONAL_HEADER')
            dump.add_lines(self.OPTIONAL_HEADER.dump())
        dll_characteristics_flags = retrieve_flags(DLL_CHARACTERISTICS, 'IMAGE_DLL_CHARACTERISTICS_')
        dump.add('DllCharacteristics: ')
        flags = []
        for flag in dll_characteristics_flags:
            if getattr(self.OPTIONAL_HEADER, flag[0]):
                flags.append(flag[0])

        dump.add_line(', '.join(flags))
        dump.add_newline()
        dump.add_header('PE Sections')
        section_flags = retrieve_flags(SECTION_CHARACTERISTICS, 'IMAGE_SCN_')
        for section in self.sections:
            dump.add_lines(section.dump())
            dump.add('Flags: ')
            flags = []
            for flag in section_flags:
                if getattr(section, flag[0]):
                    flags.append(flag[0])

            dump.add_line(', '.join(flags))
            dump.add_line('Entropy: %f (Min=0.0, Max=8.0)' % section.get_entropy())
            if md5 is not None:
                dump.add_line('MD5     hash: %s' % section.get_hash_md5())
            if sha1 is not None:
                dump.add_line('SHA-1   hash: %s' % section.get_hash_sha1())
            if sha256 is not None:
                dump.add_line('SHA-256 hash: %s' % section.get_hash_sha256())
            if sha512 is not None:
                dump.add_line('SHA-512 hash: %s' % section.get_hash_sha512())
            dump.add_newline()

        if hasattr(self, 'OPTIONAL_HEADER') and hasattr(self.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
            dump.add_header('Directories')
            for idx in xrange(len(self.OPTIONAL_HEADER.DATA_DIRECTORY)):
                directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
                dump.add_lines(directory.dump())

            dump.add_newline()

        def convert_char(char):
            if char in string.ascii_letters or char in string.digits or char in string.punctuation or char in string.whitespace:
                return char
            else:
                return '\\x%02x' % ord(char)

        def convert_to_printable(s):
            return ''.join([ convert_char(c) for c in s ])

        if hasattr(self, 'VS_VERSIONINFO'):
            dump.add_header('Version Information')
            dump.add_lines(self.VS_VERSIONINFO.dump())
            dump.add_newline()
            if hasattr(self, 'VS_FIXEDFILEINFO'):
                dump.add_lines(self.VS_FIXEDFILEINFO.dump())
                dump.add_newline()
            if hasattr(self, 'FileInfo'):
                for entry in self.FileInfo:
                    dump.add_lines(entry.dump())
                    dump.add_newline()
                    if hasattr(entry, 'StringTable'):
                        for st_entry in entry.StringTable:
                            [ dump.add_line('  ' + line) for line in st_entry.dump() ]
                            dump.add_line('  LangID: ' + st_entry.LangID)
                            dump.add_newline()
                            for str_entry in st_entry.entries.items():
                                dump.add_line('    ' + convert_to_printable(str_entry[0]) + ': ' + convert_to_printable(str_entry[1]))

                        dump.add_newline()
                    elif hasattr(entry, 'Var'):
                        for var_entry in entry.Var:
                            if hasattr(var_entry, 'entry'):
                                [ dump.add_line('  ' + line) for line in var_entry.dump() ]
                                dump.add_line('    ' + convert_to_printable(var_entry.entry.keys()[0]) + ': ' + var_entry.entry.values()[0])

                        dump.add_newline()

        if hasattr(self, 'DIRECTORY_ENTRY_EXPORT'):
            dump.add_header('Exported symbols')
            dump.add_lines(self.DIRECTORY_ENTRY_EXPORT.struct.dump())
            dump.add_newline()
            dump.add_line('%-10s   %-10s  %s' % ('Ordinal', 'RVA', 'Name'))
            for export in self.DIRECTORY_ENTRY_EXPORT.symbols:
                if export.address is not None:
                    dump.add('%-10d 0x%08Xh    %s' % (export.ordinal, export.address, export.name))
                    if export.forwarder:
                        dump.add_line(' forwarder: %s' % export.forwarder)
                    else:
                        dump.add_newline()

            dump.add_newline()
        if hasattr(self, 'DIRECTORY_ENTRY_IMPORT'):
            dump.add_header('Imported symbols')
            for module in self.DIRECTORY_ENTRY_IMPORT:
                dump.add_lines(module.struct.dump())
                dump.add_newline()
                for symbol in module.imports:
                    if symbol.import_by_ordinal is True:
                        dump.add('%s Ordinal[%s] (Imported by Ordinal)' % (module.dll, str(symbol.ordinal)))
                    else:
                        dump.add('%s.%s Hint[%s]' % (module.dll, symbol.name, str(symbol.hint)))
                    if symbol.bound:
                        dump.add_line(' Bound: 0x%08X' % symbol.bound)
                    else:
                        dump.add_newline()

                dump.add_newline()

        if hasattr(self, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
            dump.add_header('Bound imports')
            for bound_imp_desc in self.DIRECTORY_ENTRY_BOUND_IMPORT:
                dump.add_lines(bound_imp_desc.struct.dump())
                dump.add_line('DLL: %s' % bound_imp_desc.name)
                dump.add_newline()
                for bound_imp_ref in bound_imp_desc.entries:
                    dump.add_lines(bound_imp_ref.struct.dump(), 4)
                    dump.add_line('DLL: %s' % bound_imp_ref.name, 4)
                    dump.add_newline()

        if hasattr(self, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            dump.add_header('Delay Imported symbols')
            for module in self.DIRECTORY_ENTRY_DELAY_IMPORT:
                dump.add_lines(module.struct.dump())
                dump.add_newline()
                for symbol in module.imports:
                    if symbol.import_by_ordinal is True:
                        dump.add('%s Ordinal[%s] (Imported by Ordinal)' % (module.dll, str(symbol.ordinal)))
                    else:
                        dump.add('%s.%s Hint[%s]' % (module.dll, symbol.name, str(symbol.hint)))
                    if symbol.bound:
                        dump.add_line(' Bound: 0x%08X' % symbol.bound)
                    else:
                        dump.add_newline()

                dump.add_newline()

        if hasattr(self, 'DIRECTORY_ENTRY_RESOURCE'):
            dump.add_header('Resource directory')
            dump.add_lines(self.DIRECTORY_ENTRY_RESOURCE.struct.dump())
            for resource_type in self.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name is not None:
                    dump.add_line('Name: [%s]' % resource_type.name, 2)
                else:
                    dump.add_line('Id: [0x%X] (%s)' % (resource_type.struct.Id, RESOURCE_TYPE.get(resource_type.struct.Id, '-')), 2)
                dump.add_lines(resource_type.struct.dump(), 2)
                if hasattr(resource_type, 'directory'):
                    dump.add_lines(resource_type.directory.struct.dump(), 4)
                    for resource_id in resource_type.directory.entries:
                        if resource_id.name is not None:
                            dump.add_line('Name: [%s]' % resource_id.name, 6)
                        else:
                            dump.add_line('Id: [0x%X]' % resource_id.struct.Id, 6)
                        dump.add_lines(resource_id.struct.dump(), 6)
                        if hasattr(resource_id, 'directory'):
                            dump.add_lines(resource_id.directory.struct.dump(), 8)
                            for resource_lang in resource_id.directory.entries:
                                if hasattr(resource_lang, 'data'):
                                    dump.add_line('\\--- LANG [%d,%d][%s,%s]' % (resource_lang.data.lang,
                                     resource_lang.data.sublang,
                                     LANG.get(resource_lang.data.lang, '*unknown*'),
                                     get_sublang_name_for_lang(resource_lang.data.lang, resource_lang.data.sublang)), 8)
                                    dump.add_lines(resource_lang.struct.dump(), 10)
                                    dump.add_lines(resource_lang.data.struct.dump(), 12)

                            if hasattr(resource_id.directory, 'strings') and resource_id.directory.strings:
                                dump.add_line('[STRINGS]', 10)
                                for idx, res_string in resource_id.directory.strings.items():
                                    dump.add_line('%6d: %s' % (idx, convert_to_printable(res_string)), 12)

                dump.add_newline()

            dump.add_newline()
        if hasattr(self, 'DIRECTORY_ENTRY_TLS') and self.DIRECTORY_ENTRY_TLS and self.DIRECTORY_ENTRY_TLS.struct:
            dump.add_header('TLS')
            dump.add_lines(self.DIRECTORY_ENTRY_TLS.struct.dump())
            dump.add_newline()
        if hasattr(self, 'DIRECTORY_ENTRY_LOAD_CONFIG') and self.DIRECTORY_ENTRY_LOAD_CONFIG and self.DIRECTORY_ENTRY_LOAD_CONFIG.struct:
            dump.add_header('LOAD_CONFIG')
            dump.add_lines(self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.dump())
            dump.add_newline()
        if hasattr(self, 'DIRECTORY_ENTRY_DEBUG'):
            dump.add_header('Debug information')
            for dbg in self.DIRECTORY_ENTRY_DEBUG:
                dump.add_lines(dbg.struct.dump())
                try:
                    dump.add_line('Type: ' + DEBUG_TYPE[dbg.struct.Type])
                except KeyError:
                    dump.add_line('Type: 0x%x(Unknown)' % dbg.struct.Type)

                dump.add_newline()

        if hasattr(self, 'DIRECTORY_ENTRY_BASERELOC'):
            dump.add_header('Base relocations')
            for base_reloc in self.DIRECTORY_ENTRY_BASERELOC:
                dump.add_lines(base_reloc.struct.dump())
                for reloc in base_reloc.entries:
                    try:
                        dump.add_line('%08Xh %s' % (reloc.rva, RELOCATION_TYPE[reloc.type][16:]), 4)
                    except KeyError:
                        dump.add_line('0x%08X 0x%x(Unknown)' % (reloc.rva, reloc.type), 4)

                dump.add_newline()

        return dump.get_text()

    def get_physical_by_rva(self, rva):
        """Gets the physical address in the PE file from an RVA value."""
        try:
            return self.get_offset_from_rva(rva)
        except Exception:
            return None

    def get_data_from_dword(self, dword):
        """Return a four byte string representing the double word value. (little endian)."""
        return struct.pack('<L', dword & 4294967295L)

    def get_dword_from_data(self, data, offset):
        """Convert four bytes of data to a double word (little endian)
        
        'offset' is assumed to index into a dword array. So setting it to
        N will return a dword out of the data starting at offset N*4.
        
        Returns None if the data can't be turned into a double word.
        """
        if (offset + 1) * 4 > len(data):
            return None
        return struct.unpack('<I', data[offset * 4:(offset + 1) * 4])[0]

    def get_dword_at_rva(self, rva):
        """Return the double word value at the given RVA.
        
        Returns None if the value can't be read, i.e. the RVA can't be mapped
        to a file offset.
        """
        try:
            return self.get_dword_from_data(self.get_data(rva)[:4], 0)
        except PEFormatError:
            return None

    def get_dword_from_offset(self, offset):
        """Return the double word value at the given file offset. (little endian)"""
        if offset + 4 > len(self.__data__):
            return None
        return self.get_dword_from_data(self.__data__[offset:offset + 4], 0)

    def set_dword_at_rva(self, rva, dword):
        """Set the double word value at the file offset corresponding to the given RVA."""
        return self.set_bytes_at_rva(rva, self.get_data_from_dword(dword))

    def set_dword_at_offset(self, offset, dword):
        """Set the double word value at the given file offset."""
        return self.set_bytes_at_offset(offset, self.get_data_from_dword(dword))

    def get_data_from_word(self, word):
        """Return a two byte string representing the word value. (little endian)."""
        return struct.pack('<H', word)

    def get_word_from_data(self, data, offset):
        """Convert two bytes of data to a word (little endian)
        
        'offset' is assumed to index into a word array. So setting it to
        N will return a dword out of the data starting at offset N*2.
        
        Returns None if the data can't be turned into a word.
        """
        if (offset + 1) * 2 > len(data):
            return None
        return struct.unpack('<H', data[offset * 2:(offset + 1) * 2])[0]

    def get_word_at_rva(self, rva):
        """Return the word value at the given RVA.
        
        Returns None if the value can't be read, i.e. the RVA can't be mapped
        to a file offset.
        """
        try:
            return self.get_word_from_data(self.get_data(rva)[:2], 0)
        except PEFormatError:
            return None

    def get_word_from_offset(self, offset):
        """Return the word value at the given file offset. (little endian)"""
        if offset + 2 > len(self.__data__):
            return None
        return self.get_word_from_data(self.__data__[offset:offset + 2], 0)

    def set_word_at_rva(self, rva, word):
        """Set the word value at the file offset corresponding to the given RVA."""
        return self.set_bytes_at_rva(rva, self.get_data_from_word(word))

    def set_word_at_offset(self, offset, word):
        """Set the word value at the given file offset."""
        return self.set_bytes_at_offset(offset, self.get_data_from_word(word))

    def get_data_from_qword(self, word):
        """Return a eight byte string representing the quad-word value. (little endian)."""
        return struct.pack('<Q', word)

    def get_qword_from_data(self, data, offset):
        """Convert eight bytes of data to a word (little endian)
        
        'offset' is assumed to index into a word array. So setting it to
        N will return a dword out of the data starting at offset N*8.
        
        Returns None if the data can't be turned into a quad word.
        """
        if (offset + 1) * 8 > len(data):
            return None
        return struct.unpack('<Q', data[offset * 8:(offset + 1) * 8])[0]

    def get_qword_at_rva(self, rva):
        """Return the quad-word value at the given RVA.
        
        Returns None if the value can't be read, i.e. the RVA can't be mapped
        to a file offset.
        """
        try:
            return self.get_qword_from_data(self.get_data(rva)[:8], 0)
        except PEFormatError:
            return None

    def get_qword_from_offset(self, offset):
        """Return the quad-word value at the given file offset. (little endian)"""
        if offset + 8 > len(self.__data__):
            return None
        return self.get_qword_from_data(self.__data__[offset:offset + 8], 0)

    def set_qword_at_rva(self, rva, qword):
        """Set the quad-word value at the file offset corresponding to the given RVA."""
        return self.set_bytes_at_rva(rva, self.get_data_from_qword(qword))

    def set_qword_at_offset(self, offset, qword):
        """Set the quad-word value at the given file offset."""
        return self.set_bytes_at_offset(offset, self.get_data_from_qword(qword))

    def set_bytes_at_rva(self, rva, data):
        """Overwrite, with the given string, the bytes at the file offset corresponding to the given RVA.
        
        Return True if successful, False otherwise. It can fail if the
        offset is outside the file's boundaries.
        """
        if not isinstance(data, str):
            raise TypeError('data should be of type: str')
        offset = self.get_physical_by_rva(rva)
        if not offset:
            return False
        return self.set_bytes_at_offset(offset, data)

    def set_bytes_at_offset(self, offset, data):
        """Overwrite the bytes at the given file offset with the given string.
        
        Return True if successful, False otherwise. It can fail if the
        offset is outside the file's boundaries.
        """
        if not isinstance(data, str):
            raise TypeError('data should be of type: str')
        if offset >= 0 and offset < len(self.__data__):
            self.__data__ = self.__data__[:offset] + data + self.__data__[offset + len(data):]
        else:
            return False
        return True

    def merge_modified_section_data(self):
        """Update the PE image content with any individual section data that has been modified."""
        for section in self.sections:
            section_data_start = self.adjust_FileAlignment(section.PointerToRawData, self.OPTIONAL_HEADER.FileAlignment)
            section_data_end = section_data_start + section.SizeOfRawData
            if section_data_start < len(self.__data__) and section_data_end < len(self.__data__):
                self.__data__ = self.__data__[:section_data_start] + section.get_data() + self.__data__[section_data_end:]

    def relocate_image(self, new_ImageBase):
        """Apply the relocation information to the image using the provided new image base.
        
        This method will apply the relocation information to the image. Given the new base,
        all the relocations will be processed and both the raw data and the section's data
        will be fixed accordingly.
        The resulting image can be retrieved as well through the method:
            
            get_memory_mapped_image()
        
        In order to get something that would more closely match what could be found in memory
        once the Windows loader finished its work.
        """
        relocation_difference = new_ImageBase - self.OPTIONAL_HEADER.ImageBase
        for reloc in self.DIRECTORY_ENTRY_BASERELOC:
            virtual_address = reloc.struct.VirtualAddress
            size_of_block = reloc.struct.SizeOfBlock
            entry_idx = 0
            while entry_idx < len(reloc.entries):
                entry = reloc.entries[entry_idx]
                entry_idx += 1
                if entry.type == RELOCATION_TYPE['IMAGE_REL_BASED_ABSOLUTE']:
                    pass
                elif entry.type == RELOCATION_TYPE['IMAGE_REL_BASED_HIGH']:
                    self.set_word_at_rva(entry.rva, self.get_word_at_rva(entry.rva) + relocation_difference >> 16 & 65535)
                elif entry.type == RELOCATION_TYPE['IMAGE_REL_BASED_LOW']:
                    self.set_word_at_rva(entry.rva, self.get_word_at_rva(entry.rva) + relocation_difference & 65535)
                elif entry.type == RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']:
                    self.set_dword_at_rva(entry.rva, self.get_dword_at_rva(entry.rva) + relocation_difference)
                elif entry.type == RELOCATION_TYPE['IMAGE_REL_BASED_HIGHADJ']:
                    if entry_idx == len(reloc.entries):
                        break
                    next_entry = reloc.entries[entry_idx]
                    entry_idx += 1
                    self.set_word_at_rva(entry.rva, ((self.get_word_at_rva(entry.rva) << 16) + next_entry.rva + relocation_difference & 4294901760L) >> 16)
                elif entry.type == RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']:
                    self.set_qword_at_rva(entry.rva, self.get_qword_at_rva(entry.rva) + relocation_difference)

    def verify_checksum(self):
        return self.OPTIONAL_HEADER.CheckSum == self.generate_checksum()

    def generate_checksum(self):
        self.__data__ = self.write()
        checksum_offset = self.OPTIONAL_HEADER.__file_offset__ + 64
        checksum = 0
        remainder = len(self.__data__) % 4
        data = self.__data__ + '\x00' * ((4 - remainder) * (remainder != 0))
        for i in range(len(data) / 4):
            if i == checksum_offset / 4:
                continue
            dword = struct.unpack('I', data[i * 4:i * 4 + 4])[0]
            checksum = (checksum & 4294967295L) + dword + (checksum >> 32)
            if checksum > 4294967296L:
                checksum = (checksum & 4294967295L) + (checksum >> 32)

        checksum = (checksum & 65535) + (checksum >> 16)
        checksum = checksum + (checksum >> 16)
        checksum = checksum & 65535
        return checksum + len(self.__data__)

    def is_exe(self):
        """Check whether the file is a standard executable.
        
        This will return true only if the file has the IMAGE_FILE_EXECUTABLE_IMAGE flag set
        and the IMAGE_FILE_DLL not set and the file does not appear to be a driver either.
        """
        EXE_flag = IMAGE_CHARACTERISTICS['IMAGE_FILE_EXECUTABLE_IMAGE']
        if not self.is_dll() and not self.is_driver() and EXE_flag & self.FILE_HEADER.Characteristics == EXE_flag:
            return True
        return False

    def is_dll(self):
        """Check whether the file is a standard DLL.
        
        This will return true only if the image has the IMAGE_FILE_DLL flag set.
        """
        DLL_flag = IMAGE_CHARACTERISTICS['IMAGE_FILE_DLL']
        if DLL_flag & self.FILE_HEADER.Characteristics == DLL_flag:
            return True
        return False

    def is_driver(self):
        """Check whether the file is a Windows driver.
        
        This will return true only if there are reliable indicators of the image
        being a driver.
        """
        if hasattr(self, 'DIRECTORY_ENTRY_IMPORT'):
            if set(('ntoskrnl.exe', 'hal.dll', 'ndis.sys', 'bootvid.dll', 'kdcom.dll')).intersection([ imp.dll.lower() for imp in self.DIRECTORY_ENTRY_IMPORT ]):
                return True
        return False

    def get_overlay_data_start_offset(self):
        """Get the offset of data appended to the file and not contained within the area described in the headers."""
        highest_PointerToRawData = 0
        highest_SizeOfRawData = 0
        for section in self.sections:
            if section.PointerToRawData + section.SizeOfRawData > len(self.__data__):
                continue
            if section.PointerToRawData + section.SizeOfRawData > highest_PointerToRawData + highest_SizeOfRawData:
                highest_PointerToRawData = section.PointerToRawData
                highest_SizeOfRawData = section.SizeOfRawData

        if len(self.__data__) > highest_PointerToRawData + highest_SizeOfRawData:
            return highest_PointerToRawData + highest_SizeOfRawData

    def get_overlay(self):
        """Get the data appended to the file and not contained within the area described in the headers."""
        overlay_data_offset = self.get_overlay_data_start_offset()
        if overlay_data_offset is not None:
            return self.__data__[overlay_data_offset:]

    def trim(self):
        """Return the just data defined by the PE headers, removing any overlayed data."""
        overlay_data_offset = self.get_overlay_data_start_offset()
        if overlay_data_offset is not None:
            return self.__data__[:overlay_data_offset]
        return self.__data__[:]

    def adjust_FileAlignment(self, val, file_alignment):
        global FileAlignment_Warning
        if file_alignment > FILE_ALIGNEMNT_HARDCODED_VALUE:
            if not power_of_two(file_alignment) and FileAlignment_Warning is False:
                self.__warnings.append('If FileAlignment > 0x200 it should be a power of 2. Value: %x' % file_alignment)
                FileAlignment_Warning = True
        if file_alignment < FILE_ALIGNEMNT_HARDCODED_VALUE:
            return val
        return val / 512 * 512

    def adjust_SectionAlignment(self, val, section_alignment, file_alignment):
        global SectionAlignment_Warning
        if file_alignment < FILE_ALIGNEMNT_HARDCODED_VALUE:
            if file_alignment != section_alignment and SectionAlignment_Warning is False:
                self.__warnings.append('If FileAlignment(%x) < 0x200 it should equal SectionAlignment(%x)' % (file_alignment, section_alignment))
                SectionAlignment_Warning = True
        if section_alignment < 4096:
            section_alignment = file_alignment
        if section_alignment and val % section_alignment:
            return section_alignment * (val / section_alignment)
        return val

