ENTRY(nomain)
SECTIONS
{
. = 0x804800 + SIZEOF_HEADERS;
tinytext : { *(.text) *(.data) *(.rodata)}
/DISCARD/ :{*(.comment)}
}
