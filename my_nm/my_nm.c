
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

const char *get_type(unsigned char type)
{
    const char *types[] = {
        "STT_NOTYPE", "STT_OBJECT", "STT_FUNC",   "STT_SECTION",
        "STT_FILE",   "STT_COMMON", "STT_TLS",    "STT_NUM",
        "STT_LOOS",   "STT_HIOS",   "STT_LOPROC", "STT_HIPROC",
    };
    return types[type];
}

const char *get_bind(unsigned char bind)
{
    const char *binds[] = {
        "STB_LOCAL", "STB_GLOBAL", "STB_WEAK",   "STB_NUM",
        "STB_LOOS",  "STB_HIOS",   "STB_LOPROC", "STB_HIPROC",
    };
    return binds[bind];
}

const char *get_visibility(unsigned char vis)
{
    const char *visibilities[] = {
        "STV_DEFAULT",
        "STV_INTERNAL",
        "STV_HIDDEN",
        "STV_PROTECTED",
    };
    return visibilities[vis];
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    char *path = argv[1];

    int fd = open(path, O_RDONLY);
    if (fd == -1)
        return 1;

    struct stat st;

    if (fstat(fd, &st) == -1)
        return 1;

    char *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    if (map == MAP_FAILED)
        return 1;

    close(fd);

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;

    if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0)
    {
        munmap(map, st.st_size);
        return 1;
    }

    unsigned long offset = ehdr->e_shoff;
    Elf64_Shdr *sections = (Elf64_Shdr *)(map + offset);
    char *section_names = map + (&sections[ehdr->e_shstrndx])->sh_offset;
    Elf64_Shdr *symtab_hdr = NULL;
    Elf64_Shdr *strtab_hdr = NULL;
    for (unsigned short i = 0; i < ehdr->e_shnum; i++)
    {
        if (sections[i].sh_type == SHT_SYMTAB)
            symtab_hdr = &sections[i];
        else if (sections[i].sh_type == SHT_STRTAB
                 && strcmp(section_names + sections[i].sh_name, ".strtab") == 0)
            strtab_hdr = &sections[i];
    }

    if (symtab_hdr == NULL || strtab_hdr == NULL)
        return 1;

    Elf64_Sym *symtab = (Elf64_Sym *)(map + symtab_hdr->sh_offset);
    const char *strtab = (char *)(map + strtab_hdr->sh_offset);
    unsigned long nb_symbols = symtab_hdr->sh_size / sizeof(Elf64_Sym);

    for (unsigned long i = 0; i < nb_symbols; i++)
    {
        unsigned char type = ELF64_ST_TYPE(symtab[i].st_info);
        unsigned char bind = ELF64_ST_BIND(symtab[i].st_info);
        unsigned char vis = ELF64_ST_VISIBILITY(symtab[i].st_other);

        if (type == STT_FILE)
            continue;

        const char *section_name = NULL;
        if (symtab[i].st_shndx == SHN_UNDEF)
            section_name = "UND";
        else
            section_name = section_names + sections[symtab[i].st_shndx].sh_name;

        printf("%016lx\t%lu\t%s\t%s\t%s\t%s\t%s\n", symtab[i].st_value,
               symtab[i].st_size, get_type(type), get_bind(bind),
               get_visibility(vis), section_name, strtab + symtab[i].st_name);
    }
    munmap(map, st.st_size);
    return 0;
}
