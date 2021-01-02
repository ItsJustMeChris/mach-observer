#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/swap.h>
#include <mach-o/fat.h>
#include <iostream>
#include <vector>
#include <iterator>
#include <algorithm>

uint32_t readMagic(FILE* file, off_t offset)
{
    uint32_t magic;
    fseek(file, offset, SEEK_SET);
    fread(&magic, sizeof(uint32_t), 1, file);
    return magic;
}

bool isMagic64(uint32_t magic)
{
    return magic == MH_MAGIC_64 || MH_CIGAM_64;
}

bool isFat(uint32_t magic)
{
    return magic == FAT_MAGIC || magic == FAT_CIGAM;
}

bool shouldSwapBytes(uint32_t magic)
{
    return magic == MH_CIGAM || magic == MH_CIGAM_64 || magic == FAT_CIGAM;
}

const char* getCPUName(cpu_type_t CPUType)
{
    switch (CPUType)
    {
    case CPU_TYPE_I386:
        return "i386";
    case CPU_TYPE_X86_64:
        return "x86_64";
    case CPU_TYPE_ARM:
        return "arm";
    case CPU_TYPE_ARM64:
        return "arm64";
    default:
        return "unknown";
    }
}

void* loadBytes(FILE* file, off_t offset, size_t size)
{
    void* buff = calloc(1, size);
    fseek(file, offset, SEEK_SET);
    fread(buff, size, 1, file);
    return buff;
}

template <typename T>
std::vector<T*> dumpSections(FILE* file, off_t offset, int nsects)
{
    std::vector<T*> ret;
    uint32_t sectSize = sizeof(T);
    off_t sectionOffset = offset;
    for (int i = 0; i < (int)nsects;i++)
    {
        T* sect = (T*)loadBytes(file, sectionOffset, sectSize);
        sectionOffset += sectSize;
        ret.push_back(sect);
    }
    return ret;
}

template<typename T, typename S>
struct _segments {
    bool is64;
    uint64_t rebase;

    std::vector<T*> segments;
    std::vector<S*> sections;
};

template<typename A, typename T>
_segments<A, T> dumpSegmentCommands(FILE* file, off_t offset, int ncmds)
{
    _segments<A, T> ret;

    ret.is64 = typeid(T) == typeid(section_64);

    off_t actualOffset = offset;
    for (int i = 0; i < ncmds; i++)
    {
        load_command* command = (load_command*)loadBytes(file, actualOffset, sizeof(load_command));
        if (command->cmd == LC_SEGMENT_64)
        {
            A* segment = (A*)loadBytes(file, actualOffset, sizeof(A));
            ret.segments.push_back(segment);

            if (std::string(segment->segname) == "__PAGEZERO")
            {
                ret.rebase = segment->vmsize;
            }
            uint32_t sectionOffset = actualOffset + sizeof(A);

            std::cout << segment->segname << std::endl;
            std::vector<T*> sects = dumpSections<T>(file, sectionOffset, (int)segment->nsects);
            std::copy(sects.begin(), sects.end(), back_inserter(ret.sections));
        }
        actualOffset += command->cmdsize;
    }
    return ret;
}

template<typename H, typename A, typename T>
struct _header
{
    H* header;
    _segments<A, T> segments;
    const char* CPUName;
};

template<typename H, typename A, typename T>
_header<H, A, T> dumpMachHeader(FILE* file, off_t offset, bool isSwap)
{
    _header<H, A, T> ret;
    off_t loadCommandsOffset = offset;
    size_t headerSize = sizeof(H);
    H* header = (H*)loadBytes(file, offset, headerSize);
    if (isSwap && typeid(H) == typeid(mach_header))
    {
        swap_mach_header((mach_header*)header, NX_UnknownByteOrder);
    }
    else if (isSwap && typeid(H) == typeid(mach_header_64))
    {
        swap_mach_header_64((mach_header_64*)header, NX_UnknownByteOrder);
    }

    loadCommandsOffset += headerSize;

    ret.header = header;
    ret.CPUName = getCPUName(header->cputype);
    ret.segments = dumpSegmentCommands<A, T>(file, loadCommandsOffset, header->ncmds);

    return ret;
}


template<typename H, typename A, typename T>
_header<H, A, T> dumpFatArch(FILE* file, bool isSwap, cpu_type_t cpu)
{
    size_t header_size = sizeof(fat_header);
    size_t archSize = sizeof(fat_arch);
    fat_header* header = (fat_header*)loadBytes(file, 0, header_size);
    if (isSwap)
    {
        swap_fat_header(header, NX_UnknownByteOrder);
    }

    off_t archOffset = (off_t)header_size;
    for (uint32_t i = 0U; i < header->nfat_arch; i++)
    {
        fat_arch* arch = (fat_arch*)loadBytes(file, archOffset, archSize);
        if (isSwap)
        {
            swap_fat_arch(arch, 1, NX_UnknownByteOrder);
        }

        off_t machHeaderOffset = (off_t)arch->offset;
        archOffset += archSize;

        uint32_t magic = readMagic(file, machHeaderOffset);
        bool is64 = isMagic64(magic);
        bool isSwap = shouldSwapBytes(magic);

        if (arch->cputype == cpu)
        {
            return dumpMachHeader<H, A, T>(file, machHeaderOffset, isSwap);
        }
    }
}

void dumpFatMachHeader(FILE* file, bool isSwap)
{
    size_t header_size = sizeof(fat_header);
    size_t archSize = sizeof(fat_arch);
    fat_header* header = (fat_header*)loadBytes(file, 0, header_size);
    if (isSwap)
    {
        swap_fat_header(header, NX_UnknownByteOrder);
    }

    off_t archOffset = (off_t)header_size;
    for (uint32_t i = 0U; i < header->nfat_arch; i++)
    {
        fat_arch* arch = (fat_arch*)loadBytes(file, archOffset, archSize);
        if (isSwap)
        {
            swap_fat_arch(arch, 1, NX_UnknownByteOrder);
        }

        off_t machHeaderOffset = (off_t)arch->offset;
        archOffset += archSize;

        uint32_t magic = readMagic(file, machHeaderOffset);
        bool is64 = isMagic64(magic);
        bool isSwap = shouldSwapBytes(magic);

        if (is64)
        {
            _header<mach_header_64, segment_command_64, section_64> a = dumpMachHeader<mach_header_64, segment_command_64, section_64>(file, machHeaderOffset, isSwap);
            for (section_64* sect : a.segments.sections)
            {
                std::cout << sect->segname << "." << sect->sectname << std::endl;
            }
        }
        else
        {
            _header<mach_header, segment_command, section> a = dumpMachHeader<mach_header, segment_command, section>(file, machHeaderOffset, isSwap);
        }
    }
}

void dumpSegments(FILE* file)
{
    uint32_t magic = readMagic(file, 0);
    std::cout << "Read magic " << magic << std::endl;
    bool swap = shouldSwapBytes(magic);
    bool fat = isFat(magic);
    bool is64 = isMagic64(magic);
    if (fat)
    {
        dumpFatMachHeader(file, swap);
    }
    else
    {
        if (is64)
        {
            _header<mach_header_64, segment_command_64, section_64> a = dumpMachHeader<mach_header_64, segment_command_64, section_64>(file, 0, swap);
        }
        else
        {
            _header<mach_header, segment_command, section> a = dumpMachHeader<mach_header, segment_command, section>(file, 0, swap);
        }
    }
}

int main()
{
    FILE* file = fopen("wow", "rb");

    uint32_t magic = readMagic(file, 0);
    bool swap = shouldSwapBytes(magic);

    _header<mach_header_64, segment_command_64, section_64> a = dumpFatArch<mach_header_64, segment_command_64, section_64>(file, swap, CPU_TYPE_X86_64);
    for (section_64* sect : a.segments.sections)
    {
        std::cout << sect->segname << "." << sect->sectname << " offset: 0x" << std::hex << sect->addr - a.segments.rebase << std::endl;
    }

    // dumpSegments(file);
}