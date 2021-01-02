#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/swap.h>
#include <mach-o/fat.h>
#include <iostream>
#include <vector>

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
        std::cout << sect->segname << "." << sect->sectname << " : 0x" << std::hex << sect->offset << std::endl;
        ret.push_back(sect);
    }
    return ret;
}

void dumpSegmentCommands(FILE* file, off_t offset, bool isSwap, uint32_t ncmds)
{
    off_t actualOffset = offset;
    for (uint32_t i = 0U; i < ncmds; i++)
    {
        load_command* command = (load_command*)loadBytes(file, actualOffset, sizeof(load_command));
        if (command->cmd == LC_SEGMENT_64)
        {
            segment_command_64* segment = (segment_command_64*)loadBytes(file, actualOffset, sizeof(segment_command_64));
            uint32_t sectionOffset = actualOffset + sizeof(segment_command_64);

            std::cout << segment->segname << std::endl;
            std::vector<section_64*> sects = dumpSections<section_64>(file, sectionOffset, (int)segment->nsects);
        }
        else if (command->cmd == LC_SEGMENT)
        {
            segment_command_64* segment = (segment_command_64*)loadBytes(file, actualOffset, sizeof(segment_command_64));
            uint32_t sectionOffset = actualOffset + sizeof(segment_command_64);

            std::cout << segment->segname << std::endl;
            std::vector<section*> sects = dumpSections<section>(file, sectionOffset, (int)segment->nsects);
        }

        actualOffset += command->cmdsize;
    }
}

void dumpMachHeader(FILE* file, off_t offset, bool is64, bool isSwap)
{
    uint32_t ncmds;
    off_t loadCommandsOffset = offset;
    if (is64)
    {
        size_t headerSize = sizeof(mach_header_64);
        mach_header_64* header = (mach_header_64*)loadBytes(file, offset, headerSize);
        if (isSwap)
        {
            swap_mach_header_64(header, NX_UnknownByteOrder);
        }
        std::cout << getCPUName(header->cputype) << std::endl;
        loadCommandsOffset += headerSize;
        ncmds = header->ncmds;
    }
    else {
        size_t headerSize = sizeof(mach_header);
        mach_header* header = (mach_header*)loadBytes(file, offset, headerSize);
        if (isSwap)
        {
            swap_mach_header(header, NX_UnknownByteOrder);
        }
        std::cout << getCPUName(header->cputype) << std::endl;
        loadCommandsOffset += headerSize;
        ncmds = header->ncmds;
    }

    dumpSegmentCommands(file, loadCommandsOffset, isSwap, ncmds);
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
        dumpMachHeader(file, machHeaderOffset, is64, isSwap);
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
        dumpMachHeader(file, 0, is64, swap);
    }
}

int main()
{
    FILE* file = fopen("wow", "rb");
    std::cout << file << std::endl;
    dumpSegments(file);
}