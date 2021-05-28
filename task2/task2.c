#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>
#define NAME_LEN 128
#define BUF_SZ 10000

int CurrentFD = -1;
int debug_mode = 0;
void *map_start;
struct stat fd_stat;
Elf32_Ehdr *header;
char magicNum[4] = {0x7E, 0x45, 0x4c, 0x46};

struct fun_desc
{
  char *name;
  void (*fun)();
};

void debugMode()
{
  if (debug_mode == 0)
  {
    puts("Debug flag now on\n");
    debug_mode = 1;
  }
  else
  {
    puts("Debug flag now off\n");
    debug_mode = 0;
  }
}

char *bigOrlittle(char c)
{
  if (c == 1)
    return "2's complement, little endian";
  if (c == 2)
    return "2's complement, big endian";
  return "invalid data encodeing";
}

void examineELFFile()
{
  char file_name[NAME_LEN];
  fputs("Enter file name:\n", stdout);
  fgets(file_name, NAME_LEN, stdin);
  char *end = strchr(file_name, '\n');
  if (end != NULL)
  {
    *end = '\0';
  }

  if (debug_mode)
  {
    printf("Debug: file name set to %s\n", file_name);
  }
  if (CurrentFD != -1)
  {
    munmap(map_start, fd_stat.st_size);
    close(CurrentFD);
  }

  CurrentFD = open(file_name, O_RDWR, 0777);
  if (CurrentFD < 0)
  {
    perror("error in open");
    exit(-1);
  }

  if (fstat(CurrentFD, &fd_stat) != 0)
  {
    perror("stat failed");
    exit(-1);
  }

  if ((map_start = mmap(0, fd_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, CurrentFD, 0)) == MAP_FAILED)
  {
    perror("mmap failed");
    exit(-4);
  }
  header = (Elf32_Ehdr *)map_start;
  printf("the magic number:\t\t%x %x %x\n", header->e_ident[1], header->e_ident[2], header->e_ident[3]);
  if (strncmp("ELF", header->e_ident + 1, 3))
  {
    perror("not an ELF file");
    munmap(map_start, fd_stat.st_size);
    close(CurrentFD);
    CurrentFD = -1;
    return;
  }
  printf("The data encoding scheme is:\t%s \n", bigOrlittle(header->e_ident[EI_DATA]));
  printf("The entry point is:\t\t%x \n", header->e_entry);
  printf("The section header table offset is:\t%d\n", header->e_shoff);
  printf("The number of section header entries:\t%d\n", header->e_shnum);
  printf("The size of each section header entry:\t%d\n", header->e_shentsize);
  printf("The file offset in which the program header table resides:\t%d\n", header->e_phoff);
  printf("The number of program header entries:\t%d\n", header->e_phnum);
  printf("The size of each program header entry:\t%d\n", header->e_phentsize);
}

char *findType(int num)
{
  switch (num)
  {
  case 0:
    return "NULL";
  case 1:
    return "PROGBITS";
  case 2:
    return "SYMTAB";
  case 3:
    return "STRTAB";
  case 4:
    return "RELA";
  case 5:
    return "HASH";
  case 6:
    return "DYNAMIC";
  case 7:
    return "NOTE";
  case 8:
    return "NOBITS";
  case 9:
    return "REL";
  case 10:
    return "SHLIB";
  case 11:
    return "DYNSYM";
  case 0x70000000:
    return "LOPROC";
  case 0x7fffffff:
    return "HIPROC";
  case 0x80000000:
    return "LOUSER";
  case 0xffffffff:
    return "HIUSER";
  default:
    return "UNKNOWN";
  }
}

void printSectionNames()
{
  if (CurrentFD == -1)
  {
    perror("invalid file\n");
    return;
  }
  Elf32_Shdr *sectionH = (Elf32_Shdr *)(map_start + header->e_shoff);
  int shnum = header->e_shnum;

  Elf32_Shdr *stringTable = map_start + header->e_shoff + (header->e_shstrndx * header->e_shentsize);
  char *headerstringtab = map_start + stringTable->sh_offset;
  if (debug_mode)
  {
    printf("the string table adress is %x\n", header->e_shstrndx);
    printf("the section header offset is %d\n", sectionH->sh_offset);
  }
  printf("\tname\t\tadress\t  offset\t  size\ttype\n");
  for (int i = 0; i < shnum; ++i)
  {
    if (!debug_mode)
      printf("[%2d]\t%-15s %4x\t%8x\t%3d\t%8s\n", i, headerstringtab + sectionH[i].sh_name, sectionH[i].sh_addr, sectionH[i].sh_offset, sectionH[i].sh_size, findType(sectionH[i].sh_type));
    else
      printf("[%2d]\t%8x\t%8x\t%-15s %4x\t%8x\t%3d\t%8s\n", i, sectionH[i].sh_offset, stringTable->sh_offset + sectionH[i].sh_name, headerstringtab + sectionH[i].sh_name, sectionH[i].sh_addr, sectionH[i].sh_offset, sectionH[i].sh_size, findType(sectionH[i].sh_type));
  }
}

void quit()
{
  if (debug_mode)
  {
    puts("quitting\n");
  }
  munmap(map_start, fd_stat.st_size);
  close(CurrentFD);
  exit(0);
}

Elf32_Shdr *findTablewithName(char *name)
{
  Elf32_Shdr *output;
  Elf32_Shdr *secheaderstringtable = (Elf32_Shdr *)(map_start + header->e_shoff + header->e_shentsize * header->e_shstrndx);
  output = (Elf32_Shdr *)(map_start + header->e_shoff);
  for (int i = 0; i < header->e_shnum; i++)
  {
    if (!strcmp((char *)(map_start + secheaderstringtable->sh_offset + output->sh_name), name))
    {
      return output;
    }
    output++;
  }
  return NULL;
}

char *findSymbol(int c)
{
  switch (c)
  {
  case SHN_UNDEF:
    return "UND";
  case SHN_ABS:
    return "ABS";
  case SHN_COMMON:
    return "SHN_COMMON";
  default:
    return "UNKNOWN";
  }
}

void printSymbols()
{
  int numofsymbols;
  char * name;
  Elf32_Shdr *sh_pointer;
  Elf32_Shdr *strTablePointer;
  Elf32_Shdr *sh_StrTable;
  Elf32_Shdr *symbol_sh;
  Elf32_Sym *symbol_table_pointer;
  if (CurrentFD == -1)
  {
    fprintf(stderr, "%s\n", "invalid file descriptor");
    return;
  }
  
  sh_StrTable = (Elf32_Shdr *)(map_start + header->e_shoff + header->e_shentsize * header->e_shstrndx);
  sh_pointer = (Elf32_Shdr *)(map_start + header->e_shoff);
  strTablePointer = findTablewithName(".strtab");
  
  if (debug_mode)
  {
    printf("section-header-string-table index: %d\n", header->e_shstrndx);
    printf("section header-string-table offset: %x\n", (int)(sh_StrTable->sh_offset));
    
    printf("section header offset: %x\n", header->e_shoff);
    printf("section header value size: %d\n", header->e_shentsize);
  }

  for (int i = 0; i < header->e_shnum; i++)
  {
    if ((sh_pointer[i].sh_type == SHT_SYMTAB) || (sh_pointer[i].sh_type == SHT_DYNSYM) || (sh_pointer[i].sh_type == SHT_HASH))
    {
      symbol_table_pointer = (Elf32_Sym *)(map_start + sh_pointer[i].sh_offset); //symbol table pointer
      numofsymbols = sh_pointer[i].sh_size / sizeof(Elf32_Sym);    //number of symbols
      if (debug_mode)
      {
        printf("symbol table %s has %d values:\n", (char *)(map_start + sh_StrTable->sh_offset + sh_pointer[i].sh_name), numofsymbols);
      }
      printf("\tvalue\tsection\tindex\tsection name\tsymbol name\n");
      for (int j = 0; j < numofsymbols; j++)
      {
        name = findSymbol(symbol_table_pointer[j].st_shndx);
        if(strncmp("UNKNOWN" , name , 7)){
        printf("[%2d]\t%8x\t%5d\t%-20s\t%-20s\n", j, symbol_table_pointer[j].st_value, symbol_table_pointer[j].st_shndx, name,(char *)(map_start + strTablePointer->sh_offset + symbol_table_pointer[j].st_name));
        }
        else
        {
          symbol_sh = (Elf32_Shdr *)(map_start + header->e_shoff + header->e_shentsize * symbol_table_pointer[j].st_shndx); //get to the symbols section header entry
          printf("[%2d]\t%8x\t%5d\t%-20s\t%-20s\n", j, symbol_table_pointer[j].st_value, symbol_table_pointer[j].st_shndx, (char *)(map_start + sh_StrTable->sh_offset + symbol_sh->sh_name), (char *)(map_start + strTablePointer->sh_offset + symbol_table_pointer[j].st_name));
        }
    
      }
      printf("\n");
    }
  }
}

void relocationTables()
{
}

int main(int argc, char **argv)
{

  struct fun_desc array[] = {{"Toggle Debug Mode", &debugMode}, {"Examine ELF File", &examineELFFile}, {"Print Section Names", &printSectionNames}, {"Print Symbols", &printSymbols}, {"Relocation Tables", &relocationTables}, {"Quit", &quit}, {NULL, NULL}};

  debug_mode = 0;
  int size, i = 0, num;
  char choose[20], c;
  char *name;
  while (1)
  {
    int num = 0;
    name = array[0].name;
    i = 0;
    fputs("Choose action:\n", stdout);
    choose[0] = '\0';
    size = sizeof(array) / sizeof(array[0]) - 1;

    while (i < size)
    {
      printf("%i) %s\n", i, name);
      i++;
      name = array[i].name;
    }
    fputs("Option:", stdout);
    fgets(choose, sizeof(choose), stdin);
    num = atoi(choose);
    if (choose[0] == '\n' || num > size || num < 0)
    {
      printf("the input: %x not valid\n", num);
      fputs("Not within bounds!\n", stdout);
      exit(1);
    }
    array[num].fun();
  }
}
