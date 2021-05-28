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
void *map_start;
struct stat fd_stat;
Elf32_Ehdr *header;
char magicNum[4] = {0x7E, 0x45, 0x4c, 0x46};

typedef struct
{
  char debug_mode;
  char file_name[NAME_LEN];
  int unit_size;
  unsigned char mem_buf[BUF_SZ];
  size_t mem_count;
  /*
   .
   .
   Any additional fields you deem necessary
  */
} state;

struct fun_desc
{
  char *name;
  void (*fun)(state *);
};

void debugMode(state *s)
{
  if (s->debug_mode == 0)
  {
    puts("Debug flag now on\n");
    s->debug_mode = 1;
  }
  else
  {
    puts("Debug flag now off\n");
    s->debug_mode = 0;
  }
}

char *bigOrlittle(char c)
{
  if (c == 1)
    return "little endian";
  if (c == 2)
    return "big endian";
  return "invalid data encodeing";
}

void examineELFFile(state *s)
{
  fputs("Enter file name:\n", stdout);
  fgets(s->file_name, NAME_LEN, stdin);
  char *end = strchr(s->file_name, '\n');
  if (end != NULL)
  {
    *end = '\0';
  }

  if (s->debug_mode)
  {
    printf("Debug: file name set to %s\n", s->file_name);
  }
  if (CurrentFD != -1)
  {
    close(CurrentFD);
  }
  
  CurrentFD = open(s->file_name, O_RDWR, 0777);
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

  munmap(map_start, fd_stat.st_size);
  close(CurrentFD);
  
  }

void printSectionNames(state *s)
{
  int num;
  char choose[3];
  puts("input number:");
  fgets(choose, 3, stdin);
  num = atoi(choose);
  if (num == 1 || num == 2 || num == 4)
  {
    s->unit_size = num;
    if (s->debug_mode)
    {
      printf("Debug: set size to %d\n", num);
    }
  }
  else
  {
    fputs("error! invalid unit size given.\n", stdout);
  }
}

void quit(state *s)
{
  if (s->debug_mode)
  {
    puts("quitting\n");
  }
  free(s);
  exit(0);
}

void printSymbols(state *s)
{
  FILE *fd;
  int location;
  int length;
  char input[10000];
  if (strcmp(s->file_name, "") == 0)
  {
    fputs("error! no file name!\n", stderr);
    return;
  }
  fd = fopen(s->file_name, "rb");
  if (fd == NULL)
  {
    printf("failed opening file: %s\n", s->file_name);
    return;
  }
  puts("Please enter <location> <length>\n");
  fgets(input, 10000, stdin);
  sscanf(input, "%x %d", &location, &length);
  if (s->debug_mode)
  {
    printf("file name: %s, location given: %x, length given:%d\n", s->file_name, location, length);
  }
  fseek(fd, location, SEEK_SET);
  int readd = fread(s->mem_buf, s->unit_size, length, fd);
  printf("loaded %d units into memory\n", readd);
  fclose(fd);
}

char *unit_to_formatx(int unit)
{
  switch (unit)
  {
  case 1:
    return "%#hhx\n";
  case 2:
    return "%#hx\n";
  case 4:
    return "%#hhx\n";
  default:
    return "Unknown unit";
  }
}

char *unit_to_formatd(int unit)
{
  switch (unit)
  {
  case 1:
    return "%#hhd\n";
  case 2:
    return "%#hd\n";
  case 4:
    return "%#hhd\n";
  default:
    return "Unknown unit";
  }
}

void relocationTables(state *s)
{
  int address, length, fd;
  char input[10000];
  puts("Enter address and length\n");
  fgets(input, 10000, stdin);
  sscanf(input, "%x %d", &address, &length);
  char *buffer;
  char *end;
  if (address == 0)
  {
    buffer = s->mem_buf;
    end = buffer + s->unit_size * length;
  }
  else
  {
    buffer = (char *)address;
    printf("the buffer is: %x\n", (unsigned int)buffer);
  }
  puts("Hexadecimal");
  puts("===========");

  while (buffer < end)
  {
    //print ints
    int var = *((int *)(buffer));
    fprintf(stdout, unit_to_formatx(s->unit_size), var);
    buffer += s->unit_size;
  }
  puts("\n");
  buffer = s->mem_buf;
  puts("decimal");
  puts("=======");
  while (buffer < end)
  {
    //print ints
    int var = *((int *)(buffer));

    fprintf(stdout, unit_to_formatd(s->unit_size), var);
    buffer += s->unit_size;
  }
  puts("\n");
}


int main(int argc, char **argv)
{

  struct fun_desc array[] = {{"Toggle Debug Mode", &debugMode}, {"Examine ELF File", &examineELFFile}, {"Print Section Names", &printSectionNames}, {"Print Symbols", &printSymbols}, {"Relocation Tables", &relocationTables}, {"Quit", &quit}, {NULL, NULL}};

  state *s = calloc(1, sizeof(state));
  s->unit_size = 1;
  s->debug_mode = 0;
  int size, i = 0, num;
  char choose[20] ,c;
  char *name;
  while (1)
  {
    int num=0;
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
    fputs("Option: ", stdout);
    fgets(choose, sizeof(choose), stdin);
    num = atoi(choose);
    if ( choose[0] == '\n' || num > size || num < 0)
    {
      printf("the input: %x not valid\n", num);
      fputs("Not within bounds!\n", stdout);
      free(s);
      exit(1);
    }
    array[num].fun(s);
  }
}