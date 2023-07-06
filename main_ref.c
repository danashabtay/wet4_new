#include <stdio.h>
#include "elf64.h"

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>


#define	ET_NONE	0	//No file type
#define	ET_REL	1	//Relocatable file
#define	ET_EXEC	2	//Executable file
#define	ET_DYN	3	//Shared object file
#define	ET_CORE	4	//Core file


bool compare_symbol_name(FILE *file, long offset,  const char * wanted) {
    fseek(file, offset, SEEK_SET);

    int i = 0;
    int character = fgetc(file);
    if (character == EOF || character == '\0')
        return false;

    while (character != EOF && character != '\0') {
        if (character != wanted[i]) {
            return false;
        }

        i++;
        character = fgetc(file);
    }
    if (strlen(wanted) != i) {
        return false;
    }

    return true;
}

/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {

    // Open a file to read in binary mode:
    FILE *file = fopen(exe_file_name, "rb");
    if (file == NULL) {
        return 0;
    }

    // Load the ELF file header into a struct:
    Elf64_Ehdr elf_header;
    if(fread(&elf_header, sizeof(elf_header), 1, file) != 1){
        fclose(file);
        return -1;
    }

    // Check if it's an executable:
    if(elf_header.e_type != ET_EXEC){
        *error_val = -3;
        return 0;
    }

    // Set the file position indicator to the start of the Section header table:
    fseek(file, (long) elf_header.e_shoff, SEEK_SET);

    // Read all section headers into an array:
    Elf64_Shdr *section_headers = malloc(sizeof (Elf64_Shdr) * elf_header.e_shnum);
    if(fread(section_headers, sizeof(Elf64_Shdr), elf_header.e_shnum, file) != elf_header.e_shnum) {
        free(section_headers);
        fclose(file);
        return -1;
    }

    // Go over all the sections:
    int symtab_i = -1;
    int strtab_i = -1;
    for (int i = 0; i < elf_header.e_shnum; ++i) {
        // Read the current section:
        Elf64_Shdr current_section_header = section_headers[i];
        unsigned long shstrtab_offset = section_headers[elf_header.e_shstrndx].sh_offset;
        bool is_strtab = compare_symbol_name(file, (long) shstrtab_offset + current_section_header.sh_name, ".strtab");

        if (current_section_header.sh_type == 2) {
            symtab_i = i;
        } else if (is_strtab) {
            strtab_i = i;
        }
    }

    if (symtab_i == -1 || strtab_i == -1) {
        free(section_headers);
        fclose(file);
        return -1;
    }

    // Set the file position indicator to the start of the Symbol Table (this section):
    fseek(file, (long) section_headers[symtab_i].sh_offset, SEEK_SET);

    unsigned long symbol_entry_size = section_headers[symtab_i].sh_entsize;
    unsigned long num_of_symbols = section_headers[symtab_i].sh_size / symbol_entry_size;
    // Get all the symbols in an array:
    Elf64_Sym *symbols = malloc(sizeof (Elf64_Sym) * num_of_symbols);
    if(fread(symbols, sizeof(Elf64_Sym), num_of_symbols, file) != num_of_symbols){
        free(section_headers);
        free(symbols);
        fclose(file);
        return -1;
    }

    int wanted_symbol_bind = -1;
    unsigned long load_address = 0;
    // Go over all the symbols:
    for (int i = 0; i < num_of_symbols; ++i) {
        Elf64_Sym current_symbol = symbols[i];

        // Compare the symbol name:
        long strtab_offset = (long) section_headers[strtab_i].sh_offset;
        bool is_wanted_symbol = compare_symbol_name(file, strtab_offset + current_symbol.st_name, symbol_name);

        if (is_wanted_symbol) {
            if (ELF64_ST_BIND(current_symbol.st_info) == 0 || ELF64_ST_BIND(current_symbol.st_info) == 1) {
                if (wanted_symbol_bind != 1) {
                    wanted_symbol_bind = ELF64_ST_BIND(current_symbol.st_info);
                    load_address = current_symbol.st_value;
                }
            }
        }
    }

    if (wanted_symbol_bind == -1) {
        *error_val = -1;
    } else if (wanted_symbol_bind == 0) {
        *error_val = -2;
    } else if (wanted_symbol_bind == 1) {
        if (load_address > 0) {  // TODO Check if we should change the check to whether Ndx != UND
            *error_val = 1;
        } else {
            *error_val = -4;
        }
    }

    free(symbols);
    free(section_headers);
    fclose(file);

    return load_address;
}

unsigned long find_extern_address(char* symbol_name, char* exe_file_name) {
    // Open a file to read in binary mode:
    FILE *file = fopen(exe_file_name, "rb");
    if (file == NULL) {
        return 0;
    }

    // Load the ELF file header into a struct:
    Elf64_Ehdr elf_header;
    if(fread(&elf_header, sizeof(elf_header), 1, file) != 1){
        fclose(file);
        return -1;
    }

    // Set the file position indicator to the start of the Section header table:
    fseek(file, (long) elf_header.e_shoff, SEEK_SET);

    // Read all section headers into an array:
    Elf64_Shdr *section_headers = malloc(sizeof (Elf64_Shdr) * elf_header.e_shnum);
    if(fread(section_headers, sizeof(Elf64_Shdr), elf_header.e_shnum, file) != elf_header.e_shnum) {
        free(section_headers);
        fclose(file);
        return -1;
    }


    // Go over all the sections:
    for (int i = 0; i < elf_header.e_shnum; ++i) {
        // Read the current section:
        Elf64_Shdr current_section_header = section_headers[i];
        unsigned long shstrtab_offset = section_headers[elf_header.e_shstrndx].sh_offset;

        // Check if the section is of type RELA:
        if (current_section_header.sh_type == 4) {
            Elf64_Shdr symtable = section_headers[current_section_header.sh_link];

            // Set the file position indicator to the start of the Symbol Table (this section):
            fseek(file, (long) symtable.sh_offset, SEEK_SET);

            unsigned long symbol_entry_size = symtable.sh_entsize;
            unsigned long num_of_symbols = symtable.sh_size / symbol_entry_size;
            // Get all the symbols in an array:
            Elf64_Sym *symbols = malloc(sizeof (Elf64_Sym) * num_of_symbols);
            if(fread(symbols, sizeof(Elf64_Sym), num_of_symbols, file) != num_of_symbols){
                free(section_headers);
                free(symbols);
                fclose(file);
                return -1;
            }

            Elf64_Shdr strtable = section_headers[symtable.sh_link];
            // Compare the symbol name:
            long strtab_offset = (long) strtable.sh_offset;

            // Set the file position indicator to the start of the relocation table (this section):
            fseek(file, (long) current_section_header.sh_offset, SEEK_SET);

            unsigned long relocation_entry_size = current_section_header.sh_entsize;
            unsigned long num_of_relocations = current_section_header.sh_size / relocation_entry_size;
            // Get all the symbols in an array:
            Elf64_Rela *relocations = malloc(sizeof (Elf64_Rela) * num_of_relocations);
            if(fread(relocations, sizeof(Elf64_Rela), num_of_relocations, file) != num_of_relocations){
                free(section_headers);
                free(symbols);
                free(relocations);
                fclose(file);
                return -1;
            }

            for (int j = 0; j < num_of_relocations; ++j) {
                Elf64_Rela current_relocation = relocations[j];
                int index_in_symbols = ELF64_R_SYM(current_relocation.r_info);

                bool is_wanted_symbol = compare_symbol_name(file, strtab_offset + symbols[index_in_symbols].st_name, symbol_name);

                if (is_wanted_symbol) {
                    return current_relocation.r_offset;
                }
            }
        }
    }

    return -1;
}

pid_t run_target(const char* programname, char *const argv[])
{
    pid_t pid = fork();

    if (pid > 0) {
        return pid;
    } else if (pid == 0) {
        /* Allow tracing of this process */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        /* Replace this process's image with the given program */
        execv(programname, argv);
    } else {
        // fork error
        perror("fork");
        exit(1);
    }
}



void run_debugger(pid_t child_pid, unsigned long address, bool is_extern)
{
    int wait_status;
    struct user_regs_struct regs;
    int call_counter = 0;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);

    /* Get the actual address of symbol */
    unsigned long new_address = address;

    unsigned long start_rsp;
    unsigned long instruction;
    unsigned long return_address;
    while(!WIFEXITED(wait_status)) {
        if (is_extern) {
            unsigned long got_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) address, NULL);
            if (call_counter == 0) {
                new_address = got_data - 6;
            } else {
                new_address = got_data;
            }
        }

        instruction = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) new_address, NULL);

        /* Write the trap instruction 'int 3' into the address */
        unsigned long data_trap = (instruction & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void *) new_address, (void *) data_trap);

        /* Let the child run to the breakpoint and wait for it to reach it */
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);

        wait(&wait_status);
        if (WIFEXITED(wait_status))
            break;

        call_counter++;

        /* Arrived at the plt, print the first argument */
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        printf("PRF:: run #%d first parameter is %d\n", call_counter, (int) regs.rdi);

        start_rsp = regs.rsp;

        /* Remove the breakpoint by restoring the previous data and set rdx = 5 */
        ptrace(PTRACE_POKETEXT, child_pid, (void *) new_address, (void *) instruction);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

        return_address = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) start_rsp, NULL);
        //printf("Return address: %lu\n", return_address);

        instruction = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) return_address, NULL);
        //printf("Return instruction: %lu\n", instruction);

        /* Write the trap instruction 'int 3' into the address */
        unsigned long data_trap2 = (instruction & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void *) return_address, (void *) data_trap2);

        /* Let the child run to the breakpoint and wait for it to reach it */
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);

        wait(&wait_status);
        if (WIFEXITED(wait_status))
            break;

        /* Arrived at the plt, print the first argument */
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

        /* Remove the breakpoint by restoring the previous data and set rdx = 5 */
        ptrace(PTRACE_POKETEXT, child_pid, (void *) return_address, (void *) instruction);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

        while (regs.rsp < start_rsp - 8) {
            ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        }

        /* Write the trap instruction 'int 3' into the address */
        data_trap2 = (instruction & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void *) return_address, (void *) data_trap2);

        /* Let the child run to the breakpoint and wait for it to reach it */
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);

        wait(&wait_status);
        if (WIFEXITED(wait_status))
            break;

        /* Arrived at the plt, print the first argument */
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

        printf("PRF:: run #%d returned with %d\n", call_counter, (int) regs.rax);

        /* Remove the breakpoint by restoring the previous data and set rdx = 5 */
        ptrace(PTRACE_POKETEXT, child_pid, (void *) return_address, (void *) instruction);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

        new_address = address;
    }

    /* The child can continue running now */
    ptrace(PTRACE_CONT, child_pid, 0, 0);

    wait(&wait_status);
}

void step6(unsigned long address, char* symbol_name, char* exe_file_name, char *const argv[], bool is_extern) {
    pid_t child_pid;
    child_pid = run_target(exe_file_name, argv);

    run_debugger(child_pid, address, is_extern);
}



int main(int argc, char *const argv[]) {
    int err = 0;
    unsigned long addr = find_symbol(argv[1], argv[2], &err);

    bool is_extern = false;

    if (err == -2)
        printf("PRF:: %s is not a global symbol!\n", argv[1]);
    else if (err == -1)
        printf("PRF:: %s not found! :(\n", argv[1]);
    else if (err == -3)
        printf("PRF:: %s not an executable!\n", argv[2]);
    else
    {
        if (err == -4) {
            is_extern = true;
            addr = find_extern_address(argv[1], argv[2]);
        }

        step6(addr, argv[1], argv[2], argv + 2, is_extern);
    }

    return 0;
}
