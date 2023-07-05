//
// Created by user on 05/07/2023.
//

#include "elf64.h"
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>


#define	ET_NONE	0	//No file type
#define	ET_REL	1	//Relocatable file
#define	ET_EXEC	2	//Executable file
#define	ET_DYN	3	//Shared object file
#define	ET_CORE	4	//Core file

bool comparing_name(FILE* file,unsigned long offset_to_name,const char* symbol_name_given){
    fseek(file,offset_to_name,SEEK_SET);
    int sym_char_strtab =fgetc(file);
    int j=0;
    while(sym_char_strtab!= EOF && sym_char_strtab != '\0') {
        if(sym_char_strtab!=symbol_name_given[j]) {
            return false;
        }
        j++;
        sym_char_strtab=fgetc(file);
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
    FILE *file = fopen(exe_file_name, "rb");
    if (file == NULL) {
        return -1;
    }

    Elf64_Ehdr elf_header;
    if(fread(&elf_header, sizeof(elf_header), 1, file)!=1){
        fclose(file);
        return -1;
    }
    Elf64_Half elf_type = elf_header.e_type;

    //check if the type is exe:
    if (elf_type != ET_EXEC) {
        *error_val = -3;
        fclose(file);
        return -1;
    }

    //else, the ELF file is an exe file:
    // find section table offset from beginning of file:
    Elf64_Off section_offset=elf_header.e_shoff;
    // size of entry in section table:
    Elf64_Half section_size=elf_header.e_shentsize; //not used
    //num of entries in section table:
    Elf64_Half section_num=elf_header.e_shnum;

    Elf64_Shdr* section_header_table=malloc(sizeof(Elf64_Shdr)*section_num);
    /**setting file to point at the start of section header table**/
    fseek(file,(long) section_offset, SEEK_SET);
    if(fread(section_header_table,sizeof(Elf64_Shdr),section_num,file)!=section_num){
        free(section_header_table);
        fclose(file);
        return -1;
    }

    //find SYMTAB index inside section header table:
    int symtab_index=-1;
    for(int i=0;i<section_num;++i){
        if(section_header_table[i].sh_type==2) {
            symtab_index=i;
        }
    }
    if (symtab_index==-1){
        free(section_header_table);
        fclose(file);
        return -1;
    }

    /**file curr at the start of section table**/

    //offset of symtable from beginning of file:
    Elf64_Off symtable_offset = section_header_table[symtab_index].sh_offset;
    // entry size of symbol in symbol table:
    Elf64_Xword entry_size_symtable = section_header_table[symtab_index].sh_entsize;
    // symbol table size:
    Elf64_Xword sym_table_size = section_header_table[symtab_index].sh_size;
    // num of section in section header table that is the string table belonging to symtable - strtable:
    Elf64_Word sym_table_link = section_header_table[symtab_index].sh_link;
    //saving the index of strtab (which is the link of symtab)
    int strtab_index=(int)sym_table_link;

    unsigned long num_symbols = sym_table_size/entry_size_symtable; //Elf64_Xword for num symbols

    //create sym_table:
    Elf64_Sym* symbol_table=malloc(sizeof(Elf64_Sym)*num_symbols);
    /**setting file to point at the start of symbol table**/
    fseek(file, (long)symtable_offset,SEEK_SET);

    //reading symbol table from file and saving it
    if(fread(symbol_table, sizeof(Elf64_Sym), num_symbols, file)!=num_symbols){
        fclose(file);
        free(section_header_table);
        free(symbol_table);
        return -1;
    }

    //iterate over sym_table:
    Elf64_Off strtab_offset=section_header_table[strtab_index].sh_offset;
    int flag = 0;
    unsigned long address=0;
    for(int i=0;i<num_symbols;++i){
        //comparing symbol name:
        if(comparing_name(file,strtab_offset+(symbol_table[i].st_name),symbol_name)==true){
            if(ELF64_ST_BIND(symbol_table[i].st_info)==1){ //GLOBAL
                if(symbol_table[i].st_shndx==0){ //NOT IN FILE
                    *error_val = -4;
                    free(symbol_table);
                    free(section_header_table);
                    fclose(file);
                    return -1;

                }
                else {
                    *error_val = 1;
                    address=symbol_table[i].st_value;
                    free(symbol_table);
                    free(section_header_table);
                    fclose(file);
                    return address;
                }
            }
            else if(ELF64_ST_BIND(symbol_table[i].st_info)==0 && symbol_table[i].st_value>0){ //LOCAL
                flag =1;
            }
        }
    }


    //if symbol is not found in sym_table:
    *error_val = -1;

    //if symbol is found but is a local symbol:
    if(flag==1){
        *error_val = -2;
    }


    free(symbol_table);
    free(section_header_table);
    fclose(file);
    return -1;
}


void run_sys_debugger(pid_t child_pid, unsigned long func_addr, bool is_extern) {
    int wait_status;
    struct user_regs_struct regs;
    unsigned long func_call_count = 0; // Counter for function calls

    ///wait for child to stop:
    wait(&wait_status);

    ///save address;
    unsigned long address = func_addr;
    unsigned long curr_rsp;
    unsigned long return_address;

    while(!WIFEXITED(wait_status)) {
        if (is_extern) {
            unsigned long addr_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) address, NULL);
            if(func_call_count == 0){
                address = addr_data - 6;
            }
            address = addr_data;
        }

        ///save original inst an fun address:
        unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)address, NULL);

        ///write trap instruction at func address:
        unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void*)address, (void*)data_trap);

        ///let child run until first breakpoint:
        ptrace(PTRACE_CONT,child_pid,NULL,NULL);

        ///wait for child to stop at breakpoint:
        wait(&wait_status);
        if (WIFEXITED(wait_status))
            break;

        func_call_count++;

        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        printf("PRF:: run %lu first parameter is %d\n", func_call_count, (int)regs.rdi);

        curr_rsp = regs.rsp;

        ///removing the breakpoint:
        ptrace(PTRACE_POKETEXT, child_pid, (void *) address, (void *) data);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

        return_address = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)curr_rsp, NULL);

        ///save original inst af ret address:
        data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)return_address, NULL);

        ///write trap instruction at func address:
        unsigned long ret_data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void*)return_address, (void*)ret_data_trap);

        ///let child run until breakpoint at ret:
        ptrace(PTRACE_CONT,child_pid,NULL,NULL);

        ///wait for child to stop at breakpoint:
        wait(&wait_status);
        if (WIFEXITED(wait_status))
            break;

        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        ///removing the breakpoint:
        ptrace(PTRACE_POKETEXT, child_pid, (void *) return_address, (void *) data);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

        ///while recursion - do nothing:
        while (regs.rsp < curr_rsp - 8) {
            ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        }

        ret_data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void*)return_address, (void*)ret_data_trap);

        ///let child run until first breakpoint:
        ptrace(PTRACE_CONT,child_pid,NULL,NULL);

        ///wait for child to stop at breakpoint:
        wait(&wait_status);
        if (WIFEXITED(wait_status))
            break;

        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        printf("PRF:: run #%ld returned with %d\n", func_call_count, (int) regs.rax);

        ///removing the breakpoint:
        ptrace(PTRACE_POKETEXT, child_pid, (void *) return_address, (void *) data);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

        address=func_addr;
    }

    ///exited while:
    ptrace(PTRACE_CONT, child_pid, 0, 0);
    wait(&wait_status);
}


pid_t run_target(const char* func, char** argv) {
    pid_t pid = fork();

    if (pid > 0) {
        return pid;
    } else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        execv(func, argv);
    } else {
        perror("fork");
        exit(1);
    }
}





int main(int argc, char** argv) {
    char* func_name = argv[0];
    char* program_name = argv[1];
    int *val = 0;
    unsigned long res = find_symbol(func_name, program_name,val);
    printf("here");

//check if the program is an exe:
    if(*val == -3){
        printf("PRF:: %s not an executable!\n", program_name);
        return 0;
    }

//check for the func_name in symtab:
    if(*val == -1){
        printf("PRF:: %s not found! :(\n", func_name);
        return 0;
    }

//check if func_name is global:
    if(*val == -2){
        printf("PRF:: %s is not a global symbol! :(\n", func_name);
        return 0;
    }

    Elf64_Addr real_func_address;
    bool is_extern=false;
//check if func_name is an external func:
    if(*val == -4){
        // do step 5:
        FILE *file = fopen(program_name, "rb");
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

                    bool is_wanted_symbol = comparing_name(file, strtab_offset + symbols[index_in_symbols].st_name, func_name);

                    if (is_wanted_symbol) {
                        real_func_address = current_relocation.r_offset;
                    }
                }
            }
        }
    }
    else if(*val == 1) {
        real_func_address = res;
    }

    //step 6:
    pid_t child_pid = run_target(program_name, argv);
    run_sys_debugger(child_pid, real_func_address, is_extern); // Initial call is the first call

    return 0;
}
