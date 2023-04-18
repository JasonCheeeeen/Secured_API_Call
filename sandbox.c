#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <elf.h>

// record hijacking function offset, name and numbers
char *fun_name[6];
long int fun_address[6];
int function_count = 0;

int fd_env;
static int (*libc_open)(const char *, int, ...);
static int (*libc_connect)(int, const struct sockaddr *, socklen_t);
static int (*libc_getaddrinfo)(const char *restrict, const char *restrict, const struct addrinfo *restrict, struct addrinfo **restrict);
static int (*libc_system)(const char *);
static ssize_t(*libc_read)(int, void *, size_t);
static ssize_t(*libc_write)(int, void *, size_t);
static int (*libc_lsm)(int (*)(int, char **, char **), int, char **, int (*)(int, char **, char **), void (*)(void), void (*)(void), void *);

// structure for config file
int bo_index = 0, br_index = 0, bc_index = 0, bg_index = 0;
char *hostname;
char *black_open[100];
char *black_read[100];
char *black_connect[100][2];
char *black_getaddrinfo[100];

int self_open(char* file_name, int flags, ...){

    // get file path
    char real_file_path[512];
    realpath(file_name, real_file_path);
    file_name = real_file_path;

    // parse open args
    va_list args;
    mode_t mode = 0;
    va_start(args, flags);
    mode = va_arg(args, mode_t);
    // printf("%o\n", mode&0777);
    va_end(args);

    int self_open_return;

    for(int i=0;i<bo_index;i++){
        if(strncmp(black_open[i], file_name, strlen(file_name)) == 0){
            self_open_return = -1;
            errno = EACCES;
            dprintf(fd_env, "[logger] open(\"%s\", %o, %o) = %d\n", real_file_path, flags, mode&0777, self_open_return);
            // if(mode == 0){
            //     dprintf(fd_env, "[logger] open(\"%s\", %d) = %d\n", real_file_path, flags, self_open_return);
            // }
            // else{
            //     dprintf(fd_env, "[logger] open(\"%s\", %o, %o) = %d\n", real_file_path, flags, mode&0777, self_open_return);
            // }
            return -1;
        }
    }
    
    if((mode&0777) == 0){
        self_open_return = libc_open(file_name, flags);
    }
    else{
        self_open_return = libc_open(file_name, flags, mode);
    }

    dprintf(fd_env, "[logger] open(\"%s\", %o, %o) = %d\n", real_file_path, flags, mode&0777, self_open_return);
    // if(mode == 0){
    //     dprintf(fd_env, "[logger] open(\"%s\", %o) = %d\n", real_file_path, flags, self_open_return);
    // }
    // else{
    //     dprintf(fd_env, "[logger] open(\"%s\", %o, %o) = %d\n", real_file_path, flags, mode&0777, self_open_return);
    // }

    return self_open_return;
}

ssize_t self_read(int fd, void* buf, size_t count){
    ssize_t libc_return  = libc_read(fd, buf, count);
    char *read_buf = (char *)buf;

    // construct log file
    pid_t _pid = getpid();
    char log_file[100];
    sprintf(log_file, "%d-%d-read.log", _pid, fd);
    char *content;
    FILE* fp = fopen(log_file, "a");

    // read log file content
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    content = malloc((fsize + 1)*sizeof(char));
    memset(content, '\0', strlen(content));
    fread(content, fsize, 1, fp);
    content[fsize] = '\0';

    // combine log file content and read buffer
    char *combine;
    combine = malloc(sizeof(char)*(strlen(content) + libc_return + 1));
    memset(combine, '\0', strlen(combine));
    strcat(combine, content);
    strncat(combine, read_buf, libc_return);

    //check read black list
    for(int i=0;i<br_index;i++){
        if(strstr(combine, black_read[i]) != NULL){
            close(fd);
            errno = EIO;
            libc_return = -1;
            dprintf(fd_env, "[logger] read(%d, %p, %ld) = %ld\n", fd, read_buf, count, libc_return);
            return -1;
        }
    }

    fwrite(read_buf, sizeof(char), libc_return, fp);
    fclose(fp);
    free(content);
    free(combine);

    dprintf(fd_env, "[logger] read(%d, %p, %ld) = %ld\n", fd, buf, count, libc_return);
    return libc_return;
}

ssize_t self_write(int fd, void* buf, size_t count){
    ssize_t libc_return = libc_write(fd, buf, count);
    char *write_buf = (char *)buf;

    // construct log file
    pid_t _pid = getpid();
    char log_file[100];
    sprintf(log_file, "%d-%d-write.log", _pid, fd);
    FILE* fp = fopen(log_file, "a");
    fwrite(write_buf, sizeof(char), libc_return, fp);
    fclose(fp);
    dprintf(fd_env, "[logger] write(%d, %p, %ld) = %ld\n", fd, buf, count, libc_return);
    return libc_return;
}

int self_connect(int fd, struct sockaddr *serv_addr, int addrlen){
    int libc_return;
    struct sockaddr_in* sin = (struct sockaddr_in *)serv_addr;
    char *ip = inet_ntoa(sin->sin_addr);
    uint16_t port;
    port = ntohs(sin->sin_port);
    char s_port[100];
    sprintf(s_port, "%u", port);
    for(int i=0;i<bc_index;i++){
        if((strncmp(black_connect[i][0], hostname, strlen(hostname)) == 0) && (strncmp(black_connect[i][1], s_port, strlen(s_port)) == 0)){
            libc_return = -1;
            errno = ECONNREFUSED;
            dprintf(fd_env, "[logger] connect(%d, \"%s\", %d) = %d\n", fd, ip, addrlen, libc_return);
            return libc_return;
        }
    }
    libc_return = libc_connect(fd, serv_addr, addrlen);
    dprintf(fd_env, "[logger] connect(%d, \"%s\", %d) = %d\n", fd, ip, addrlen, libc_return);
    return libc_return;
}

int self_getaddrinfo(const char *restrict node, const char *restrict service, const struct addrinfo *restrict hints, struct addrinfo **restrict res){
    int libc_return;
    for(int i=0;i<bg_index;i++){
        if(strncmp(black_getaddrinfo[i], node, strlen(node)) == 0){
            libc_return = -1;
            errno = EAI_NONAME;
            dprintf(fd_env, "[logger] getaddrinfo(\"%s\", \"%s\", %p, %p) = %d\n", node, service, hints, res, EAI_NONAME);
            return EAI_NONAME;
        }
    }
    hostname = (char*)malloc(sizeof(char)*(strlen(node)+1));
    memcpy(hostname, node, strlen(node));
    hostname[strlen(node)] = '\0';
    libc_return = libc_getaddrinfo(node, service, hints, res);
    dprintf(fd_env, "[logger] getaddrinfo(\"%s\", \"%s\", %p, %p) = %d\n", node, service, hints, res, libc_return);
    return libc_return;
}

int self_system(const char *command){
    dprintf(fd_env, "[logger] system(\"%s\")\n", command);
    int libc_return = libc_system(command);
    return libc_return;
}

void elf_parser(char *target_file){

    // printf("%s\n", target_file);
    FILE *fp = fopen(target_file, "rb");
    if (!fp) {
        perror("[ ERROR for open execution file ]\n");
        exit(-1);
    }

    // read elf header
    Elf64_Ehdr elf_header;
    if (fread(&elf_header, sizeof(Elf64_Ehdr), 1, fp) != 1) {
        perror("[ ERROR for read ELF header from file ]\n");
        exit(-1);
    }
    
    // read section header
    Elf64_Shdr *shdr_table = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr) * elf_header.e_shnum);
    if (!shdr_table) {
        perror("[ ERROR for allocate memory for section header table ]\n");
        exit(-1);
    }

    fseek(fp, elf_header.e_shoff, SEEK_SET); // section header start 
    if (fread(shdr_table, sizeof(Elf64_Shdr), elf_header.e_shnum, fp) != elf_header.e_shnum) {
        perror("[ ERROR for read section header table from file ]\n");
        exit(-1);
    }

    // read .rela.plt && .dynsym && .strtab
    Elf64_Shdr *rela_plt_hdr = NULL;
    Elf64_Shdr *symtab_hdr = NULL;
    Elf64_Shdr *strtab_hdr = NULL;

    int check = 0;
    for (int i = 0; i < elf_header.e_shnum; i++) {
        if (shdr_table[i].sh_type == SHT_RELA) {
            rela_plt_hdr = &shdr_table[i];
        }
        else if (shdr_table[i].sh_type == SHT_DYNSYM) {
            symtab_hdr = &shdr_table[i];
        }
        else if (shdr_table[i].sh_type == SHT_STRTAB && check==0) {
            strtab_hdr = &shdr_table[i];
            check = 1;
        }
    }

    if (!rela_plt_hdr) {
        perror("[ ERROR for find .rela.plt section in file ]\n");
        exit(-1);
    }

    if (!symtab_hdr) {
        perror("[ ERROR for find symbol table section in file ]\n");
        exit(-1);
    }

    if (!strtab_hdr) {
        perror("[ ERROR for find string table section in file ]\n");
        exit(-1);
    }
    
    // read .rela.plt section
    fseek(fp, rela_plt_hdr->sh_offset, SEEK_SET);
    size_t num_relocations = rela_plt_hdr->sh_size / rela_plt_hdr->sh_entsize;
    Elf64_Rela *relocations = (Elf64_Rela *)malloc(sizeof(Elf64_Rela) * (num_relocations));
    if (!relocations) {
        perror("[ ERROR for allocate memory for relocations ]\n");
        exit(-1);
    }

    if (fread(relocations, rela_plt_hdr->sh_entsize, num_relocations, fp) != num_relocations) {
        perror("[ ERROR for read relocations from file ]\n");
        exit(-1);
    }

    // read symbol section
    fseek(fp, symtab_hdr->sh_offset, SEEK_SET);
    size_t num_symbols = symtab_hdr->sh_size / symtab_hdr->sh_entsize;
    Elf64_Sym *symbols = (Elf64_Sym *)malloc(sizeof(Elf64_Sym) * num_symbols);
    if (!symbols) {
        perror("[ ERROR for allocate memory for symbols ]\n");
        exit(-1);
    }

    if (fread(symbols, symtab_hdr->sh_entsize, num_symbols, fp) != num_symbols) {
        perror("[ ERROR for read symbols from file ]\n");
        exit(-1);
    }

    // read string table section
    fseek(fp, strtab_hdr->sh_offset, SEEK_SET);
    char *strtab = (char *)malloc(strtab_hdr->sh_size);
    if (!strtab) {
        perror("[ ERROR for allocate memory for string table ]\n");
        exit(-1);
    }

    if (fread(strtab, 1, strtab_hdr->sh_size, fp) != strtab_hdr->sh_size) {
        perror("[ ERROR for read string table from file ]\n");
        exit(-1);
    }

    // parse hijacking functions
    for (int i = 0; i < num_relocations; i++) {
        Elf64_Rela *rela = &relocations[i];
        if (ELF64_R_TYPE(rela->r_info) == R_X86_64_JUMP_SLOT) {
            Elf64_Sym *sym = &symbols[ELF64_R_SYM(rela->r_info)];
            char *symname = &strtab[sym->st_name];
            if (strlen(symname) == 4 && strncmp(symname, "read", 4) == 0){
                fun_name[function_count] = "read";
                fun_address[function_count++] = rela->r_offset;
            }
            else if(strlen(symname) == 4 && strncmp(symname, "open", 4)==0){
                fun_name[function_count] = "open";
                fun_address[function_count++] = rela->r_offset;
            }
            else if(strlen(symname) == 5 && strncmp(symname, "write", 5)==0){
                fun_name[function_count] = "write";
                fun_address[function_count++] = rela->r_offset;
            }
            else if(strlen(symname) == 7 && strncmp(symname, "connect", 7)==0){
                fun_name[function_count] = "connect";
                fun_address[function_count++] = rela->r_offset;
            }
            else if(strlen(symname) == 11 && strncmp(symname, "getaddrinfo", 11)==0){
                fun_name[function_count] = "getaddrinfo";
                fun_address[function_count++] = rela->r_offset;
            }
            else if(strlen(symname) == 6 && strncmp(symname, "system", 6)==0){
                fun_name[function_count] = "system";
                fun_address[function_count++] = rela->r_offset;
            }
        }
    }
    fclose(fp);
    free(relocations);
    free(symbols);
    free(strtab);
}

void got_rewritter(char *target_file){
    // get base address
    int fd, sz;
	char bbuf[16384], *s = bbuf, *line, *saveptr;
	if((fd = open("/proc/self/maps", O_RDONLY)) < 0) perror("get_base/open");
	if((sz = read(fd, bbuf, sizeof(bbuf)-1)) < 0) perror("get_base/read");
	bbuf[sz] = 0;
	close(fd);
    long int record[5];
    int index = 0;
    while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) {
        s = NULL;
		if(strstr(line, target_file) != NULL) {
            char* base_s = strtok(line, "-");
            record[index++] = strtol(base_s, NULL, 16);
		}
	}

    // mmap to get base address
    if(mprotect(record[3], record[4]-record[3], PROT_READ | PROT_WRITE) < 0){
        fprintf(stderr, "error is: %s\n",strerror(errno));
    }

    // get libc's function (real function)
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    if(handle != NULL){
        libc_open = dlsym(handle, "open");
        libc_read = dlsym(handle, "read");
        libc_write = dlsym(handle, "write");
        libc_connect = dlsym(handle, "connect");
        libc_getaddrinfo = dlsym(handle, "getaddrinfo");
        libc_system = dlsym(handle, "system");
        libc_lsm = dlsym(handle, "__libc_start_main");
    }

    // rewrite got entry
    for(int i=0;i<function_count;i++){
        //long int *pointer = fun_address[i];
        if(fun_address[i] > record[4]){
            break;
        }
        long int *pointer = fun_address[i] + record[0];
        // long int *pointer = fun_address[i];
        // printf("%lx\n", pointer);
        if(strncmp(fun_name[i], "open", 4) == 0){
            *(pointer) = (void *) self_open;
        }
        else if(strncmp(fun_name[i], "read", 4) == 0){
            *(pointer) = (void *) self_read;
        }
        else if(strncmp(fun_name[i], "write", 5) == 0){
            *(pointer) = (void *) self_write;
        }
        else if(strncmp(fun_name[i], "connect", 7) == 0){
            *(pointer) = (void *) self_connect;
        }
        else if(strncmp(fun_name[i], "getaddrinfo", 11) == 0){
            *(pointer) = (void *) self_getaddrinfo;
        }
        else if(strncmp(fun_name[i], "system", 6) == 0){
            *(pointer) = (void *) self_system;
        }
    }
}

void config_parser(){
    // open and record config file
    char *config_path = getenv("SANDBOX_CONFIG");
    int config_fd = libc_open(config_path, O_RDONLY);
    if(config_fd == -1){
        perror("[ Open Config.txt Fail ]\n");
    }

    // get each line of config file
    char config_buf[16384];
    char *config_line[500];
    char cur;
    int config_word_index = 0, config_line_index = 0;
    while(read(config_fd, &cur, 1) > 0) {
        if(cur != '\n'){
            config_buf[config_word_index++] = cur;
        }
        else{
            if(strlen(config_buf) > 0){
                config_buf[config_word_index] = '\0';
                config_line[config_line_index] = malloc(strlen(config_buf)+1);
                config_line[config_line_index][strlen(config_buf)] = '\0';
                memcpy(config_line[config_line_index], config_buf, strlen(config_buf));
                config_line_index++;
                memset(config_buf, '\0', sizeof(config_buf));
                config_word_index = 0;
            }
        }
    }
    if(strlen(config_buf) > 0){
        config_buf[config_word_index] = '\0';
        config_line[config_line_index] = malloc(strlen(config_buf)+1);
        config_line[config_line_index][strlen(config_buf)] = '\0';
        memcpy(config_line[config_line_index++], config_buf, strlen(config_buf));
    }

    int open_end = 0;
    for(int i=0;i<config_line_index;i++){
        if(strncmp(config_line[i], "BEGIN", 5) == 0){
            i++;
            if(open_end == 0){
                while(strncmp(config_line[i], "END", 3)){
                    char real_file_path[512];
                    realpath(config_line[i], real_file_path);
                    black_open[bo_index] = malloc(strlen(real_file_path)+1);
                    black_open[bo_index][strlen(real_file_path)] = '\0';
                    memcpy(black_open[bo_index++], real_file_path, strlen(real_file_path));
                    i++;
                }
            }
            if(open_end == 1){
                while(strncmp(config_line[i], "END", 3)){
                    black_read[br_index] = malloc(strlen(config_line[i])+1);
                    black_read[br_index][strlen(config_line[i])] = '\0';
                    memcpy(black_read[br_index++], config_line[i], strlen(config_line[i]));
                    i++;
                }
            }
            if(open_end == 2){
                while(strncmp(config_line[i], "END", 3)){
                    const char *d = ":";
                    char *p;
                    p = strtok(config_line[i], d);
                    while(p != NULL){
                        black_connect[bc_index][0] = malloc(strlen(p)+1);
                        black_connect[bc_index][0][strlen(p)] = '\0';
                        memcpy(black_connect[bc_index][0], p, strlen(p));
                        p = strtok(NULL, d);
                        black_connect[bc_index][1] = malloc(strlen(p)+1);
                        black_connect[bc_index][1][strlen(p)] = '\0';
                        memcpy(black_connect[bc_index++][1], p, strlen(p));
                        p = strtok(NULL, d);
                    }
                    i++;
                }
            }
            if(open_end == 3){
                while(strncmp(config_line[i], "END", 3)){
                    black_getaddrinfo[bg_index] = malloc(strlen(config_line[i])+1);
                    black_getaddrinfo[bg_index][strlen(config_line[i])] = '\0';
                    memcpy(black_getaddrinfo[bg_index++], config_line[i], strlen(config_line[i]));
                    i++;
                }
            }
            open_end++;
        }
    }
}

int __libc_start_main(int (*main)(int, char **, char **), int argc, char **argv, int (*init)(int, char **, char **), void (*fini)(void), void (*rtld_fini)(void), void *stack_end){

    // get execution file
    char target_file[50];
    memset(target_file, '\0', sizeof(target_file));
    readlink("/proc/self/exe", target_file, sizeof(target_file));

    // parse elf
    elf_parser(target_file);

    // rewrite got table
    got_rewritter(target_file);
    
    // parse config.txt
    config_parser();

    // call real libc_start_main
    return libc_lsm(main, argc, argv, init, fini, rtld_fini, stack_end);
}