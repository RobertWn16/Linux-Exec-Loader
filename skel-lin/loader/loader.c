/*
 * Loader Implementation
 *
 * 2022, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include <sys/mman.h>

#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "exec_parser.h"

#define E_SIGSEGV 139
#define SIGSEGV 11
static so_exec_t *exec;
static int exec_descriptor;

#define SRESULT int
#define BOOL int


typedef struct page
{
    void* address;
}Page;

typedef struct PageDesc {
    Page* internal_page;
    uint8_t count;
}PageDesc;

typedef enum
{
    SO_OK = 0,
    SO_FAIL = -1,
    SO_E_SEG_NOT_FOUND = -2,
    SO_E_POINTER = -3,
    SO_E_ALREADY_MAPPED = -4,
    SO_E_PAGE_OUT_OF_BOUNDS = -5,
    SO_E_INPUT = -6,
    SO_E_EOF = -7
}SO_RESULT;
// functie simpla pt alocari
SRESULT SO_Alloc(void** data, unsigned int dataSize) {
    if(*data)
        return SO_E_POINTER;
    *data = malloc(dataSize);
    return SO_OK;
}
// determina daca pagina de la o anumita adresa este deja mapata
SRESULT IsMapped(void* comp_address) {
    int pageSize = getpagesize();
    for(int i = 0; i < exec->segments_no; i++){
        Page* page_desc = ((PageDesc*)exec->segments[i].data)->internal_page;
        int size = ((PageDesc*)exec->segments[i].data)->count;
        for(int j = 0; j < size; j++){
            long diff = (char*)comp_address - (char*)page_desc[j].address;

            if(diff < pageSize && (((char*)comp_address - (char*)page_desc[j].address) > 1)){
                return SO_E_ALREADY_MAPPED;
            }
        }
    }
    return SO_OK;
}
// gaseste adresa ce cauzeaza segfault
SRESULT FindSegment(void* seg_sig_addr, uint32_t* index_out){
    long int diff;
    for(int i = 0; i < exec->segments_no ; i++){
        diff = (char*)seg_sig_addr - (char*)exec->segments[i].vaddr;

        if (diff < 0){
            return SO_E_PAGE_OUT_OF_BOUNDS;
        }
        if(diff <= exec->segments[i].mem_size){
            *index_out = i;
            return SO_OK;
        }

    }
    return SO_E_SEG_NOT_FOUND;
}
// citeste in buff un numar de bytes_redad bytes
SRESULT ReadAllChuncks(int fd, size_t siz, void* buff, ssize_t* bytes_read)
{
    size_t cp_siz = siz;
    *bytes_read = 0;

    while(*bytes_read < siz){
        *bytes_read = read(fd, buff, siz);
        buff += *bytes_read;
        siz -= *bytes_read;

        if(errno == EIO)
            return SO_E_INPUT;

        if(bytes_read == 0)
            return SO_E_EOF;
    }
    buff -= (cp_siz - siz);

    return SO_OK;
}

// copy the instructions into the pages
void copy_into(so_seg_t *segment,size_t  offset, void *pageAddress)
{
    int bytesRead = 0;
    ssize_t pageSize = getpagesize();
    char *buffer = malloc(pageSize);

    long int chunck_size = 0;
    lseek(exec_descriptor, segment->offset + offset, SEEK_SET);
    /*if(offset <= pageSize)
        chunck_size = pageSize + offset;

    if(offset >= pageSize)
        chunck_size = segment->file_size;*/

    if (offset + pageSize <= segment->file_size)
    {
        //int* misto = malloc(sizeof(int));
        chunck_size = pageSize;
                //dprintf(1, "Dimension of chunk is %d \n", chunck_size);
        ReadAllChuncks(exec_descriptor, chunck_size, buffer, &bytesRead);
        memcpy(pageAddress, buffer, pageSize);
        //free(misto);
    }
    else if (offset <= segment->file_size)
    {

        chunck_size = segment->file_size - offset;

        ReadAllChuncks(exec_descriptor, chunck_size, buffer, &bytesRead);

        memset(buffer + segment->file_size - offset, 0, offset + pageSize - segment->file_size);
        memcpy(pageAddress, buffer, pageSize);
    }
    else if (offset > segment->file_size)
        memset(pageAddress, 0, pageSize);
    free(buffer);
}

static void segv_handler(int signum, siginfo_t *info, void *context)
{
    SRESULT s_res = SO_OK;
    so_seg_t* seg_to_map = NULL;
    uint32_t seg_map_index = 0;
    size_t segment_offset = 0;

    if(s_res == SO_OK){
        s_res = FindSegment(info->si_addr, &seg_map_index); //Tested
    }

    if(s_res == SO_OK){
        s_res = IsMapped(info->si_addr); //Tested
    }

    if(s_res == SO_OK){
        seg_to_map = &exec->segments[seg_map_index];
        PageDesc* seg_page_desc = (PageDesc*)(seg_to_map->data);
        size_t page_size = getpagesize();
        size_t segment_offset = (char*)info->si_addr - (char*)seg_to_map->vaddr;
        size_t page_offset = segment_offset % page_size;
        segment_offset -= page_offset;
        // mapeaza adresa care da segfault
        void* mapped_block = mmap(seg_to_map->vaddr + segment_offset, getpagesize(), PERM_R | PERM_W, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        copy_into(seg_to_map, segment_offset, mapped_block);

        seg_page_desc->internal_page[seg_page_desc->count].address = mapped_block;
        seg_page_desc->count++;


        mprotect(mapped_block, getpagesize(), seg_to_map->perm);
    }

    if(s_res != SO_OK){
        exit(E_SIGSEGV);
    }
}

int so_init_loader(void)
{
    int rc;
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO;
    rc = sigaction(SIGSEGV, &sa, NULL);
    if (rc < 0) {
        perror("sigaction");
        return -1;
    }
    return 0;
}

int so_execute(char *path, char *argv[])
{
    exec_descriptor = open(path, O_RDONLY);
    exec = so_parse_exec(path);
    if (!exec)
        return -1;

    for(int i = 0; i < exec->segments_no; i++) {
        exec->segments[i].data = NULL;
        SRESULT err_code = SO_Alloc(&exec->segments[i].data, sizeof(PageDesc));
        ((PageDesc*)(exec->segments[i].data))->internal_page = NULL;
        err_code = SO_Alloc(&((PageDesc*)(exec->segments[i].data))->internal_page, sizeof(Page) * 1000);
        ((PageDesc*)(exec->segments[i].data))->count = 0;
        if(err_code != SO_OK)
            return -1;
    }


    so_start_exec(exec, argv);

    return -1;
}
