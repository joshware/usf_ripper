#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define __USE_GNU
#define _GNU_SOURCE
#include <limits.h>
#include <time.h>
#include <pulse/simple.h>
#include <pulse/error.h>
#include <unistd.h>
#include <pthread.h>
#include <ncurses.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>

#include "usf.h"
#include "usf_internal.h"
#include "barray.h"

static int SampleRate = 32000, fd = 0, firstWrite = 1, curHeader = 0;
static int bufptr = 0;
static int AudioFirst = 0;

#define BUGSIZE (65536)
#define MAX_PATH PATH_MAX
#define _MAX_PATH PATH_MAX
#define _MAX_FNAME NAME_MAX
#define PATCH_MAX	4096
#define PATCH_ENT_MAX	256
#define PATCH_TOKEN_STRING 0xFFFd00dFFFFFFFFULL

pa_simple *hWaveOut = NULL;

void OpenSound(void)
{
	int error = 0;
    static pa_sample_spec ss;
	ss.format = PA_SAMPLE_S16LE;
	ss.rate = SampleRate;
	ss.channels = 2;

	hWaveOut = pa_simple_new(NULL,
		"usf_rippper",
		PA_STREAM_PLAYBACK,
		NULL,
		"playback",
		&ss,
		NULL,
		NULL, &error);

	if(hWaveOut == NULL) {
		printf("Couldn't open Pulseaudion\n");
		exit(0);
	}
}

void writeAudio(pa_simple * s, void *buffer, size_t size)
{
	int error = 0;
	pa_simple_write(s, buffer, size, &error);
}

static unsigned int buffersize = 0;
static unsigned char buffer[BUGSIZE];
static double play_time = 0;

void PlayBuffer(unsigned char *buf, unsigned int length)
{
	uint32_t i = 0;
	if (!AudioFirst) {
		AudioFirst = 1;
		OpenSound();
	}

	for (i = 0; i < (length >> 1); i += 2) {
		int32_t r = ((short*)buf)[i];
		int32_t l = ((short*)buf)[i + 1];

		((short*)buffer)[(buffersize >> 1) + i] = r;
		((short*)buffer)[(buffersize >> 1) + i + 1] = l;
	}

	buffersize += length;

	if (buffersize >(32768 - length)) {
		writeAudio(hWaveOut, buffer, buffersize);
		buffersize = 0;
	}

}

/* Copied from usf.c */
static void swap_rom(const unsigned char* signature, unsigned char* localrom, int loadlength) {
    unsigned char temp;
    int i;

    /* Btyeswap if .v64 image. */
    if(signature[0]==0x37) {
        for (i = 0; i < loadlength; i+=2) {
            temp=localrom[i];
            localrom[i]=localrom[i+1];
            localrom[i+1]=temp;
        }
    }
    /* Wordswap if .n64 image. */
    else if(signature[0]==0x40) {
        for (i = 0; i < loadlength; i+=4) {
            temp=localrom[i];
            localrom[i]=localrom[i+3];
            localrom[i+3]=temp;
            temp=localrom[i+1];
            localrom[i+1]=localrom[i+2];
            localrom[i+2]=temp;
        }
    }
	else {
		fprintf(stderr, "What kind of rom is this?\n");
	}
}

static char * _load_file(char * file_name, size_t * file_size, int swap)
{
	FILE * fd = NULL;
	char * buf = NULL;
	size_t _file_size = 0;
	char fakesig[1] = { 0x40 };
	fd = fopen(file_name, "rb");

	if (!fd)
		return (char*)1;

	fseek(fd, 0, SEEK_END);
	_file_size = ftell(fd);
	if (file_size)
		*file_size = _file_size;

	buf = (char *)malloc(_file_size);
	if (!buf) {
		fclose(fd);
		return (char*)1;
	}

	fseek(fd, 0, SEEK_SET);
	if (fread(buf, _file_size, 1, fd) != 1) {
		free(buf);
		fclose(fd);
		return (char*)NULL;
	}

	if (swap)
		swap_rom(fakesig, buf, _file_size);
	fclose(fd);
	return buf;
}

char * usf_upload_file(usf_state_t * state, char * fn, void(*load_function)(void*, const uint8_t *, size_t), int swap)
{
	char * buf = NULL;
	size_t file_size;

	buf = _load_file(fn, &file_size, swap);

	if (load_function) {
		load_function(state, buf, file_size);
		free(buf);
	} else {
		return buf;
	}

	return (char*)NULL;
}

void do_patches(uint8_t *rdram, uint8_t *rom, uint64_t *regs, uint32_t reg_num, uint32_t index, char * patches);

void usf_save_sparsed_rom(usf_state_t * state, char * out_file_name, char * rom_file_name, char * patches)
{
	FILE * sparse_file = NULL;
	void * bit_array = usf_get_rom_coverage_barray(state);
	char * rom_data = NULL;
	size_t rom_length = 0, ptr = 0;
	uint32_t offset = 0, position = 0, length = 0;
	int32_t fudge_factor = 16;

	rom_data = _load_file(rom_file_name, &rom_length, 1);
	if (!rom_data)
		return;

	sparse_file = fopen(out_file_name, "wb");
	if (!sparse_file) {
		free(rom_data);
		return;
	}

	if (patches)
	{
		do_patches(NULL, rom_data, NULL, 0, 0, patches);
	}

	// Write header
	fwrite("SR64", 4, 1, sparse_file);

	for (ptr = 0; ptr < rom_length / 4; ptr++) {
		//uint32_t bit = bit_array_test(bit_array, ptr);
		int32_t bit = 0, fudge;
		for (fudge = -fudge_factor; fudge < fudge_factor; fudge ++) {
			bit |= bit_array_test(bit_array, ptr + fudge) ;
		}


		// Force the rom header to be included
		if (ptr <= 0x10) {
			bit = 1;
		}

		//bit = 1;

		if (bit) {
			if (length == 0)
				position = ptr;
			length += 4;
		}
		else if(length) {
			uint32_t offset = (position * 4);
			fwrite(&length, 4, 1, sparse_file);
			fwrite(&offset, 4, 1, sparse_file);
			fwrite(rom_data + offset, length, 1, sparse_file);

			length = 0;
		}
	}

	if(length) {
		offset = (position * 4);
		fwrite(&length, 4, 1, sparse_file);
		fwrite(&offset, 4, 1, sparse_file);
		fwrite(rom_data + offset, length, 1, sparse_file);
	}

	// Zero for the last chunk
	length = 0;
	fwrite(&length, 4, 1, sparse_file);

	fclose(sparse_file);
	free(rom_data);
}

void usf_save_sparsed_ram(usf_state_t * state, char * out_file_name, char * state_file_name, int32_t reg_num, int32_t index, char * patches)
{
	FILE * sparse_file = NULL;
	void * bit_array = usf_get_ram_coverage_barray(state);
	char * save_state = NULL;
	size_t state_length = 0, ptr = 0;
	uint32_t offset = 0, position = 0, length = 0x75c;
	uint64_t *regs;
	uint8_t *rdram;
	int32_t fudge_factor = 64;

	save_state = _load_file(state_file_name, &state_length, 0);
	if (!save_state)
		return;

	sparse_file = fopen(out_file_name, "wb");
	if (!sparse_file) {
		free(save_state);
		return;
	}

	regs = (uint64_t*)(save_state + 0x50);
	rdram = (uint8_t*)(save_state + 0x75C);

	// Alter this if necessary
	if (patches)
	{
		do_patches(rdram, NULL, regs, reg_num, index, patches);
	}

	// Write header
	fwrite("SR64", 4, 1, sparse_file);
	fwrite(&length, 4, 1, sparse_file);
	fwrite(&position, 4, 1, sparse_file);
	fwrite(save_state, 0x75c, 1, sparse_file);
	length = 0;
	position = 0;
	//uint32_t bit2 = bit_array_test(bit_array, 0xC2);

	for (ptr = 0; ptr < (state_length - 0x275C) / 4; ptr++) {
		int32_t bit = 0, fudge;
		for (fudge = -fudge_factor; fudge < fudge_factor; fudge ++) {
            int32_t bit_offset = ptr + fudge;
            if (bit_offset > 0 && bit_offset < ((state_length - 0x275C) / 4)) {
    			bit |= bit_array_test(bit_array, ptr + fudge) ;
            }
		}

		if (bit) {
			if (length == 0)
				position = ptr;
			length += 4;
		}
		else if(length) {
			uint32_t offset = 0x75C + (position * 4);
			fwrite(&length, 4, 1, sparse_file);
			fwrite(&offset, 4, 1, sparse_file);
			fwrite(save_state + offset, length, 1, sparse_file);

			length = 0;
		}
	}

	// Do leftover
	if (length) {
		uint32_t offset = 0x75C + (position * 4);
		fwrite(&length, 4, 1, sparse_file);
		fwrite(&offset, 4, 1, sparse_file);
		fwrite(save_state + offset, length, 1, sparse_file);
	}

	//Do RSP mem
	offset = state_length - 0x2000; length = 0x2000;
	fwrite(&length, 4, 1, sparse_file);
	fwrite(&offset, 4, 1, sparse_file);
	fwrite(save_state + offset, length, 1, sparse_file);

	// Zero for the last chunk
	length = 0;
	fwrite(&length, 4, 1, sparse_file);

	fclose(sparse_file);
	free(save_state);
}

size_t coverage_get_bitcount(usf_state_t * state)
{
	char * ram_barray = usf_get_ram_coverage_barray(state);
	char * rom_barray = usf_get_rom_coverage_barray(state);
	size_t count = 0, i, ram_size, rom_size;
	ram_size = *(size_t*)ram_barray;
	rom_size = *(size_t*)rom_barray;

	for (i = 0; i < (ram_size - 0x275C) / 32; i++) {
		count += ((uint32_t*)ram_barray)[i];
	}
	for (i = 0; i < (rom_size) / 32; i++) {
		count += ((uint32_t*)rom_barray)[i];
	}
	return count;
}

#define MAX_THREADS 256
#define BUFFER_SIZE 4000
static int error_exits = 0;

typedef struct ripper_params_t {
	char * rom_name;
	char * state_name;
	int reg_num;
	int index;
	char * output_name;
	int play_length;
	int flags;
	int cur_thread;
	int play;
	char * patches;
	int debug_bits;
	int disable_fifofull;
	int use_hle;
	int save_raw;
} ripper_params_t;

typedef struct ripping_status_t {
	int index;
	char name[MAX_PATH];
	int play_length;
	int counter;
	int max_counter;
	int max_counter_reset;
	int status;
	usf_state_t * state;
	uintptr_t custom;
	struct timespec start, end;
	double speed;
} ripping_status_t;

static int64_t patch_rvalue_to_int(char * number)
{
	int64_t value = 0;
	ssize_t len = strlen(number);
	return (int64_t)strtol(number, NULL, 0);
}

static char patch_strings[400][16][64] = {0};
static uint64_t patch_data[400][16];
static uint32_t patch_data_count = 0;

void do_patches(uint8_t *rdram, uint8_t *rom, uint64_t *regs, uint32_t reg_num, uint32_t index, char * patches_in)
{
	if(patches_in) {
		char patches[PATCH_MAX], * tok = NULL, *token;
		strcpy(patches, patches_in);
		tok = strtok_r(patches, ":", &token);
		int32_t skip_count = 0;

		while(tok != NULL) {
			char lvalue[PATCH_ENT_MAX] = {0}, rvalue[PATCH_ENT_MAX] = {0}, *eq = NULL;
			uint64_t rval;
			uint32_t rval_valid;

			if (skip_count > 0) {
				skip_count --;
			}
			else if ((eq = strchr(tok, '=')) != NULL) {
				uint32_t column;
				strncpy(lvalue, tok, (size_t)(eq - tok));
				strcpy(rvalue, eq + 1);
				rval = strtoul(rvalue, NULL, 0);
				rval_valid = (errno == EINVAL)?0:(errno==ERANGE?0:1);

				if (sscanf(rvalue, "SDATA[%d,%d]", &column, &skip_count) == 2) {
					rval = patch_data[index][column];
					if (rval == 0xFFFFFFFF) {
						continue;
					}
					skip_count = 0;
					rval_valid = 1;
				}
				else if (sscanf(rvalue, "ZDATA[%d]", &column) == 1) {
					rval = patch_data[index][column];
					if (rval == 0xFFFFFFFF) {
						continue;
					}
					rval_valid = 1;
				}
				else if (sscanf(rvalue, "DATA[%d]", &column) == 1) {
					rval = patch_data[index][column];
					rval_valid = 1;
				}

				if(!strcasecmp(lvalue, "IDLE") && rval_valid && rdram) {
					*(uint32_t*)(rdram + rval) = 0x1000FFFF;
					*(uint32_t*)(rdram + rval + 4) = 0;
				}
				else if(!strncasecmp(lvalue, "NOPR[", 5) && rval_valid && rdram) {
					uint32_t i, begin;
					if(sscanf(lvalue, "NOPR[0x%x]", &begin) == 1) {
					for(i = begin; i <= rval; i += 4)
						*(uint32_t*)(rdram + i) = 0;
					}
				}
				else if(!strcasecmp(lvalue, "NOP") && rval_valid && rdram) {
					*(uint32_t*)(rdram + rval) = 0;
				}
				else if(!strncasecmp(lvalue, "REG[", 4) && rdram) {
					uint32_t reg = 0;
					if(sscanf(lvalue, "REG[%d]", &reg) == 1) {
						if(reg < 1 || reg > 32) {
							reg = 0;
						}
					}
					if(!strcasecmp(rvalue, "INDEX") && reg) {
						regs[reg] = index;
					}
					else if(rval_valid && reg) {
						regs[reg] = rval;
					}
				}
				else if(!strncasecmp(lvalue, "PATCH[", 6) && rdram) {
					uint64_t addr = 0;
					if(sscanf(lvalue, "PATCH[0x%x]", &addr) == 1) {
						if(addr < 0x0 || addr > 0x7FFFF8) {
							addr = 0;
						}
					}
					if(!strcasecmp(rvalue, "INDEX") && addr) {
						*(uint32_t*)(rdram + addr) = index;
					}
					else if(rval_valid && addr) {
						*(uint32_t*)(rdram + addr) = rval;
					}
				}
				else if(!strncasecmp(lvalue, "PATCHB[", 7) && rdram) {
					uint64_t addr = 0;
					if(sscanf(lvalue, "PATCHB[0x%x]", &addr) == 1) {
						if(addr < 0x0 || addr > 0x7FFFF8) {
							addr = 0;
						}
					}
					if(!strcasecmp(rvalue, "INDEX") && addr) {
						*(uint8_t*)(rdram + (addr ^ 3)) = index;
					}
					else if(rval_valid && addr) {
						*(uint8_t*)(rdram + (addr ^ 3)) = rval;
					}
				}
				else if(!strncasecmp(lvalue, "ROMB[", 5) && rom) {
					uint64_t addr = 0;
					if(sscanf(lvalue, "ROMB[0x%x]", &addr) == 1) {
						if(addr < 0x0 || addr > 0x3FFFFFF) {
							addr = 0;
						}
					}
					if(!strcasecmp(rvalue, "INDEX") && addr) {
						*(uint8_t*)(rom + (addr)) = index;
					}
					else if(rval_valid && addr) {
						*(uint8_t*)(rom + (addr)) = rval;
					}
				}
				else if(!strncasecmp(lvalue, "PATCHH[",7) && rdram) {
					uint64_t addr = 0;
					if(sscanf(lvalue, "PATCHH[0x%x]", &addr) == 1) {
						if(addr < 0x0 || addr > 0x7FFFF8) {
							addr = 0;
						}
					}
					if(!strcasecmp(rvalue, "INDEX") && addr) {
						*(uint16_t*)(rdram + (addr ^ 2)) = index;
					}
					else if(rval_valid && addr) {
						*(uint16_t*)(rdram + (addr ^ 2)) = rval;
					}
				}

			}
			tok = strtok_r(NULL, ":", &token);
		}
	}
}

#include <byteswap.h>
usf_state_t * global_state;
void segfault_handler(int sig)
{
	FILE *fd = fopen("ram.ram", "wb");
	FILE *rfd = fopen("rsp.ram", "wb");
	usf_state_t * state = global_state;
	uint32_t * rdram = (uint32_t *)((uint8_t*)(USF_STATE->g_rdram));
	uint32_t * rspmem = (uint32_t *)((uint8_t*)(USF_STATE->g_sp.mem));
	int i;

	for (i = 0; i < 0x200000; i++) {
		uint32_t bswapped = bswap_32(rdram[i]);
		fwrite(&bswapped, 4, 1, fd);
	}

	for (i = 0; i < 0x800; i++) {
		uint32_t bswapped = bswap_32(rspmem[i]);
		fwrite(&bswapped, 4, 1, rfd);
	}

	fclose(fd);
	fclose(rfd);
	fprintf(stderr, "Segfault exit");
	exit(1);
}

static ripping_status_t rip_status[MAX_THREADS];
void usf_log_start(usf_state_t *);

void rip_usf(ripper_params_t *params)
{
	int16_t buffer[BUFFER_SIZE * 2];
	int32_t count = BUFFER_SIZE, i = 0;
	size_t total_bitcount = 0, total_counter = 0;
	int32_t minimum = 1, add_index_to_name = 1;
	usf_state_t * state = NULL;
	char out_rom_name[MAX_PATH], out_ram_name[MAX_PATH];
	int32_t counter = 0;
	int cancel = 0;
	// Copy all of these, as the main thread will wipe the data
	char rom_name[MAX_PATH];
	char state_name[MAX_PATH];
	int reg_num = params->reg_num;
	int index = params->index;
	char output_name[MAX_PATH];
	int play_length = params->play_length;
	int flags = params->flags;
	int cur_thread = params->cur_thread;
	int play_audio = params->play;
	int disable_fifofull = params->disable_fifofull;
	int use_hle = params->use_hle;
	int save_raw = params->save_raw;
	int debug_bits = params->debug_bits;
	char * patches = params->patches;
	struct timespec start, end, render_begin, render_end;
	clock_t begin_time, end_time;
	const char * e;
	FILE * raw_file = (FILE *)NULL, * loop_file = (FILE *)NULL;
	uint64_t runtime_us, render_us, error_counter = 0;
	uint16_t * begin_section, * loop_scan;
	uint32_t begin_length, loop_section_length, loop_length, loop_max_length, begin_section_seconds;
	double begin_avg;


	strcpy(rom_name, params->rom_name);
	strcpy(state_name, params->state_name);
	strcpy(output_name, params->output_name);

	state = malloc(usf_get_state_size());
	usf_clear(state);

	usf_set_trimming_mode(state, 1);

	usf_upload_file(state, (char *)rom_name, usf_upload_rom, 1);
	usf_upload_file(state, (char *)state_name, usf_upload_save_state, 0);

	usf_set_compare(state, 1);
	usf_set_fifo_full(state, disable_fifofull ? 0 : 1);
	usf_set_hle_audio(state, use_hle ? 1 : 0);

	USF_STATE->debug_bits = debug_bits;
	if (debug_bits & 1) {
		usf_log_start(state);
	}

	if (patches) {
		uint8_t * rdram = ((uint8_t*)(USF_STATE->save_state) + 0x75C);
		uint64_t *regs = (uint64_t*)((char*)(USF_STATE->save_state) + 0x50);
		uint8_t * rom = ((uint8_t*)(USF_STATE->g_rom));
		do_patches(rdram, rom, regs, reg_num, index, patches);
	}
	if (!strncmp(output_name, "DATA[", 5)) {
		int32_t column;
		if (sscanf(output_name, "DATA[%d]", &column) == 1) {
			strcpy(output_name, patch_strings[index][column]);
			add_index_to_name = 0;
		}
	}

	strcpy(rip_status[cur_thread].name, output_name);
	rip_status[cur_thread].index = index;
	rip_status[cur_thread].status = 1;
	rip_status[cur_thread].state = state;
	rip_status[cur_thread].max_counter = 0;

	clock_gettime(CLOCK_MONOTONIC_RAW, &start);

	//rip_status[cur_thread].custom = &(USF_STATE->g_rdram[0xB5EB8 /4]);
	//global_state = state;


	for (i = 0; (counter < play_length) || minimum; i++) {
		//USF_STATE->debug_bits = ((rip_status[cur_thread].play_length > 564) && (rip_status[cur_thread].play_length < 566)) ? 34 : 0;

		clock_gettime(CLOCK_MONOTONIC_RAW, &render_begin);
		e = usf_render(state, buffer, count, &SampleRate);
		counter++;
		total_counter++;
		clock_gettime(CLOCK_MONOTONIC_RAW, &render_end);

		render_us = (render_end.tv_sec - render_begin.tv_sec) * 1000000 + (render_end.tv_nsec - render_begin.tv_nsec) / 1000;

		if (e || ((render_us > 300000) && 0)) {
			usf_shutdown(state);
			free(state);
			rip_status[cur_thread].status = 0;
			error_exits++;
			fprintf(stderr, "Track %d exit errored at %d seconds\n", rip_status[cur_thread].index, rip_status[cur_thread].play_length);
			pthread_exit(0);
			break;
		}


		if (play_audio/* && ((i*count) / SampleRate) > 48*/)
			PlayBuffer((char*)buffer, count * 4);

		if (save_raw) {
			if (raw_file == (FILE *)NULL) {
				char raw_file_name[256];
				sprintf(raw_file_name, "%s%02x.raw", output_name, index);
				raw_file = fopen(raw_file_name, "wb");
			}
			if (raw_file != (FILE*)NULL) {
				fwrite(buffer, count, 4, raw_file);
			}
		}

		// Reset counter on new data read
		if (i % 100 == 0) {
			size_t new_bitcount = coverage_get_bitcount(state);
			if (counter > rip_status[cur_thread].max_counter)
				rip_status[cur_thread].max_counter = counter;
			if (new_bitcount != total_bitcount) {
				total_bitcount = new_bitcount;
				rip_status[cur_thread].max_counter_reset = counter;
				counter = 0;
			}
		}

		if ((i % 10) ==  0) {
			// Play for a minimum of 10 minutes
			if (((i * count) / SampleRate) > 600)
				minimum = 0;


			rip_status[cur_thread].counter = counter;
			rip_status[cur_thread].play_length = ((i*count) / SampleRate);

			clock_gettime(CLOCK_MONOTONIC_RAW, &end);
			runtime_us = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
			rip_status[cur_thread].speed = (double)rip_status[cur_thread].play_length / ((double)runtime_us / 1000000.0);
		}
	}

	if (add_index_to_name) {
		sprintf(out_rom_name, "%s%02x.rom", output_name, index);
		sprintf(out_ram_name, "%s%02x.ram", output_name, index);
	}
	else {
		sprintf(out_rom_name, "%s.rom", output_name, index);
		sprintf(out_ram_name, "%s.ram", output_name, index);
	}

	usf_save_sparsed_ram(state, out_ram_name, state_name, reg_num, index, patches);
	usf_save_sparsed_rom(state, out_rom_name, rom_name, patches);
	usf_shutdown(state);
	free(state);
	rip_status[cur_thread].status = 0;
	usleep(5000);
	pthread_exit(0);
}


// Eg: usf_ripper -r "c:\games\roms\Mario Kart 64 (U) [!].z64" -s "f:\usf\Project 64 1.5\MK64.pj" -o f:\usf\mk64\sparse -n 5 -b 0 -e 40 -c 3000 -t 4
// Nope:
// ./usf_ripper -r ~/Games/N64/GoldenEye\ 007\ \(E\)\ \[\!\].z64 -s /home/josh/projects/usf/saves/ge3.pj -c 800 -n 4 -b 23 -e 25 -o out/sparse -l -p "REG[4]=index:IDLE=0xE70:IDLE=0x6428:IDLE=0x5464:IDLE=0x4474:NOP=0xFE8"
int main(int argc, char ** argv)
{
	pthread_t threadIDs[MAX_THREADS];
	int32_t play_audio = 0, play_length = 2000, count = 2000, i = 0, c = 0, threads = 1;
	char state_name[_MAX_PATH], rom_name[_MAX_PATH], output_name[_MAX_FNAME], patch_file[_MAX_FNAME] = {'\0'};
	char patches[4096];
	size_t total_bitcount = 0, begin = 0, end = 1, index = 0, play = 0, have_patches = 0, debug_bits = 0, disable_fifofull = 0, use_hle = 0, save_raw = 0;
	int32_t last_counter[MAX_THREADS], max_counter = 0;
	int32_t last_counter_count[MAX_THREADS];
	uint32_t reg_num = 0, completed = 0;
	uint32_t threads_busy[MAX_THREADS];
	uint32_t cur_x, cur_y;
	WINDOW * win = NULL;

	//signal(SIGSEGV, segfault_handler);

	struct option options[] = {
		{ "rom", required_argument, NULL, 'r' },
		{ "state", required_argument, NULL, 's' },
		{ "register_num", optional_argument, NULL, 'n' },
		{ "begin", optional_argument, NULL, 'b' },
		{ "end", optional_argument, NULL, 'e' },
		{ "count", optional_argument, NULL, 'c' },
		{ "output_name" , optional_argument, NULL, 'o'},
		{ "threads" , optional_argument, NULL, 't' },
		{ "patches" , optional_argument, NULL, 'p' },
		{ "listen" , optional_argument, NULL, 'l' },
		{ "use_hle" , optional_argument, NULL, 'H' },
		{ "debug" , optional_argument, NULL, 'd' },
		{ "file" , optional_argument, NULL, 'f' },
		{ "save_raw" , optional_argument, NULL, 'R' },
		{ "disablefifofull" , optional_argument, NULL, 'F' },
		{NULL, 0, NULL, 0}
	};
	rom_name[0] = 0;
	state_name[0] = 0;
	strcpy(output_name, "sparse");

	while ((c = getopt_long(argc, argv, "r:s:n:b:e:c:o:t:p:lRHFd:f:", options, NULL)) != -1) {
		switch (c) {
		case 'r':
			if(optarg)
				strcpy(rom_name, optarg);
			break;
		case 's':
			if (optarg)
				strcpy(state_name, optarg);
			break;
		case 'c':
			if (optarg)
				play_length = atoi(optarg);
			break;
		case 'n':
			if (optarg)
				reg_num = atoi(optarg);
			break;
		case 'b':
			if (optarg)
				begin = strtol(optarg, NULL, 0);
			break;
		case 'e':
			if (optarg)
				end = strtol(optarg, NULL, 0);
			break;
		case 'o':
			if (optarg)
				strcpy(output_name, optarg);
			break;
		case 't':
			if (optarg)
				threads = atoi(optarg);
			break;
		case 'p':
			if (optarg) {
				strcpy(patches, optarg);
				have_patches = 1;
			}
			break;
		case 'l':
			play = 1;
			break;
		case 'F':
			disable_fifofull = 1;
			break;
		case 'H':
			use_hle = 1;
			break;
		case 'R':
			save_raw = 1;
			break;
		case 'd':
			if (optarg)
				debug_bits = atoi(optarg);
			break;
		case 'f':
			if (optarg) {
				strcpy(patch_file, optarg);
			}
			break;
		}
	}

	if (!strlen(rom_name) || !strlen(state_name)) {
		return 2;
	}

	if (*patch_file) {
		FILE * fd = fopen(patch_file, "r");
		if (fd != NULL) {
			char line[512];
			while (fgets(line, 512, fd) != NULL) {
				char * token, temp_token[32];
				int32_t token_id = 0;
				token = strtok(line, ",");
				while (token != NULL) {
					patch_data[patch_data_count][token_id] = 0;
					if (token[0] == '"') {
						memset(patch_strings[patch_data_count][token_id], 0, 64);
						strncpy(patch_strings[patch_data_count][token_id], token + 1, strlen(token) - 3);
						patch_data[patch_data_count][token_id] = PATCH_TOKEN_STRING;
					}
					else  if (sscanf(token, "0x%llx", &patch_data[patch_data_count][token_id]) != 1) {
						sscanf(token, "%lld", &patch_data[patch_data_count][token_id]);
					}
					token = strtok(NULL, ",");
					token_id ++;
				}

				patch_data_count ++;
			}
			fclose(fd);
		}
	}

	if(play)
		threads = 1;

	memset(threads_busy, 0, sizeof(uint32_t) * MAX_THREADS);
	memset(threadIDs, 0, sizeof(pthread_t) * MAX_THREADS);
	memset(rip_status, 0, sizeof(ripping_status_t) * MAX_THREADS);
	memset(last_counter, 0, sizeof(uint32_t) * MAX_THREADS);
	memset(last_counter_count, 0, sizeof(uint32_t) * MAX_THREADS);

	if (threads > (int32_t)(end - begin))
		threads = (end - begin) >= 1 ? (end - begin) + 1 : 1;

	printf("Running USF ripper\nRunning %d threads\n\n", threads);
	initscr();
	getyx(stdscr, cur_y, cur_x);

	for(index = begin; completed <= (end - begin); ) {
		for (i = 0; i < threads; i++) {
			uint32_t run_new = 0;
			if (threads_busy[i] == 0 && (index <= end))
				run_new = 1;

			if (threads_busy[i] == 1) {
				void * exit_code;
				if(pthread_tryjoin_np(threadIDs[i], &exit_code) != 0)
					continue;

				completed++;
				threadIDs[i] = 0;
				threads_busy[i] = 0;
			}

			if (index > end)
				continue;

			if (run_new == 1) {
				ripper_params_t params = {0};
				params.flags = 0;
				params.play = play;
				params.index = index;
				params.output_name = output_name;
				params.reg_num = reg_num;
				params.state_name = state_name;
				params.rom_name = rom_name;
				params.play_length = play_length;
				params.cur_thread = i;
				params.debug_bits = debug_bits;
				params.disable_fifofull = disable_fifofull;
				params.use_hle = use_hle;
				params.save_raw = save_raw;
				if(have_patches)
					params.patches = patches;

				if(pthread_create(&threadIDs[i], NULL, (void *(*) (void *))rip_usf, &params)) {
					printf("Error creating thread\n");
					exit(1);
				}
				threads_busy[i] = 1;
				last_counter_count[i] = 0;
				last_counter[i] = 0;
				index++;
				usleep(50*1000);
			}
		}
		usleep(25*1000);

		for(i = 0; i < threads; i++) {
			//COORD new_pos;
			char name[MAX_PATH];
			char buf[MAX_PATH], buf2[MAX_PATH];
			usf_state_t * state = rip_status[i].state;
			struct timespec end;

			sprintf(name, "%s%02x", rip_status[i].name, rip_status[i].index);
			sprintf(buf, "Counter %6d / %6d", rip_status[i].counter, play_length);
			sprintf(buf2, "Ripping 0x%-3x", rip_status[i].index);
			mvprintw(cur_y + i, cur_x, "Thread %2d : %-15s %-24s (max %6d) %4d seconds   Speed: %.2f",
					 i, buf2, buf, rip_status[i].max_counter, rip_status[i].play_length, rip_status[i].speed);

			if (rip_status[i].max_counter_reset > max_counter) {
				max_counter = rip_status[i].max_counter_reset;
			}
			if (last_counter[i] == rip_status[i].counter)
				last_counter_count[i]++;
			else
				last_counter_count[i] = 0;
			if (0 && last_counter_count[i] == 3000 && threads_busy[i]) {
				// frozen, skip
				pthread_cancel(threadIDs[i]);
				usleep(200 * 1000);
				usf_shutdown(rip_status[i].state);
				threads_busy[i] = 0;
				completed++;
				error_exits++;
			}
			last_counter[i] = rip_status[i].counter;
		}
		mvprintw(cur_y + i, cur_x, "Completed %d / %d\nErrors: %d   Max Counter: %d", completed, (end - begin) + 1, error_exits, max_counter);
		wrefresh(stdscr);
		fflush(stdout);
	}

	endwin();
	printf("Doneski. Errors: %d\n", error_exits);
	return 0;
}


