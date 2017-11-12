#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "usf.h"
#include "usf_internal.h"
#include "barray.h"
#include "getopt.h"

static int SampleRate = 32000, fd = 0, firstWrite = 1, curHeader = 0;
static int bufptr = 0;
static int AudioFirst = 0;

#include <windows.h>
#include <mmsystem.h>

#define BUFFERS	2
#define BUGSIZE 65536
HWAVEOUT hWaveOut = NULL;
char tempbuffer[BUFFERS][BUGSIZE];
WAVEHDR header[BUFFERS];

void CALLBACK _waveOutProc(HWAVEOUT hwo, UINT uMsg, DWORD_PTR dwInstance, LPWAVEHDR dwParam1, void * dwParam2)
{
	if (uMsg == WOM_DONE) {		
		((WAVEHDR*)dwParam1)->lpData = 0;
	}
}

void writeAudio(HWAVEOUT hWaveOut, LPSTR data, int size)
{

	if (firstWrite) {
		ZeroMemory(header, sizeof(WAVEHDR)*BUFFERS);
		curHeader = 0;
	}

	if (!firstWrite) {
		int i = 0;
		curHeader = -1;

		while (curHeader == -1) {
			for (i = 0; i < BUFFERS; i++) {
				if (header[i].lpData == 0) {
					curHeader = i;
					break;
				}
			}
			if (curHeader == -1)
				Sleep(1);
		}
	}

	ZeroMemory(&header[curHeader], sizeof(WAVEHDR));
	memcpy(&tempbuffer[curHeader][0], data, size);
	header[curHeader].dwBufferLength = size;
	header[curHeader].lpData = &tempbuffer[curHeader][0];

	waveOutPrepareHeader(hWaveOut, &header[curHeader], sizeof(WAVEHDR));
	waveOutWrite(hWaveOut, &header[curHeader], sizeof(WAVEHDR));
	firstWrite = 0;
}

void OpenSound()
{
	MMRESULT result = 0;
	WAVEFORMATEX wfx;

	memset(&wfx, 0, sizeof(WAVEFORMATEX));
	wfx.nSamplesPerSec = SampleRate;	
	wfx.wBitsPerSample = 16;
	wfx.nChannels = 2;

	wfx.cbSize = 0;
	wfx.wFormatTag = WAVE_FORMAT_PCM;
	wfx.nBlockAlign = (wfx.wBitsPerSample >> 3) * wfx.nChannels;
	wfx.nAvgBytesPerSec = wfx.nBlockAlign * wfx.nSamplesPerSec;

	printf("Waveoutopen\n");
	if (waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, (DWORD_PTR)_waveOutProc, 0, CALLBACK_FUNCTION)) {
		fprintf(stderr, "unable to open WAVE_MAPPER device\n");
		exit(0);
	}
	printf("Waveoutopen done\n");

}

static unsigned int buffersize = 0;
static unsigned char buffer[BUGSIZE];
static double play_time = 0;

void PlayBuffer(unsigned char *buf, unsigned int length) {
	uint32_t i = 0;	
	if (!AudioFirst) {
		AudioFirst = 1;		
		OpenSound();		
	}

	for (i = 0; i < (length >> 1); i += 2) {
		int32_t r = ((short*)buf)[i];
		int32_t l = ((short*)buf)[i + 1];

		((short*)buffer)[(buffersize >> 1) + i + 1] = r;
		((short*)buffer)[(buffersize >> 1) + i] = l;
	}

	buffersize += length;

	if (buffersize >(32768 - length)) {
		writeAudio(hWaveOut, buffer, buffersize);
		buffersize = 0;
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

char * usf_upload_file(usf_state_t * state, char * fn, void(*load_function)(usf_state_t*, uint8_t *, size_t), int swap)
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

void usf_save_sparsed_rom(usf_state_t * state, char * out_file_name, char * rom_file_name)
{
	FILE * sparse_file = NULL;
	void * bit_array = usf_get_rom_coverage_barray(state);
	char * rom_data = NULL;
	size_t rom_length = 0, ptr = 0;
	uint32_t offset = 0, position = 0, length = 0;
	

	rom_data = _load_file(rom_file_name, &rom_length, 1);
	if (!rom_data)
		return;

	sparse_file = fopen(out_file_name, "wb");
	if (!sparse_file) {
		free(rom_data);
		return;
	}

	// Write header
	fwrite("SR64", 4, 1, sparse_file);	

	for (ptr = 0; ptr < rom_length / 4; ptr++) {	
		uint32_t bit = bit_array_test(bit_array, ptr);		

		// Force the rom header to be included
		if (ptr <= 0x10) {
			bit = 1;
		}

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

void usf_save_sparsed_ram(usf_state_t * state, char * out_file_name, char * state_file_name, int32_t reg_num, int32_t index)
{
	FILE * sparse_file = NULL;
	void * bit_array = usf_get_ram_coverage_barray(state);	
	char * save_state = NULL;
	size_t state_length = 0, ptr = 0;
	uint32_t offset = 0, position = 0, length = 0x75c;
	uint64_t *regs;
	uint8_t *rdram;

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
	if(reg_num)
		regs[reg_num] = index;
	
	// Write header
	fwrite("SR64", 4, 1, sparse_file);	
	fwrite(&length, 4, 1, sparse_file);
	fwrite(&position, 4, 1, sparse_file);	
	fwrite(save_state, 0x75c, 1, sparse_file);
	length = 0;
	uint32_t bit2 = bit_array_test(bit_array, 0xC2);

	for (ptr = 0; ptr < (state_length - 0x275C) / 4; ptr++) {		
		uint32_t bit = bit_array_test(bit_array, ptr);

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
	char * rom_barray = usf_get_ram_coverage_barray(state);
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
#define BUFFER_SIZE 8000

typedef struct ripper_params_t {
	char * rom_name;
	char * state_name;
	int reg_num;
	int index;
	char * output_name;
	int play_length;
	int flags;
	int cur_thread;
} ripper_params_t;

typedef struct ripping_status_t {
	int index;
	char name[MAX_PATH];
	int play_length;
	int counter;
	int status;	
	usf_state_t * state;	
} ripping_status_t;

static ripping_status_t rip_status[MAX_THREADS];

void rip_usf(ripper_params_t *params)
{	
	int16_t buffer[BUFFER_SIZE * 2];
	int32_t play_audio = 0, count = BUFFER_SIZE, i = 0;
	size_t total_bitcount = 0, total_counter = 0;
	int32_t minimum = 1;
	usf_state_t * state = NULL;
	char out_rom_name[_MAX_FNAME], out_ram_name[_MAX_FNAME];
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
	
	strcpy(rom_name, params->rom_name);
	strcpy(state_name, params->state_name);
	strcpy(output_name, params->output_name);	

	state = malloc(usf_get_state_size());
	usf_clear(state);

	usf_set_trimming_mode(state, 1);

	usf_upload_file(state, (char *)rom_name, usf_upload_rom, 1);
	usf_upload_file(state, (char *)state_name, usf_upload_save_state, 0);

	usf_set_compare(state, 1);
	usf_set_fifo_full(state, 1);
	usf_set_hle_audio(state, 0);

	if (reg_num) {		
		uint8_t * rdram = ((uint8_t*)(USF_STATE->save_state) + 0x75C);
		uint64_t *regs = (uint64_t*)((char*)(USF_STATE->save_state) + 0x50);		
		// Alter this if necessary
		regs[reg_num] = index;		
	}

	strcpy(rip_status[cur_thread].name, output_name);	
	rip_status[cur_thread].index = index;
	rip_status[cur_thread].status = 1;
	rip_status[cur_thread].state = state;

	for (i = 0; (counter < play_length) || minimum; i++) {
		const char *e = usf_render(state, buffer, count, &SampleRate);
		counter++;
		total_counter++;		

		if (e)
			break;

		if (play_audio)
			PlayBuffer((char*)buffer, count * 4);		

		// Reset counter on new data read
		if (i % 35 == 0) {
			size_t new_bitcount = coverage_get_bitcount(state);
			if (new_bitcount != total_bitcount) {
				total_bitcount = new_bitcount;
				counter = 0;
			}
		}
				
		if ((i % 5) == 0) {
			// Play for a minimum of 10 minutes
			if (((i * count) / SampleRate) > 600)
				minimum = 0;

			rip_status[cur_thread].counter = counter;
			rip_status[cur_thread].play_length = ((i*count) / SampleRate);

		}
	}

	sprintf(out_rom_name, "%s%02x.rom", output_name, index);
	sprintf(out_ram_name, "%s%02x.ram", output_name, index);	

	usf_save_sparsed_ram(state, out_ram_name, state_name, reg_num, index);
	usf_save_sparsed_rom(state, out_rom_name, rom_name);
	usf_shutdown(state);
	free(state);
	rip_status[cur_thread].status = 0;	
	ExitThread(0);
}

// Eg: usf_ripper -r "c:\games\roms\Mario Kart 64 (U) [!].z64" -s "f:\usf\Project 64 1.5\MK64.pj" -o f:\usf\mk64\sparse -n 5 -b 0 -e 40 -c 3000 -t 4
int main(int argc, char ** argv)
{
	HANDLE threadIDs[MAX_THREADS];
	int32_t play_audio = 0, play_length = 2000, count = 2000, i = 0, c = 0, threads = 1;
	char state_name[_MAX_PATH], rom_name[_MAX_PATH], output_name[_MAX_FNAME];
	size_t total_bitcount = 0, begin = 0, end = 1, index = 0;
	int32_t last_counter[MAX_THREADS];
	int32_t last_counter_count[MAX_THREADS];
	uint32_t reg_num = 0, completed = 0;
	uint32_t threads_busy[MAX_THREADS];
	CONSOLE_SCREEN_BUFFER_INFO con_info;
	HANDLE console;
	struct option options[] = {
		{ "rom", required_argument, NULL, 'r' },
		{ "state", required_argument, NULL, 's' },
		{ "register_num", optional_argument, NULL, 'n' },
		{ "begin", optional_argument, NULL, 'b' },
		{ "end", optional_argument, NULL, 'e' },
		{ "count", optional_argument, NULL, 'c' },
		{ "output_name" , optional_argument, NULL, 'o'},
		{ "threads" , optional_argument, NULL, 't' },
		{NULL, 0, NULL, 0}
	};
	rom_name[0] = 0;
	state_name[0] = 0;
	strcpy(output_name, "sparse");

	while ((c = getopt_long(argc, argv, "r:s:n:b:e:c:o:t:", options, NULL)) != -1) {
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
				begin = atoi(optarg);
			break;
		case 'e':
			if (optarg)
				end = atoi(optarg);
			break;
		case 'o':
			if (optarg)
				strcpy(output_name, optarg);
			break;
		case 't':
			if (optarg)
				threads = atoi(optarg);
			break;
		}
	}

	if (!strlen(rom_name) || !strlen(state_name)) {
		return 2;
	}

	memset(threads_busy, 0, sizeof(uint32_t) * MAX_THREADS);
	memset(threadIDs, 0, sizeof(HANDLE) * MAX_THREADS);
	memset(rip_status, 0, sizeof(ripping_status_t) * MAX_THREADS);
	memset(last_counter, 0, sizeof(uint32_t) * MAX_THREADS);
	memset(last_counter_count, 0, sizeof(uint32_t) * MAX_THREADS);
	
	printf("Running USF ripper\nRunning %d threads\n\n", threads);
	console = GetStdHandle(STD_OUTPUT_HANDLE);
	GetConsoleScreenBufferInfo(console, &con_info);
	
	if (threads > (int32_t)(end - begin))
		threads = (end - begin) > 1 ? end-begin : 1;

	for(index = begin; completed <= (end - begin); ) {
		for (i = 0; i < threads; i++) {			
			uint32_t run_new = 0;
			if (threads_busy[i] == 0 && (index <= end))
				run_new = 1;
						
			if (threads_busy[i] == 1) {
				DWORD exit_code;
				BOOL status = GetExitCodeThread(threadIDs[i], &exit_code);
				if (status == 0 || exit_code == STILL_ACTIVE)
					continue;				
				completed++;
				CloseHandle(threadIDs[i]);
				threadIDs[i] = 0;
				threads_busy[i] = 0;				
			}

			if (index > end)
				continue;

			if (run_new == 1) {				
				ripper_params_t params;
				DWORD threadID;
				params.flags = 0;
				params.index = index;
				params.output_name = output_name;
				params.reg_num = reg_num;
				params.state_name = state_name;
				params.rom_name = rom_name;
				params.play_length = play_length;
				params.cur_thread = i;
				CreateThread(NULL, 0x100000, (LPTHREAD_START_ROUTINE)rip_usf, &params, 0, &threadID);
				threadIDs[i] = OpenThread(THREAD_ALL_ACCESS, TRUE, threadID);
				threads_busy[i] = 1;
				last_counter_count[i] = 0;
				last_counter[i] = 0;
				index++;
				Sleep(50);
			}
		}
		Sleep(250);
		for(i = 0; i < threads; i++) {
			COORD new_pos;
			char name[MAX_PATH];
			char buf[MAX_PATH], buf2[MAX_PATH];
			new_pos.X = con_info.dwCursorPosition.X;
			new_pos.Y = con_info.dwCursorPosition.Y + i;
			SetConsoleCursorPosition(console, new_pos);
			sprintf(name, "%s%02x", rip_status[i].name, rip_status[i].index);
			sprintf(buf, "Counter %5d / %5d", rip_status[i].counter, play_length);
			sprintf(buf2, "Ripping 0x%-3x", rip_status[i].index);
			printf("Thread %2d : %-15s %-24s  %d seconds        \n", i, buf2, buf, rip_status[i].play_length);
			if (last_counter[i] == rip_status[i].counter)
				last_counter_count[i]++;
			else
				last_counter_count[i] = 0;
			if (last_counter_count[i] == 250 && threads_busy[i]) {
				// frozen, skip												
				BOOL status = TerminateThread(threadIDs[i], 1);
				DWORD err_no = GetLastError();
				Sleep(200);				
				usf_shutdown(rip_status[i].state);				
				CloseHandle(threadIDs[i]);
				threads_busy[i] = 0;
				completed++;								
			}
			last_counter[i] = rip_status[i].counter;
		}
		printf("Completed %d / %d\n", completed, (end - begin)+1);
		fflush(stdout);		
	}

	printf("Doneski\n");
	return 0;
}


