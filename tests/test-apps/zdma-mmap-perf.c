
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <math.h>

#define NUM_TRIALS 1000

int main(int argc, char **argv)
{
  int fd, ret;
  struct timespec tvs, tve;
  uint64_t tdelta_ns;
  void *map_base;
  uint32_t dst;

  if (argc != 1) {
    fprintf(stderr, "usage: zdma-mmap-perf\n");
    return 1;
  }
  
  fd = open("/dev/zdma0_user", O_RDWR | O_SYNC);
  if (fd < 0) {
    perror("open() failed");
    return 1;
  }

  uint64_t time_array[3];

  map_base = mmap(0, 0x70000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if( map_base == (void *)-1 ) {
    perror("mmap() failed");
    return 1;
  }
  printf("Opened mmap at %p\n", (unsigned *)map_base);
  clock_gettime(CLOCK_REALTIME, &tvs);
  for( unsigned i = 0; i < NUM_TRIALS; i++ ) {
    *((unsigned *) map_base + 0xF000/4) = i + 1;
  }
  clock_gettime(CLOCK_REALTIME, &tve);
  tdelta_ns = ((tve.tv_sec - tvs.tv_sec) * 1000000000) + (tve.tv_nsec - tvs.tv_nsec);
  printf("%u trials took %luus\n", NUM_TRIALS,  tdelta_ns);
  time_array[0] = tdelta_ns;

  clock_gettime(CLOCK_REALTIME, &tvs);
  for( unsigned i = 0; i < NUM_TRIALS; i++ ) {
    dst = *((unsigned *) map_base + 0xF000/4);
  }
  clock_gettime(CLOCK_REALTIME, &tve);
  tdelta_ns = ((tve.tv_sec - tvs.tv_sec) * 1000000000) + (tve.tv_nsec - tvs.tv_nsec);
  printf("%u trials took %luus\n", NUM_TRIALS, tdelta_ns);
  time_array[1] = tdelta_ns;

  clock_gettime(CLOCK_REALTIME, &tvs);
  for( unsigned i = 0; i < NUM_TRIALS; i++ ) {
    dst = *((unsigned *) map_base + 0xF000/4);
    *((unsigned *) map_base + 0xF000/4) = i + 1;
    dst = *((unsigned *) map_base + 0xF000/4);
  }
  clock_gettime(CLOCK_REALTIME, &tve);
  tdelta_ns = ((tve.tv_sec - tvs.tv_sec) * 1000000000) + (tve.tv_nsec - tvs.tv_nsec);
  printf("%u trials took %luus\n", NUM_TRIALS, tdelta_ns);
  time_array[2] = tdelta_ns;

  printf("+------------+----------------------+\n");
  printf("| %10s | %20s |\n", "", "Avg Latency (ns)");
  printf("| %-10s | %20.2f |\n", "READ", (double)time_array[1]/(double)NUM_TRIALS);
  printf("| %-10s | %20.2f |\n", "WRITE", (double)time_array[0]/(double)NUM_TRIALS);
  printf("| %-10s | %20.2f |\n", "R/M/W", (double)time_array[2]/(double)NUM_TRIALS);
  printf("+------------+----------------------+\n");

  close(fd);
}
