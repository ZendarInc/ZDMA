#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define MAX_TRANSFER_SIZE (128 * 1024 * 1024)

int main(int argc, char **argv)
{
  int h2c_fd, c2h_fd, ret, retw, retr;
  uint64_t transfer_size;
  void *src;
  struct timespec tvs, tvm, tve;
  uint64_t twrite_us, tread_us, ttot_us;

  if (argc != 1) {
    fprintf(stderr, "usage: zdma-h2c2h-perf\n");
    return 1;
  }

  h2c_fd = open("/dev/zdma0_h2c_0", O_RDWR);
  if (h2c_fd < 0) {
    perror("open() failed");
    return 1;
  }

  c2h_fd = open("/dev/zdma0_c2h_0", O_RDONLY);
  if (c2h_fd < 0) {
    perror("open() failed");
    return 1;
  }

  int CHUNK_SAMPLES = log(MAX_TRANSFER_SIZE) / log(2);
  int NUM_AVERAGES = 100;   // Number of tests at each chunk size

  uint64_t len_array[CHUNK_SAMPLES];
  for (int i = 0; i < CHUNK_SAMPLES; i++) {
    len_array[i] = pow(2, i+1);
    if (len_array[i] > MAX_TRANSFER_SIZE)
      len_array[i] = MAX_TRANSFER_SIZE;
  }

  uint64_t time_array[3][CHUNK_SAMPLES];
  for (int i = 0; i < CHUNK_SAMPLES; i++) {
    time_array[0][i] = 0;
    time_array[1][i] = 0;
    time_array[2][i] = 0;
  }

  for (int i = 0; i < CHUNK_SAMPLES; i++) {
    transfer_size = len_array[i];
    printf("Test transfer size = %lu\n", transfer_size);

    src = calloc(transfer_size, 1);
    if (!src) {
      fprintf(stderr, "malloc(src) failed\n");
      return 1;
    }

    for (int j = 0; j < NUM_AVERAGES; j++) {
      off_t rc = lseek(h2c_fd, 0x80000000, SEEK_SET);
      if (rc < 0) {
        perror("lseek() failed");
        return 1;
      }
      rc = lseek(c2h_fd, 0x80000000, SEEK_SET);
      if (rc < 0) {
        perror("lseek() failed");
        return 1;
      }
      clock_gettime(CLOCK_REALTIME, &tvs);
      retw = write(h2c_fd, src, transfer_size);
      clock_gettime(CLOCK_REALTIME, &tvm);
      retr = read(c2h_fd, src, transfer_size);
      clock_gettime(CLOCK_REALTIME, &tve);
      if (retw < 0) {
        fprintf(stderr, "write(DMA) failed: %d\n", retw);
        perror("write() failed");
        return 1;
      }
      if (retr < 0) {
        fprintf(stderr, "write(DMA) failed: %d\n", retr);
        perror("read() failed");
        return 1;
      }

      ttot_us = ((tve.tv_sec - tvs.tv_sec) * 1000000) + (tve.tv_nsec - tvs.tv_nsec)/1000;
      twrite_us = ((tvm.tv_sec - tvs.tv_sec) * 1000000) + (tvm.tv_nsec - tvs.tv_nsec)/1000;
      tread_us = ((tve.tv_sec - tvm.tv_sec) * 1000000) + (tve.tv_nsec - tvm.tv_nsec)/1000;
      time_array[0][i] = time_array[0][i] + ttot_us;
      time_array[1][i] = time_array[1][i] + twrite_us;
      time_array[2][i] = time_array[2][i] + tread_us;
    }

    free(src);
  }

  printf("|------------+------------+------------+------------|\n");
  printf("| %-10s | %-10s | %-10s | %-10s |\n",
        "Bytes",
        "Read MB/s",
        "Write MB/s",
        "RT MB/s");
  printf("|------------+------------+------------+------------|\n");
  for (int i = 0; i < CHUNK_SAMPLES; i++) {
    printf("| %-10lu | %10.2f | %10.2f | %10.2f |\n",
          len_array[i], 
          (double)len_array[i]/ ((double)time_array[2][i] / NUM_AVERAGES),
          (double)len_array[i]/ ((double)time_array[1][i] / NUM_AVERAGES),
          (double)len_array[i]/ ((double)time_array[0][i] / NUM_AVERAGES));
  }
  printf("|---------------------------------------------------|\n");

  ret = close(c2h_fd);
  ret = close(h2c_fd);
  if (ret < 0) {
    perror("close() failed");
    return 1;
  }

  return 0;
}

