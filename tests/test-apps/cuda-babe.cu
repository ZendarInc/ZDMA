#include <cuda.h>
#include <cuda_runtime_api.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define SURFACE_W  256
#define SURFACE_H  256
#define SURFACE_SIZE  (SURFACE_W * SURFACE_H)

#define OFFSET(x, y)  (((y) * SURFACE_W) + x)
#define DATA(x, y)  (((y & 0xffff) << 16) | ((x) & 0xffff))

extern "C" __global__ void reorder_bytes(uint32_t* gpu_data)
{
  unsigned int pos_x = (blockIdx.x * blockDim.x) + threadIdx.x;
  unsigned int pos_y = (blockIdx.y * blockDim.y) + threadIdx.y;

  const uint32_t word = gpu_data[OFFSET(pos_x, pos_y)];
  const uint8_t b0 = word & 0xFF;
  const uint8_t b1 = (word >> 8) & 0xFF;
  const uint8_t b2 = (word >> 16) & 0xFF;
  const uint8_t b3 = (word >> 24) & 0xFF;

  gpu_data[OFFSET(pos_x, pos_y)] = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
}

void HexDump(const uint8_t* bytes, size_t size)
{
  if (!size) return;

  const size_t bytes_per_line = 16;
  const size_t total_lines = ((size - 1) / bytes_per_line) + 1;

  for (size_t line = 0; line < total_lines; ++line) {
    const unsigned int offset = line * bytes_per_line;
    // Show the offset each line:
    printf("%08x", offset);

    // Hex bytes
    for (size_t i = offset; i < offset + bytes_per_line; ++i) {
      // Add a bit of space for visual clarity
      if (i % (bytes_per_line / 2) == 0)
        printf(" ");
      if (i < size)
        printf(" %02x", bytes[i]);
      else
        printf("   ");
    }

    // printable characters
    printf("  ");
    for (size_t i = offset; i < offset + bytes_per_line && i < size; ++i) {
      char c = bytes[i];
      const char first_printable = ' ';
      const char last_printable = '\x7e';
      if (c < first_printable || c > last_printable)
        printf(".");
      else
        printf("%c", c);
    }
    printf("\n");
    fflush(stdout);
  }
}

uint32_t init_data[SURFACE_SIZE * sizeof(uint32_t)];

int main(int argc, char **argv)
{
  cudaError_t ce;
  CUresult cr;
  uint32_t* src_d;
  int c2h_fd, h2c_fd, ret;
  unsigned int flag = 1;
  /*
  struct picoevb_rdma_pin_cuda pin_params_src;
  struct picoevb_rdma_h2c2h_dma dma_params;
  struct picoevb_rdma_unpin_cuda unpin_params_src;
  */

  if (argc != 1) {
    fprintf(stderr, "usage: cuda-babe\n");
    return 1;
  }

  //c2h_fd = open("/dev/picoevb", O_RDWR);
  c2h_fd = open("/dev/xdma0_c2h_0", O_RDONLY);
  if (c2h_fd < 0) {
    perror("open() failed");
    return 1;
  }

  h2c_fd = open("/dev/xdma0_h2c_0", O_WRONLY);
  if (h2c_fd < 0) {
    perror("open() failed");
    return 1;
  }

  // *** INIT DATA to FPGA ***
  for (size_t i = 0; i < SURFACE_SIZE; ++i) {
    init_data[i] = i;
  }

  ret = lseek(h2c_fd, 0x80000000, SEEK_SET);
  if (ret == -1) {
    fprintf(stderr, "lseek(DMA) failed: %d\n", ret);
    perror("lseek() failed");
    return 1;
  }
  ret = write(h2c_fd, init_data, SURFACE_SIZE * sizeof(uint32_t));
  if (ret == -1) {
    fprintf(stderr, "write(DMA) failed: %d\n", ret);
    perror("write() failed");
    return 1;
  }
  close(h2c_fd);

  ce = cudaMallocManaged(&src_d, SURFACE_SIZE * sizeof(*src_d));

  if (ce != cudaSuccess) {
    fprintf(stderr, "Allocation of src_d failed: %s\n",
      cudaGetErrorString(ce));
    return 1;
  }

  cr = cuPointerSetAttribute(&flag, CU_POINTER_ATTRIBUTE_SYNC_MEMOPS,
    (CUdeviceptr)src_d);
  if (cr != CUDA_SUCCESS) {
    fprintf(stderr, "cuPointerSetAttribute(src_d) failed: %d\n", cr);
    return 1;
  }

  ret = lseek(c2h_fd, 0x80000000, SEEK_SET);
  if (ret == -1) {
    fprintf(stderr, "lseek(DMA) failed: %d\n", ret);
    perror("lseek() failed");
    return 1;
  }

  ret = read(c2h_fd, src_d, SURFACE_SIZE * sizeof(*src_d));
  if (ret == -1) {
    fprintf(stderr, "read(DMA) failed: %d\n", ret);
    perror("read() failed");
    return 1;
  }

  dim3 dimGrid(SURFACE_W / 16, SURFACE_H / 16);
  dim3 dimBlock(16, 16);
  reorder_bytes<<<dimGrid, dimBlock>>>(src_d);

  ce = cudaDeviceSynchronize();
  if (ce != cudaSuccess) {
    fprintf(stderr, "cudaDeviceSynchronize() failed: %d\n", ce);
    return 1;
  }

  // If this works, it's because of some weird zero-copy logic.
  HexDump((uint8_t*)src_d, SURFACE_SIZE * sizeof(*src_d));

  ce = cudaFree(src_d);

  if (ce != cudaSuccess) {
    fprintf(stderr, "Free of src_d failed: %d\n", ce);
    return 1;
  }

  ret = close(c2h_fd);
  if (ret < 0) {
    perror("close() failed");
    return 1;
  }
}

