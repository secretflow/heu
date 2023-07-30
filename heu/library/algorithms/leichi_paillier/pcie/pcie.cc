// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#include "pcie.h"

CPcieComm::CPcieComm()
{

}

CPcieComm::~CPcieComm()
{
}

int CPcieComm::open_device()
{
    wr_fd = open("/dev/xdma0_h2c_0", O_RDWR | O_NONBLOCK);  // xdma write channel.
    rd_fd = open("/dev/xdma0_c2h_0", O_RDWR | O_NONBLOCK);  // xdma read channel.
    bp_fd = open("/dev/xdma0_bypass", O_RDWR | O_NONBLOCK); // xdma bypass channel.

    if (wr_fd < 0 || rd_fd < 0 || bp_fd < 0)
    {
        // printf("CPcieComm::pcie:open device error!wr_fd:%d rd_fd:%d bp_fd:%d\n", wr_fd, rd_fd, bp_fd);
        return -1;
    }

    map_base = (int *)mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, bp_fd, 0);
    if (!map_base)
    {
        return -1;
    }

    b_pcie_open = true;
    return 1;
}

int CPcieComm::close_device()
{
    close(wr_fd); // write channel.
    close(rd_fd); // read channel.
    close(bp_fd); // bypass channel.
    b_pcie_open = false;
    munmap(map_base, MAP_SIZE);
    return 1;
}

bool CPcieComm::pcie_is_open()
{
    return b_pcie_open;
}

int CPcieComm::write_data(unsigned int addr, unsigned char *data, unsigned int len)
{
    int res = 0;
    // adjust to specified address.
    lseek(wr_fd, addr, SEEK_SET);

    res = write(wr_fd, (void *)data, len);

    if (res <= 0)
    {
        printf("CPcieComm:send data error.res=%d\n", res);
        return -1;
    }

    return res;
}

int CPcieComm::read_data(unsigned int addr, unsigned char *data, unsigned int len)
{
    int res = 0;
    // Read calculation result data.
    lseek(rd_fd, addr, SEEK_SET);

    res = read(rd_fd, (void *)data, len);
    if (res <= 0)
    {
        printf("read data error,res=%d\n", res);
        return -1;
    }
    return len;
}

int CPcieComm::write_data_bypass(unsigned int addr, unsigned char *data, unsigned int len)
{
    for (unsigned int i = 0; i < len; i++)
    {
        *((volatile uint8_t *)((unsigned char *)map_base + addr + i)) = *(data + i);
    }
    return len;
}

int CPcieComm::read_data_bypass(unsigned int addr, unsigned char *data, unsigned int len)
{
    for (unsigned int i = 0; i < len; i++)
    {
        *(data + i) = *((volatile uint8_t *)((unsigned char *)map_base + addr + i));
    }
    return len;
}

int CPcieComm::write_reg(unsigned int addr, unsigned int data)
{
    *((volatile unsigned int *)((unsigned char *)map_base+addr)) = data;
    return 1;
}

int CPcieComm::read_reg(unsigned int addr, unsigned int *data)
{
    *data = *((volatile unsigned int *)((unsigned char *)map_base+addr));
    return 1;
}
