// Copyright 2023 Polar Bear Tech (Xi 'an) Co., LTD.
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

#pragma once
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<fcntl.h>
#include<sys/mman.h>
#include<arpa/inet.h>
 
#define MAP_SIZE (2*1024*1024UL)

class CPcieComm
{
public:
	CPcieComm();
	~CPcieComm();
public: 
    int open_device();  
    int close_device();
    bool pcie_is_open(); 
    int write_data(unsigned int addr,unsigned char *data,unsigned int len);  
    int read_data(unsigned int addr,unsigned char *data,unsigned int len);
    int write_data_bypass(unsigned int addr,unsigned char *data,unsigned int len);
    int read_data_bypass(unsigned int addr,unsigned char *data,unsigned int len);
    int write_reg(unsigned int addr,unsigned int data); 
    int read_reg(unsigned int addr, unsigned int *data);
private:
    int wr_fd;  //write channel fd.
    int rd_fd;  //read channel fd.
    int bp_fd;  //bypass channel fd.
    int *map_base;
    bool b_pcie_open =false;
};