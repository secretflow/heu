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

#include "compiler.h"

std::vector<std::string> CHIP_ORDER = {
    "CHIP_0",  
    "CHIP_2", 
    "CHIP_4",  
    "CHIP_7",  
    "CHIP_9",  
    "CHIP_11", 
    "CHIP_12", 
    "CHIP_15",  
};

std::map<std::string, int> CHIP_TABLE = {
    {"CHIP_0",  (int) std::pow(2, 15)},
    {"CHIP_1",  (int) std::pow(2, 14)},
    {"CHIP_2",  (int) std::pow(2, 13)},
    {"CHIP_3",  (int) std::pow(2, 12)},
    {"CHIP_4",  (int) std::pow(2, 11)},
    {"CHIP_5",  (int) std::pow(2, 10)},
    {"CHIP_6",  (int) std::pow(2,  9)},
    {"CHIP_7",  (int) std::pow(2,  8)},
    {"CHIP_8",  (int) std::pow(2,  7)},
    {"CHIP_9",  (int) std::pow(2,  6)},
    {"CHIP_10", (int) std::pow(2,  5)},
    {"CHIP_11", (int) std::pow(2,  4)},
    {"CHIP_12", (int) std::pow(2,  3)},
    {"CHIP_13", (int) std::pow(2,  2)},
    {"CHIP_14", (int) std::pow(2,  1)},
    {"CHIP_15", (int) std::pow(2,  0)},
};

uint64_t gen_inst_l(uint32_t address, uint32_t length, uint8_t des_pe, uint8_t des_reg, uint16_t times, bool change_flag, uint8_t pe_gate) {
    if (address >= 80*1024) {
        throw std::runtime_error("Sram data in can't hold the data need");
    }
    uint64_t inst = 0;
    inst = inst + ( (0b01        % static_cast<uint64_t>(std::pow(2, 2))) << 62 );
    inst = inst + ( (address     % static_cast<uint64_t>(std::pow(2, 18))) << 44 );
    inst = inst + ( (length      % static_cast<uint64_t>(std::pow(2, 18))) << 26 );
    inst = inst + ( (des_pe      % static_cast<uint64_t>(std::pow(2, 6))) << 20 );
    inst = inst + ( (des_reg     % static_cast<uint64_t>(std::pow(2, 4))) << 16 );
    inst = inst + ( (times       % static_cast<uint64_t>(std::pow(2, 10))) << 6 );
    inst = inst + ( (change_flag % static_cast<uint64_t>(std::pow(2, 1))) << 5 );
    inst = inst + ( (pe_gate     % static_cast<uint64_t>(std::pow(2, 5))) << 0 );
    return inst;
}

uint64_t gen_inst_c(uint8_t pe_state, bool cal_flag, uint8_t pe_n_state, uint32_t address, uint8_t pe_gate) {
    uint64_t inst = 0;
    inst = inst + ( (0b10        % static_cast<uint64_t>(std::pow(2, 2))) << 62 );
    inst = inst + ( (pe_state    % static_cast<uint64_t>(std::pow(2, 8))) << 54 );
    inst = inst + ( (cal_flag    % static_cast<uint64_t>(std::pow(2, 1))) << 53 );
    inst = inst + ( (pe_n_state  % static_cast<uint64_t>(std::pow(2, 8))) << 45 );
    inst = inst + ( (address     % static_cast<uint64_t>(std::pow(2, 18))) << 27 );
    inst = inst + ( (pe_gate     % static_cast<uint64_t>(std::pow(2, 5))) << 22 );
    inst = inst + (  0b0                                                 << 0  );
    return inst;
}

uint64_t gen_inst_i(uint64_t ddr_address,uint64_t ddr_length) {
    uint64_t inst = 0;
    inst = inst + ( (0b11                                                     % static_cast<uint64_t>(std::pow(2, 2))) << 62 );
    inst = inst + ( (ddr_address                      % static_cast<uint64_t>(std::pow(2, 32))) << 30 );
    inst = inst + ( ((ddr_length-1) & 0x1fff          % static_cast<uint64_t>(std::pow(2, 13))) << 17 );
    return inst;
}

uint64_t gen_inst_none(){
    uint128_t inst = 0;
    return inst;
}

void check_inst_sram_depth(std::vector<uint64_t> _inst)
{
    std::stringstream ss;
    if(_inst.size()>=LOCAL_INST_BUFFER_DEPTH)
    {
        ss << "Sram inst in can't hold the data need";
        throw std::runtime_error(ss.str());
    }
}

uint128_t gen_inst_r(uint16_t chip, uint8_t data_type, uint32_t data_address, uint32_t data) {
    uint128_t inst = 0;
    inst = inst + ( (0b110          % static_cast<uint128_t>(std::pow(2, 3))) << 125 );
    inst = inst + ( (chip           % static_cast<uint128_t>(std::pow(2, 16))) << 109 );
    inst = inst + ( (data_type      % static_cast<uint128_t>(std::pow(2, 3))) << 106 );
    inst = inst + ( (data_address   % static_cast<uint128_t>(std::pow(2, 32))) << 74 );
    inst = inst + ( (data           % static_cast<uint128_t>(std::pow(2, 32))) << 42 );
    return inst;
}

uint128_t gen_inst_l1(uint16_t chip, uint32_t ddr_address, uint32_t ddr_length, uint8_t data_type, uint32_t data_address, bool bool_check) {
    uint128_t inst = 0;
    if (ddr_length == 0) {
        ddr_length = 1;
    }
    inst = inst + ( (0b000          % static_cast<uint128_t>(std::pow(2, 3))) << 125 );
    inst = inst + ( (chip           % static_cast<uint128_t>(std::pow(2, 16))) << 109 );
    inst = inst + ( (ddr_address    % static_cast<uint128_t>(std::pow(2, 32))) << 77 );
    inst = inst + ( ((ddr_length-1) % static_cast<uint128_t>(std::pow(2, 32))) << 45 );
    inst = inst + ( (data_type      % static_cast<uint128_t>(std::pow(2, 3))) << 42 );
    inst = inst + ( (data_address   % static_cast<uint128_t>(std::pow(2, 32))) << 10 );
    inst = inst + ( (bool_check     % static_cast<uint128_t>(std::pow(2, 0))) << 9 );
    return inst;
}

uint128_t gen_inst_l2(uint16_t chip, uint16_t times) {
    uint128_t inst = 0;
    inst = inst + ( (0b001          % static_cast<uint128_t>(std::pow(2, 3))) << 125 );
    inst = inst + ( (chip           % static_cast<uint128_t>(std::pow(2, 16))) << 109 );
    inst = inst + ( ((times-1)      % static_cast<uint128_t>(std::pow(2, 16))) << 93 );
    return inst;
}

uint8_t get_bit_of_data(uint64_t data, uint32_t start_bit, uint32_t end_bit) {
    uint32_t length = start_bit - end_bit + 1;
    uint64_t dat_tmp = static_cast<uint64_t>(std::pow(2,end_bit));
    uint8_t result = static_cast<uint32_t>(data/dat_tmp) % static_cast<uint32_t>(pow(2,length));
    return result;
}

generator_fpga::generator_fpga()
{
    chip_num = NUMBER_OF_CHIP;
}

void generator_fpga::clear()
{
    inst.clear();
}

void generator_fpga::gen_inst(struct Program program,std::vector<std::vector<uint32_t>> task_split,struct memory_allocation_t memory_allocation,
        std::vector<std::vector<std::vector<uint64_t>>> inst,std::vector<std::vector<std::vector<uint32_t>>> inst_split)
{
    clear();
    __gen_inst_none__();
    _gen_inst_vector_(program,task_split,memory_allocation,inst,inst_split);
}


void generator_fpga::_gen_inst_vector_(struct Program program,std::vector<std::vector<uint32_t>> task_split,struct memory_allocation_t memory_allocation,
        std::vector<std::vector<std::vector<uint64_t>>> inst,std::vector<std::vector<std::vector<uint32_t>>> inst_split)
{
    __gen_inst_pll_lock__();
    __gen_inst_inst_reset__();
    __gen_inst_vector_l1_data_para(memory_allocation);
    __gen_inst_l1_wait__();
    for(uint32_t task_split_first = 0; task_split_first < task_split[0].size(); task_split_first++)
    {
        __gen_inst_inst_reset__();
        for(uint32_t chip_sel = 0; chip_sel < task_split.size(); chip_sel++)
        {
            if(task_split[chip_sel].size() <= task_split_first){break;}
            __gen_inst_vector_l1_data__(chip_sel,task_split_first,memory_allocation);
        }
        __gen_inst_l1_wait__();
        for(uint32_t chip_sel = 0; chip_sel < task_split.size(); chip_sel++)
        {
            if(task_split[chip_sel].size() <= task_split_first){break;}
            __gen_inst_vector_l1_inst__(chip_sel,task_split_first,memory_allocation);
        }
        __gen_inst_l1_wait__();
        for(uint32_t chip_sel = 0; chip_sel < task_split.size(); chip_sel++)
        {
            if(task_split[chip_sel].size() <= task_split_first){break;}
            __gen_inst_vector_r_inst_length_first__(chip_sel,task_split_first,inst_split);
        }
        __gen_inst_vector_r_inst_length_middle__(task_split_first,inst,inst_split,task_split);
        __gen_inst_vector_r_inst_length_last__(task_split_first,inst,inst_split);
    }
    __gen_inst_inst_reset__();
    __gen_inst_i__();
}

void generator_fpga::__gen_inst_none__()
{
    uint128_t inst_temp=0;
    inst_temp = gen_inst_none();
    inst.push_back(inst_temp);
}

void generator_fpga::__gen_inst_pll_lock__()
{
    uint128_t inst_temp=0;
    uint32_t inst_r_chip = 0;
    uint32_t inst_r_data_type = w_reg;
    uint32_t inst_r_data_address = ADDRESS_PIN_MUX;
    uint32_t inst_r_data = DATA_PIN_MUX_PAD;
    for(uint16_t chip_sel=0 ; chip_sel < NUMBER_OF_CHIP ; chip_sel++)
    {
        inst_r_chip += CHIP_TABLE[CHIP_ORDER[chip_sel]];
    }
    inst_temp = gen_inst_r(inst_r_chip,inst_r_data_type,inst_r_data_address,inst_r_data);
    inst.push_back(inst_temp);
}


void generator_fpga::__gen_inst_inst_reset__()
{
    uint128_t inst_temp=0;
    uint32_t inst_r_chip = 0;
    uint32_t inst_r_data_type = inst_reset;
    uint32_t inst_r_data_address = 0x00000000;
    uint32_t inst_r_data = 0x00000000;

    for(uint16_t chip_sel=0 ; chip_sel < NUMBER_OF_CHIP ; chip_sel++)
    {
        inst_r_chip += CHIP_TABLE[CHIP_ORDER[chip_sel]];
    }
    inst_temp = gen_inst_r(inst_r_chip,inst_r_data_type,inst_r_data_address,inst_r_data);
    inst.push_back(inst_temp);
}

void generator_fpga::__gen_inst_inst_flag__(uint8_t chip_sel,uint32_t length)
{
    uint128_t inst_temp=0;
    uint32_t inst_r_chip = 0;
    uint32_t inst_r_data_type = w_reg;
    uint32_t inst_r_data_address = ADDRESS_INST_FLAG;
    uint32_t inst_r_data = length;
    inst_r_chip = CHIP_TABLE[CHIP_ORDER[chip_sel]];
    inst_temp = gen_inst_r(inst_r_chip,inst_r_data_type,inst_r_data_address,inst_r_data);
    inst.push_back(inst_temp);
}

void generator_fpga::__gen_inst_w__(uint32_t address,uint32_t data)
{
    uint128_t inst_temp=0;
    uint32_t inst_r_chip = 0;
    uint32_t inst_r_data_type = w_reg;
    uint32_t inst_r_data_address = address;
    uint32_t inst_r_data = data;
    for(uint16_t chip_sel=0 ; chip_sel < NUMBER_OF_CHIP ; chip_sel++)
    {
        inst_r_chip += CHIP_TABLE[CHIP_ORDER[chip_sel]];
    }
    inst_temp = gen_inst_r(inst_r_chip,inst_r_data_type,inst_r_data_address,inst_r_data);
    inst.push_back(inst_temp);
}


void generator_fpga::__gen_inst_l1_wait__()
{
    #if 0
        uint128_t inst_temp=0;
        uint16_t chip = 0;
        uint32_t ddr_address = 0;
        uint32_t ddr_length = 0;
        uint8_t data_type = 0;
        uint32_t data_address = 0;
        bool bool_check =1;
    
        inst_temp = gen_inst_l1(chip,ddr_address,ddr_length,data_type,data_address,bool_check);
        inst.push_back(inst_temp);
    #endif
}


void generator_fpga::__gen_inst_vector_l1_data_para(struct memory_allocation_t __memory_allocation)
{
    uint128_t inst_temp=0;
    uint32_t inst_l1_chip = 0;
    uint32_t inst_l1_ddr_address = __memory_allocation.in_para_ddr_address_total;
    uint32_t inst_l1_ddr_length = __memory_allocation.in_para_ddr_length_total;
    uint8_t inst_l1_data_type = w_data;
    uint32_t inst_l1_data_address = 0x00000000;
    for(uint16_t chip_sel=0 ; chip_sel < NUMBER_OF_CHIP ; chip_sel++)
    {
        inst_l1_chip += CHIP_TABLE[CHIP_ORDER[chip_sel]];
    }
    inst_temp = gen_inst_l1(inst_l1_chip,inst_l1_ddr_address,inst_l1_ddr_length,inst_l1_data_type,inst_l1_data_address);
    inst.push_back(inst_temp);
}

void generator_fpga::__gen_inst_vector_l1_data__(uint16_t chip,uint32_t task_split_first,struct memory_allocation_t __memory_allocation)
{
    uint128_t inst_temp=0;
    uint32_t last_l1_data_address = __memory_allocation.in_para_ddr_length_total * GLOBAL_BUFFER_WIDTH / LOCAL_BUFFER_WIDTH ;
    uint32_t inst_l1_chip = CHIP_TABLE[CHIP_ORDER[chip]];
    uint32_t inst_l1_ddr_address = 0;
    uint32_t inst_l1_ddr_length = 0;
    uint8_t inst_l1_data_type = w_data;
    uint32_t inst_l1_data_address = 0;
    for(uint32_t i_of_op = 0; i_of_op< __memory_allocation.in_dat_ddr_mem_alloc.size(); i_of_op++)
    {
        inst_l1_ddr_address = __memory_allocation.in_dat_ddr_mem_alloc[i_of_op].in_data_detail[chip][task_split_first].out_ddr_addr;
        inst_l1_ddr_length = __memory_allocation.in_dat_ddr_mem_alloc[i_of_op].in_data_detail[chip][task_split_first].out_ddr_length;
        inst_l1_data_address = (int)last_l1_data_address;
        inst_temp = gen_inst_l1(inst_l1_chip,inst_l1_ddr_address,inst_l1_ddr_length,inst_l1_data_type,inst_l1_data_address);
        inst.push_back(inst_temp);
        last_l1_data_address += inst_l1_ddr_length*GLOBAL_BUFFER_WIDTH/LOCAL_BUFFER_WIDTH;
    }
}

void generator_fpga::__gen_inst_vector_l1_inst__(uint16_t chip,uint32_t task_split_first,struct memory_allocation_t __memory_allocation)
{
    uint128_t inst_temp=0;
    uint32_t inst_l1_chip = CHIP_TABLE[CHIP_ORDER[chip]];
    uint32_t inst_l1_ddr_address = __memory_allocation.inst_detail[chip][task_split_first].out_ddr_addr;
    uint32_t inst_l1_ddr_length = __memory_allocation.inst_detail[chip][task_split_first].out_ddr_length;
    uint8_t inst_l1_data_type = w_inst;
    uint32_t inst_l1_data_address = 0x00000000;
    inst_temp = gen_inst_l1(inst_l1_chip,inst_l1_ddr_address,inst_l1_ddr_length,inst_l1_data_type,inst_l1_data_address);
    inst.push_back(inst_temp);
}
        
void generator_fpga::__gen_inst_vector_r_inst_length_first__(uint16_t chip,uint32_t task_split_first,std::vector<std::vector<std::vector<uint32_t>>> __inst_split_asic)
{
    uint128_t inst_temp=0;
    uint32_t inst_r_chip = CHIP_TABLE[CHIP_ORDER[chip]];
    uint32_t inst_r_data_address = 0;
    uint8_t inst_r_data_type = w_inst_length;
    uint32_t inst_r_data = __inst_split_asic[chip][task_split_first][0];
    inst_temp = gen_inst_r(inst_r_chip,inst_r_data_type,inst_r_data_address,inst_r_data);
    inst.push_back(inst_temp);
}

void generator_fpga::__gen_inst_vector_r_inst_length_middle__(uint32_t task_split_first,std::vector<std::vector<std::vector<uint64_t>>> __inst_asic,std::vector<std::vector<std::vector<uint32_t>>> __inst_split_asic,std::vector<std::vector<uint32_t>> __task_split)
{
    uint128_t inst_temp=0;
    uint32_t inst_r_chip = 0;
    
    uint32_t inst_r_data_address = 0;
    uint8_t inst_r_data_type = w_inst;
    uint32_t inst_r_data = 0x00000000;

    uint32_t inst_length_min_true = 0;
    uint32_t inst_length_min_false = 0;

    inst_length_min_true = __inst_asic[0][task_split_first].size();
    inst_length_min_false = __inst_asic[0][task_split_first].size();
    min_chip_true = 0;
    min_chip_false = 0;

    for(uint32_t chip_sel = 0; chip_sel < NUMBER_OF_CHIP; chip_sel++)
    {
        if(__task_split[chip_sel].size() <= task_split_first)
        {
            break;
        }
        if(__inst_asic[chip_sel][task_split_first].size() < inst_length_min_true)
        {
            inst_length_min_true = __inst_asic[chip_sel][task_split_first].size();
            min_chip_true = chip_sel;
        }
        if(__inst_asic[chip_sel][task_split_first].size() <= inst_length_min_false)
        {
            inst_length_min_false = __inst_asic[chip_sel][task_split_first].size();
            min_chip_false = chip_sel;
        }
    }

    for(uint16_t chip_sel=0 ; chip_sel < min_chip_false+1 ; chip_sel++)
    {
        inst_r_chip += CHIP_TABLE[CHIP_ORDER[chip_sel]];
    }
    inst_r_data_type = w_inst_length;
    inst_r_data_address = 0x00000000;
    inst_r_data = __inst_asic[min_chip_false][task_split_first].size() - __inst_split_asic[min_chip_false][task_split_first][0];
    inst_temp = gen_inst_r(inst_r_chip,inst_r_data_type,inst_r_data_address,inst_r_data);
    inst.push_back(inst_temp);

    uint32_t inst_l2_chip = inst_r_chip;
    uint32_t inst_times = __inst_split_asic[min_chip_false][task_split_first].size()-1;
    inst_temp = gen_inst_l2(inst_l2_chip,inst_times);
    inst.push_back(inst_temp);
}



void generator_fpga::__gen_inst_vector_r_inst_length_last__(uint32_t task_split_first,std::vector<std::vector<std::vector<uint64_t>>> __inst_asic,std::vector<std::vector<std::vector<uint32_t>>> __inst_split_asic)
{
    uint128_t inst_temp=0;
    uint32_t inst_r_chip = 0;
    uint32_t inst_l2_chip = 0;
    uint32_t inst_times = 0;
    uint32_t inst_r_data_address = 0;
    uint8_t inst_r_data_type = w_inst_length;
    uint32_t inst_r_data = 0x00000000;

    if(min_chip_true!=0)
    {
        for(uint16_t chip_sel = 0; chip_sel < min_chip_false; chip_sel++)
        {
            inst_r_chip += CHIP_TABLE[CHIP_ORDER[chip_sel]];
        }
        inst_r_data = __inst_asic[0][task_split_first].size() - __inst_asic[min_chip_false][task_split_first].size();
        inst_temp = gen_inst_r(inst_r_chip,inst_r_data_type,inst_r_data_address,inst_r_data);
        inst.push_back(inst_temp);

        inst_l2_chip =inst_r_chip;
        inst_times = __inst_split_asic[0][task_split_first].size() - __inst_split_asic[min_chip_false][task_split_first].size();
        inst_temp = gen_inst_l2(inst_l2_chip,inst_times);
        inst.push_back(inst_temp);
    }
}

void generator_fpga::__gen_inst_vector_r_inst_length_add__(uint16_t chip_sel)
{
    uint128_t inst_temp=0;
    uint32_t inst_r_chip = CHIP_TABLE[CHIP_ORDER[chip_sel]];
    uint32_t inst_r_data_address = 0x00000000;
    uint8_t inst_r_data_type = w_inst_length;
    uint32_t inst_r_data = 1;
    inst_temp = gen_inst_r(inst_r_chip,inst_r_data_type,inst_r_data_address,inst_r_data);
    inst.push_back(inst_temp);
}

Compiler::Compiler()
{
    num_of_chip = NUMBER_OF_CHIP;
    num_of_pe = NUMBER_OF_PE;
    ddr_address = 0;
}

void Compiler::set_device(uint8_t number_of_chip,uint8_t number_of_pe,uint64_t ddr)
{
    this->num_of_chip= (number_of_chip!=0)?number_of_chip:this->num_of_chip;
    this->num_of_pe= (number_of_chip!=0)?number_of_pe:this->num_of_pe;
    this->ddr_size= (number_of_chip!=0)?ddr:this->ddr_size;
}

void Compiler::clear()
{
    inst.clear();
    task_split.clear();
    inst_split.clear();
    inst_byte.clear();
    memory_allocation.out_detail.clear();
    memory_allocation.inst_detail.clear();
    memory_allocation.in_dat_ddr_mem_alloc.clear();
    executor.inst.clear();
    executor.inst_fpga.clear();
    memory_allocation.last_ddr_address = 0;
    ddr_address = 0;
}


void Compiler::get_k_dat(struct Program program)
{
    if(program.operation_type == "MOD_MUL")
    {
        _k_dat = {
            "MOD_MUL",
            2, 
            0, 
            2,
            {
                {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
                {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}}
            } 
        };
    }
    else if(program.operation_type == "PAILLIER_ENC")
    {
        _k_dat = {
            "PAILLIER_ENC",
            5, 
            0, 
            2, 
            {
                {{"P_BITCOUNT", 0}, {"E_BITCOUNT", 1}},
                {{"P_BITCOUNT", 0.5}, {"E_BITCOUNT", 0}}
            } 
        };
    }
    else if(program.operation_type == "MOD_EXP_CONST_E")
    {
        _k_dat = {
            "MOD_EXP_CONST_E",
            2, 
            1, 
            2, 
            {
                {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
            } 
        };
    }
    else if(program.operation_type == "MOD_EXP")
    {
        _k_dat = {
            "MOD_EXP",
            2, 
            0, 
            2, 
            {
                {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
                {{"P_BITCOUNT", 0}, {"E_BITCOUNT", 1}}
            } 
        };
    }
    else if(program.operation_type == "MOD_MUL_CONST")
    {
        _k_dat = {
            "MOD_MUL_CONST",
            3, 
            0, 
            2, 
            {
                {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
            } 
        };
    }
    else if(program.operation_type == "MOD_EXP_CONST_A")
    {
        _k_dat = {
            "MOD_EXP_CONST_A",
            3, 
            0, 
            2, 
            {
                {{"P_BITCOUNT", 0}, {"E_BITCOUNT", 1}},
            } 
        };
    }
    else if(program.operation_type == "MOD_ADD")
    {
        _k_dat = {
            "MOD_ADD",
            1, 
            0, 
            1, 
            {
                {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
                {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}}
            } 
        };
    }
    else if(program.operation_type == "MOD_ADD_CONST")
    {
        _k_dat = {
            "MOD_ADD_CONST",
            2, 
            0, 
            1, 
            {
                {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
            } 
        };
    }
    else if(program.operation_type == "MONT")
    {
        _k_dat = {
            "MONT",
            1, 
            0, 
            2, 
            {
                {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
                {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}}
            }
        };
    }
    else if(program.operation_type == "MONT_CONST")
    {
        _k_dat = {
            "MONT_CONST",
            2, 
            0, 
            2, 
            {
                {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
            } 
        };
    }
    else if(program.operation_type == "MOD_INV_CONST_P")
    {
        _k_dat = {
            "MOD_INV_CONST_P",
            1, 
            0, 
            1, 
            {
                {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
            } 
        };
    }

}

void Compiler::compile()
{
    clear();
    get_k_dat(_program);
    _task_split_(_program);
    _memory_allocation_(_program);
    _gen_fpga_inst_(_program);
    check_mem(_program);
    _inst_reshape_(_program);
    get_executor();
}

std::string Compiler::to_string(uint128_t x)
{
    if (x == 0) return "0";
    std::string s = "";
    while (x > 0) {
        s += char(x % 10 + '0');
        x /= 10;
    }
    reverse(s.begin(), s.end());
    return s;
}

void Compiler::data_inverse(uint8_t* data,uint32_t len)
{
    uint32_t i = 0;
    uint8_t tmp;

    for(i=0;i<len/2;i++)
    {
        tmp = data[len-1-i];
        data[len-1-i] = data[i];
        data[i] = tmp;
    }
}

void Compiler::get_executor()
{
    uint8_t bytes[16];
    std::vector<uint8_t> inst_fpga_bytes;
    for(__uint128_t &i_dat:_generator_fpga.inst)
    {
        memcpy(bytes, &i_dat, sizeof(i_dat));
        data_inverse(bytes,16);
        for(uint32_t i = 0;i<16;i++)
        {
            inst_fpga_bytes.push_back(bytes[i]);
        }
        
    }
    executor.inst= inst_byte;
    executor.inst_fpga = inst_fpga_bytes;
    executor.in_para_address = memory_allocation.in_para_ddr_address_total;
    executor.inst_address = memory_allocation.inst_ddr_address_total;
    executor.out_address = memory_allocation.out_ddr_address_total;
    executor.out_length = memory_allocation.out_ddr_length_total;
}

void Compiler::__task_split_vector__(struct Program program)
{
    float x=(float)(program.vec_size)/(float)MAX_ON_CHIP_VECTOR;
    uint32_t task_num = std::ceil(x);
    uint32_t task_left = program.vec_size;
    std::vector<std::vector<uint32_t>> _task_spilit(num_of_chip,std::vector<uint32_t>());
    uint32_t chip_sel = 0;
    uint32_t task = 0;
    for(uint32_t i = 0;i<task_num;i++)
    {
        task = (task_left <= MAX_ON_CHIP_VECTOR) ? task_left : MAX_ON_CHIP_VECTOR;
        _task_spilit[chip_sel].push_back(task);
        task_left -=task;
        chip_sel = (chip_sel + 1) % num_of_chip;
    }
    task_split = _task_spilit;
}
void Compiler::_task_split_(struct Program program)
{
    std::string type = program.type;
    if(type == "vector")
    {
        __task_split_vector__(program);
    }
}

void Compiler::_memory_allocation_(struct Program program)
{
    std::string type = program.type;
    if(type == "vector")
    {
        __memory_allocation_vector_out__(program);
        __gen_asic_inst__(program);
        __memory_allocation_vector_inst__(program);
        __memory_allocation_vector_in_para__(program);
        uint32_t i_of_op = 0;
        uint32_t op_totol_num = _k_dat.data_in.size();
        while(1)
        {
            if(i_of_op == op_totol_num)
            {
                break;
            }
            if(__memory_allocation_vector_in_data_i__(program,i_of_op)==false)
            {
                break;
            }
            else{
                i_of_op += 1;
            }
        }
    }
}

void Compiler::__memory_allocation_vector_out__(struct Program program)
{
    std::vector<std::vector<std::vector<out_ddr_detail_t>>> m;
    uint32_t _p_bitcount = program.p_bitcount;
    uint32_t task_num = 0;
    uint32_t ddr_length_total = 0;
    uint32_t ddr_length = 0;
    uint32_t ddr_address_total= ddr_address;

    memory_allocation.out_detail.clear();
    memory_allocation.inst_detail.clear();
    memory_allocation.in_dat_ddr_mem_alloc.clear();

    for (uint32_t chip = 0; chip < task_split.size(); chip++) {
        std::vector<std::vector<out_ddr_detail_t>> first_vector;
        for (uint32_t first = 0; first < task_split[chip].size(); first++) {
            std::vector<out_ddr_detail_t> inner_vector(std::ceil(float(task_split[chip][first]) / float(NUMBER_OF_PE)));
            first_vector.push_back(inner_vector);
        }
        m.push_back(first_vector);
    }

    for (uint32_t chip = 0; chip < m.size(); chip++) {
        for (uint32_t first = 0; first < m[chip].size(); first++) {
            for (uint32_t i = 0; i < m[chip][first].size(); i++) {
                
                if(i ==std::ceil((float)(task_split[chip][first]) / (float)(NUMBER_OF_PE)) - 1){
                    task_num = (task_split[chip][first] % NUMBER_OF_PE != 0) ? (task_split[chip][first] % NUMBER_OF_PE) : NUMBER_OF_PE;
                }
                else{
                    task_num = NUMBER_OF_PE;
                }
                ddr_length = task_num * _p_bitcount / 8;
                ddr_length_total += ddr_length;
                m[chip][first][i].out_ddr_addr = ddr_address;
                m[chip][first][i].out_ddr_length = ddr_length;
                ddr_address += ddr_length;
            }
        }
    }
    memory_allocation.out_ddr_address_total = ddr_address_total;
    memory_allocation.out_ddr_length_total = ddr_length_total;
    memory_allocation.out_detail = m;
}

void Compiler::__memory_allocation_vector_inst__(struct Program program)
{
    uint64_t ddr_length = 0;
    uint64_t inst_ddr_address_total = ddr_address;
    uint64_t inst_ddr_length_total = 0;
    struct out_ddr_detail_t ddr_detail;
    
    std::vector<std::vector<struct out_ddr_detail_t>> memory_allocation_detail(task_split.size(),std::vector<struct out_ddr_detail_t>());

    for(uint8_t chip =0;chip < task_split.size();chip++)
    {
        for(uint32_t task_split_first=0;task_split_first<task_split[chip].size();task_split_first++)
        {
            ddr_length = (LOCAL_INST_BUFFER_WIDTH * inst[chip][task_split_first].size()) / 8;
            inst_ddr_length_total += ddr_length;
            ddr_detail.out_ddr_addr = ddr_address;
            ddr_detail.out_ddr_length = ddr_length;
            memory_allocation_detail[chip].push_back(ddr_detail);
            ddr_address += ddr_length;
        }
    }
    memory_allocation.inst_ddr_address_total = inst_ddr_address_total;
    memory_allocation.inst_ddr_length_total = inst_ddr_length_total;
    memory_allocation.inst_detail = memory_allocation_detail;
}

void Compiler::__memory_allocation_vector_in_para__(struct Program program)
{
    uint64_t ddr_length = 0;
    uint64_t in_para_ddr_address_total = ddr_address;
    uint64_t in_para_ddr_length_total = 0;

    int const_p_bit = _k_dat.const_p_bitcount;
    int const_e_bit = _k_dat.const_e_bitcount;
    int const_sram_data_width = _k_dat.const_sram_data_width;
    ddr_length = const_p_bit * program.p_bitcount;
    ddr_length += const_e_bit * program.e_bitcount;
    ddr_length += const_sram_data_width * LOCAL_BUFFER_WIDTH;
    ddr_length = ddr_length / 8;
    in_para_ddr_length_total +=  ddr_length;
    ddr_address += (int)ddr_length;
    memory_allocation.in_para_ddr_address_total = in_para_ddr_address_total;
    memory_allocation.in_para_ddr_length_total = in_para_ddr_length_total;
}


bool Compiler::__memory_allocation_vector_in_data_i__(struct Program program,uint32_t i_of_op)
{
    bool sta = false;
    uint32_t _p_bitcount = program.p_bitcount;
    uint32_t _e_bitcount = program.e_bitcount;
    std::string _operation_type =program.operation_type;
    uint64_t ddr_length = 0;
    float p_b = 0;
    float e_b = 0;

    struct out_ddr_detail_t ddr_detail;
    std::vector<std::vector<struct out_ddr_detail_t>> memory_allocation_detail(task_split.size(),std::vector<struct out_ddr_detail_t>());

    try{
        p_b = _k_dat.data_in[i_of_op].at("P_BITCOUNT");
        e_b = _k_dat.data_in[i_of_op].at("E_BITCOUNT");
    }catch (...) {sta = false;}

    uint64_t in_data_ddr_address_total = ddr_address;
    uint64_t in_data_ddr_length_total = 0;
    for (uint32_t task_split_first = 0; task_split_first < task_split[0].size(); task_split_first++) {
        for (uint32_t chip = 0; chip < task_split.size(); chip++) {
            if(task_split[chip].empty()){
                continue;
            }
            ddr_length = (uint32_t)(p_b * _p_bitcount * task_split[chip][task_split_first] );
            ddr_length += (uint32_t)(e_b * _e_bitcount * task_split[chip][task_split_first]);
            ddr_length = ddr_length / 8 ;
            in_data_ddr_length_total +=ddr_length;
            ddr_detail.out_ddr_addr = ddr_address;
            ddr_detail.out_ddr_length = ddr_length;
            memory_allocation_detail[chip].push_back(ddr_detail);
            ddr_address += int(ddr_length);
        }
    }
    in_data_mem_alloc_t in_data_mem_alloc;
    in_data_mem_alloc.in_data_ddr_address_total = in_data_ddr_address_total;
    in_data_mem_alloc.in_data_ddr_length_total = in_data_ddr_length_total;
    in_data_mem_alloc.in_data_detail = memory_allocation_detail;

    if(i_of_op == 0)
    {
        memory_allocation.in_dat_ddr_mem_alloc.push_back(in_data_mem_alloc);
    }
    else{
        memory_allocation.in_dat_ddr_mem_alloc.push_back(in_data_mem_alloc);
    }

    memory_allocation.last_ddr_address = ddr_address;
    sta = true;
    return sta;
}
void Compiler::__gen_asic_inst__(struct Program program)
{
    std::string type = program.type;
    if(type == "vector")
    {
        ___gen_asic_inst_vector___();
    }
}

void Compiler::___gen_asic_inst_vector___()
{
    std::vector<std::vector<std::vector<uint64_t>>> _inst;
    struct generator_inst_t _g_inst;
    for (uint32_t chip = 0; chip < task_split.size(); ++chip) {
        std::vector<std::vector<uint64_t>> chip_inst;
        for (uint32_t i = 0; i < task_split[chip].size(); ++i) {
            std::vector<uint64_t> task_inst;
            chip_inst.push_back(task_inst);
        }
        _inst.push_back(chip_inst);
    }

    std::vector<std::vector<std::vector<uint32_t>>> _inst_split;
    for (uint32_t chip = 0; chip < task_split.size(); ++chip) {
        std::vector<std::vector<uint32_t>> chip_inst;
        for (uint32_t i = 0; i < task_split[chip].size(); ++i) {
            std::vector<uint32_t> task_inst;
            chip_inst.push_back(task_inst);
        }
        _inst_split.push_back(chip_inst);
    }
    for (uint32_t chip = 0; chip < task_split.size(); chip++) 
        for (uint32_t task_split_first = 0; task_split_first < task_split[chip].size(); task_split_first++) {
        {
            _g_inst = _generator_asic.gen_inst(_program,task_split[chip][task_split_first],memory_allocation.out_detail[chip][task_split_first]);
            _inst[chip][task_split_first] = _g_inst.inst;
            _inst_split[chip][task_split_first] = _g_inst.inst_length;
        }
    }
    inst = _inst;
    inst_split = _inst_split;
}

void Compiler::_gen_fpga_inst_(struct Program program)
{
    std::string type = program.type;
    if(type == "vector")
    {
        _generator_fpga.gen_inst(program,task_split,memory_allocation,inst,inst_split);
    }
}

void Compiler::check_mem(struct Program program)
{
    std::string type = program.type;
    std::stringstream ss;
    uint64_t ddr_depth = (uint64_t)2*1024*1024*1024;
    if(memory_allocation.last_ddr_address >= (uint64_t)ddr_depth)
    {
        ss << "memory allocation address >= 1024*1024*1024*2!";
        throw std::runtime_error(ss.str());
    }

    if(_generator_fpga.inst.size() > GLOBAL_INST_BUFFER_DEPTH)
    {
        ss << "inst fpga length > GLOBAL_INST_BUFFER_DEPTH!";
        throw std::runtime_error(ss.str());
    }
}

void Compiler::_inst_reshape_(struct Program program)
{
    std::string type = program.type;
    uint32_t length_of_inst = LOCAL_INST_BUFFER_WIDTH;
    uint32_t bit_of_bit = 8;
    if(type == "vector")
    {
        for(uint8_t chip=0;chip<inst.size();chip++)
        {
            for(uint32_t inst_split_first=0;inst_split_first<inst[chip].size();inst_split_first++)
            {
                for(uint32_t inst_split_second = 0;inst_split_second<inst[chip][inst_split_first].size();inst_split_second++)
                {
                    for(uint32_t split=0;split<(length_of_inst/bit_of_bit);split++)
                    {
                        inst_byte.push_back(get_bit_of_data(inst[chip][inst_split_first][inst_split_second],split*bit_of_bit+bit_of_bit-1,split*bit_of_bit));
                    }
                }
            }
        }
    }
}

generator_mod_mul::generator_mod_mul()
{
    _k_dat = {
        "MOD_MUL",
        1, 
        0, 
        2, 
        {
            {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
            {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}}
        } 
    };
}

void generator_mod_mul::clear()
{
    inst.clear();
    task_split.clear();
    inst_length.clear();
    inst_c_address = DATA_OUT_TO_OUT_CTRL;
    inst_l_address = 0;
    task_split_n = 0;
    load_a_address = 0;
    load_b_address = 0;
    inst_length_last = 0;
}

void generator_mod_mul::_inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;
    float p_bitcount_k = 0;
    float e_bitcount_k = 0;

    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
    // L: param
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,param,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: p
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,p,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: n_prime
    inst_l_length = 1;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,n_prime,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L : rsquare
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,r_square,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;  
    p_bitcount_k =  _k_dat.data_in[0].at("P_BITCOUNT");
    e_bitcount_k =  _k_dat.data_in[0].at("E_BITCOUNT");
    load_a_address = inst_l_address;
    load_b_address = inst_l_address + task_split_n*(p_bitcount_k*p_bitcount/LOCAL_BUFFER_WIDTH + e_bitcount_k*e_bitcount/LOCAL_BUFFER_WIDTH );
}

void generator_mod_mul::_inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length)
{
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;
    uint64_t inst_temp = 0;
    // C: IDLE -> LOAD_PARA
    inst_temp = gen_inst_c(IDLE,CAL,LOAD_PARA,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: LOAD_PARA -> ELE_MOD_MUL
    inst_temp = gen_inst_c(LOAD_PARA,CAL,ELE_MOD_MUL,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
 
    // C: ELE_MOD_MUL and WAIT
    inst_temp = gen_inst_c(ELE_MOD_MUL,WAIT,ELE_MOD_MUL,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // L : a
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = actual_pe;
    inst_temp = gen_inst_l(load_a_address,inst_l_length,pe_0,a,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    load_a_address +=inst_l_length*inst_l_times;

    // L : b
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = actual_pe;
    inst_temp = gen_inst_l(load_b_address,inst_l_length,pe_0,b,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    load_b_address +=inst_l_length*inst_l_times;

    // I
    inst_temp = gen_inst_i(ddr_address,ddr_length);
    inst.push_back(inst_temp);

    // inst split
    inst_length.push_back(inst.size()-inst_length_last);
    inst_length_last = inst.size();

    // C : ELE_MOD_MUL -> VEC_OUTPUT_RESULTS
    inst_temp = gen_inst_c(ELE_MOD_MUL,CAL,VEC_OUTPUT_RESULTS,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C : VEC_OUTPUT_RESULTS -> IDLE
    inst_temp = gen_inst_c(VEC_OUTPUT_RESULTS,CAL,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
}

void generator_mod_mul::_inst_gen_end_(uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: IDLE and WAIT
    actual_pe = 0;
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    inst_length.push_back(inst.size()-inst_length_last);
}

struct generator_inst_t generator_mod_mul::gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<struct out_ddr_detail_t> mem_alloc)
{
    uint32_t _task_split = task_split;
    uint64_t ddr_address = 0;
    uint64_t ddr_length = 0;
    uint8_t actual_pe = 0;
    struct generator_inst_t _inst_tmp;
    this->clear();
    task_split_n = task_split;
    actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;
    _inst_gen_start_(p_bitcount,e_bitcount,actual_pe);
    uint32_t number_of_outs = std::ceil((float)_task_split/(float)NUMBER_OF_PE);
    for(uint8_t t = 0;t < number_of_outs;t++)
    {
        ddr_address = mem_alloc[t].out_ddr_addr;
        ddr_length = mem_alloc[t].out_ddr_length;
        if(t==number_of_outs-1)
        {
            actual_pe = ((_task_split%NUMBER_OF_PE)==0)?NUMBER_OF_PE:(_task_split%NUMBER_OF_PE);
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
        else
        {
            actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
    }
    _inst_gen_end_(actual_pe);
    check_inst_sram_depth(inst);
    _inst_tmp.inst = inst;
    _inst_tmp.inst_length = inst_length;
    return _inst_tmp;
}

generator_mod_mul_const::generator_mod_mul_const()
{
    _k_dat = {
        "MOD_MUL_CONST",
        3, 
        0, 
        2, 
        {
            {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
        } 
    };
}

void generator_mod_mul_const::clear()
{
    inst.clear();
    task_split.clear();
    inst_length.clear();
    inst_c_address = DATA_OUT_TO_OUT_CTRL;
    inst_l_address = 0;
    task_split_n = 0;
    load_a_address = 0;
    load_b_address = 0;
    inst_length_last = 0;
}

void generator_mod_mul_const::_inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;

    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
    // L: param
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,param,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: p
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,p,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: n_prime
    inst_l_length = 1;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,n_prime,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L : rsquare
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,r_square,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;  
    // L : b
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = 1;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,b,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length*inst_l_times;
}

void generator_mod_mul_const::_inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length)
{
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;
    uint64_t inst_temp = 0;
    // C: IDLE -> LOAD_PARA
    inst_temp = gen_inst_c(IDLE,CAL,LOAD_PARA,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: LOAD_PARA -> ELE_MOD_MUL
    inst_temp = gen_inst_c(LOAD_PARA,CAL,ELE_MOD_MUL,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
 
    // C: ELE_MOD_MUL and WAIT
    inst_temp = gen_inst_c(ELE_MOD_MUL,WAIT,ELE_MOD_MUL,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // L : a
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = actual_pe;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,pe_0,a,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length*inst_l_times;

    // I
    inst_temp = gen_inst_i(ddr_address,ddr_length);
    inst.push_back(inst_temp);

    // inst split
    inst_length.push_back(inst.size()-inst_length_last);
    inst_length_last = inst.size();
    // C : ELE_MOD_MUL -> VEC_OUTPUT_RESULTS
    inst_temp = gen_inst_c(ELE_MOD_MUL,CAL,VEC_OUTPUT_RESULTS,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C : VEC_OUTPUT_RESULTS -> IDLE
    inst_temp = gen_inst_c(VEC_OUTPUT_RESULTS,CAL,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
}

void generator_mod_mul_const::_inst_gen_end_(uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: IDLE and WAIT
    actual_pe = 0;
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    inst_length.push_back(inst.size()-inst_length_last);
}

struct generator_inst_t generator_mod_mul_const::gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<struct out_ddr_detail_t> mem_alloc)
{
    uint32_t _task_split = task_split;
    uint64_t ddr_address = 0;
    uint64_t ddr_length = 0;
    uint8_t actual_pe = 0;
    struct generator_inst_t _inst_tmp;
    this->clear();
    task_split_n = task_split;
    actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;
    _inst_gen_start_(p_bitcount,e_bitcount,actual_pe);
    uint32_t number_of_outs = std::ceil((float)_task_split/(float)NUMBER_OF_PE);
    for(uint8_t t = 0;t < number_of_outs;t++)
    {
        ddr_address = mem_alloc[t].out_ddr_addr;
        ddr_length = mem_alloc[t].out_ddr_length;
        if(t==number_of_outs-1)
        {
            actual_pe = ((_task_split%NUMBER_OF_PE)==0)?NUMBER_OF_PE:(_task_split%NUMBER_OF_PE);
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
        else
        {
            actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
    }
    _inst_gen_end_(actual_pe);
    check_inst_sram_depth(inst);
    _inst_tmp.inst = inst;
    _inst_tmp.inst_length = inst_length;
    return _inst_tmp;
}

generator_mod_exp::generator_mod_exp()
{
    _k_dat = {
        "MOD_EXP",
        2, 
        0, 
        2, 
        {
            {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
            {{"P_BITCOUNT", 0}, {"E_BITCOUNT", 1}}
        } 
    };
}

void generator_mod_exp::clear()
{
    inst.clear();
    task_split.clear();
    inst_length.clear();
    inst_c_address = DATA_OUT_TO_OUT_CTRL;
    inst_l_address = 0;
    task_split_n = 0;
    load_a_address = 0;
    load_b_address = 0;
    inst_length_last = 0;
}

void generator_mod_exp::_inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;
    float p_bitcount_k = 0;
    float e_bitcount_k = 0;

    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
    // L: param
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,param,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: p
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,p,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: n_prime
    inst_l_length = 1;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,n_prime,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L : rsquare
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,r_square,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;  
    p_bitcount_k =  _k_dat.data_in[0].at("P_BITCOUNT");
    e_bitcount_k =  _k_dat.data_in[0].at("E_BITCOUNT");
    load_a_address = inst_l_address;
    load_b_address = inst_l_address + task_split_n*(p_bitcount_k*p_bitcount/LOCAL_BUFFER_WIDTH + e_bitcount_k*e_bitcount/LOCAL_BUFFER_WIDTH );
}

void generator_mod_exp::_inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length)
{
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;
    uint64_t inst_temp = 0;
    // C: IDLE -> LOAD_PARA
    inst_temp = gen_inst_c(IDLE,CAL,LOAD_PARA,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: LOAD_PARA -> ELE_MOD_EXP
    inst_temp = gen_inst_c(LOAD_PARA,CAL,ELE_MOD_EXP,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
 
    // C: ELE_MOD_EXP and WAIT
    inst_temp = gen_inst_c(ELE_MOD_EXP,WAIT,ELE_MOD_EXP,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // L : a
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = actual_pe;
    inst_temp = gen_inst_l(load_a_address,inst_l_length,pe_0,a,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    load_a_address +=inst_l_length*inst_l_times;

    // L : b
    inst_l_length = e_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = actual_pe;
    inst_temp = gen_inst_l(load_b_address,inst_l_length,pe_0,b,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    load_b_address +=inst_l_length*inst_l_times;

    // I
    inst_temp = gen_inst_i(ddr_address,ddr_length);
    inst.push_back(inst_temp);

    // inst split
    inst_length.push_back(inst.size()-inst_length_last);
    inst_length_last = inst.size();
    // C : ELE_MOD_EXP -> VEC_OUTPUT_RESULTS
    inst_temp = gen_inst_c(ELE_MOD_EXP,CAL,VEC_OUTPUT_RESULTS,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C : VEC_OUTPUT_RESULTS -> IDLE
    inst_temp = gen_inst_c(VEC_OUTPUT_RESULTS,CAL,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
}

void generator_mod_exp::_inst_gen_end_(uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: IDLE and WAIT
    actual_pe = 0;
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    inst_length.push_back(inst.size()-inst_length_last);
}

struct generator_inst_t generator_mod_exp::gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<struct out_ddr_detail_t> mem_alloc)
{
    uint32_t _task_split = task_split;
    uint64_t ddr_address = 0;
    uint64_t ddr_length = 0;
    uint8_t actual_pe = 0;
    struct generator_inst_t _inst_tmp;
    this->clear();
    task_split_n = task_split;
    actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;
    _inst_gen_start_(p_bitcount,e_bitcount,actual_pe);
    uint32_t number_of_outs = std::ceil((float)_task_split/(float)NUMBER_OF_PE);
    for(uint8_t t = 0;t < number_of_outs;t++)
    {
        ddr_address = mem_alloc[t].out_ddr_addr;
        ddr_length = mem_alloc[t].out_ddr_length;
        if(t==number_of_outs-1)
        {
            actual_pe = ((_task_split%NUMBER_OF_PE)==0)?NUMBER_OF_PE:(_task_split%NUMBER_OF_PE);
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
        else
        {
            actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
    }
    _inst_gen_end_(actual_pe);
    check_inst_sram_depth(inst);
    _inst_tmp.inst = inst;
    _inst_tmp.inst_length = inst_length;
    return _inst_tmp;
}

generator_mod_inv_const_p::generator_mod_inv_const_p()
{
    _k_dat = {
        "MOD_INV_CONST_P",
        1, 
        0, 
        1, 
        {
            {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
        } 
    };
}

void generator_mod_inv_const_p::clear()
{
    inst.clear();
    task_split.clear();
    inst_length.clear();
    inst_c_address = DATA_OUT_TO_OUT_CTRL;
    inst_l_address = 0;
    task_split_n = 0;
    load_a_address = 0;
    load_b_address = 0;
    inst_length_last = 0;
}

void generator_mod_inv_const_p::_inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;

    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
    // L: param
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,param,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: p
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,p,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
}

void generator_mod_inv_const_p::_inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length)
{
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;
    uint64_t inst_temp = 0;
    // C: IDLE -> LOAD_PARA
    inst_temp = gen_inst_c(IDLE,CAL,LOAD_PARA,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: LOAD_PARA -> ELE_MOD_INV_P
    inst_temp = gen_inst_c(LOAD_PARA,CAL,ELE_MOD_INV_P,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
 
    // C: ELE_MOD_INV_P and WAIT
    inst_temp = gen_inst_c(ELE_MOD_INV_P,WAIT,ELE_MOD_INV_P,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // L : a
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = actual_pe;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,pe_0,a,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length*inst_l_times;

    // I
    inst_temp = gen_inst_i(ddr_address,ddr_length);
    inst.push_back(inst_temp);

    // inst split
    inst_length.push_back(inst.size()-inst_length_last);
    inst_length_last = inst.size();
    // C : ELE_MOD_INV_P -> VEC_OUTPUT_RESULTS
    inst_temp = gen_inst_c(ELE_MOD_INV_P,CAL,VEC_OUTPUT_RESULTS,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C : VEC_OUTPUT_RESULTS -> IDLE
    inst_temp = gen_inst_c(VEC_OUTPUT_RESULTS,CAL,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
}

void generator_mod_inv_const_p::_inst_gen_end_(uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: IDLE and WAIT
    actual_pe = 0;
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    inst_length.push_back(inst.size()-inst_length_last);
}

struct generator_inst_t generator_mod_inv_const_p::gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<struct out_ddr_detail_t> mem_alloc)
{
    uint32_t _task_split = task_split;
    uint64_t ddr_address = 0;
    uint64_t ddr_length = 0;
    uint8_t actual_pe = 0;
    struct generator_inst_t _inst_tmp;
    this->clear();
    task_split_n = task_split;
    actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;

    _inst_gen_start_(p_bitcount,e_bitcount,actual_pe);
    uint32_t number_of_outs = std::ceil((float)_task_split/(float)NUMBER_OF_PE);

    for(uint8_t t = 0;t < number_of_outs;t++)
    {
        ddr_address = mem_alloc[t].out_ddr_addr;
        ddr_length = mem_alloc[t].out_ddr_length;

        if(t==number_of_outs-1)
        {
            actual_pe = ((_task_split%NUMBER_OF_PE)==0)?NUMBER_OF_PE:(_task_split%NUMBER_OF_PE);
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
        else
        {
            actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
    }
    _inst_gen_end_(actual_pe);
    check_inst_sram_depth(inst);
    _inst_tmp.inst = inst;
    _inst_tmp.inst_length = inst_length;
    return _inst_tmp;
}

generator_paillier_encrypt::generator_paillier_encrypt()
{
    _k_dat = {
        "PAILLIER_ENC",
        5, 
        0, 
        2,
        {
            {{"P_BITCOUNT", 0}, {"E_BITCOUNT", 1}},
            {{"P_BITCOUNT", 0.5}, {"E_BITCOUNT", 0}}
        } 
    };
}

void generator_paillier_encrypt::clear()
{
    inst.clear();
    task_split.clear();
    inst_length.clear();
    inst_c_address = DATA_OUT_TO_OUT_CTRL;
    inst_l_address = 0;
    task_split_n = 0;
    load_a_address = 0;
    load_b_address = 0;
    inst_length_last = 0;
}

void generator_paillier_encrypt::_inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;
    float p_bitcount_k = 0;
    float e_bitcount_k = 0;

    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
    // L: param
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,param,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: p
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,p,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: n_prime
    inst_l_length = 1;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,n_prime,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L : rsquare
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,r_square,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;  

    // L : r_mont
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH; 
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,r_mont,inst_l_times,NOCHANGE,actual_pe);

    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    address_n = inst_l_address;
    address_g = address_n + inst_l_length;
    inst_l_address = address_g + inst_l_length; 


    p_bitcount_k =  _k_dat.data_in[0].at("P_BITCOUNT");
    e_bitcount_k =  _k_dat.data_in[0].at("E_BITCOUNT");
    load_a_address = inst_l_address;
    load_b_address = inst_l_address + (uint32_t)(task_split_n*(p_bitcount_k*p_bitcount/LOCAL_BUFFER_WIDTH + e_bitcount_k*e_bitcount/LOCAL_BUFFER_WIDTH ));
}

void generator_paillier_encrypt::_inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length)
{
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;
    uint64_t inst_temp = 0;
    // C: IDLE -> LOAD_PARA
    inst_temp = gen_inst_c(IDLE,CAL,LOAD_PARA,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: LOAD_PARA -> ELE_MOD_EXP_INV_EXP
    inst_temp = gen_inst_c(LOAD_PARA,CAL,ELE_MOD_EXP_INV_EXP,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
 
    // C: ELE_MOD_EXP_INV_EXP and WAIT
    inst_temp = gen_inst_c(ELE_MOD_EXP_INV_EXP,WAIT,ELE_MOD_EXP_INV_EXP,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // L : g
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = 1;
    inst_temp = gen_inst_l(address_g,inst_l_length,all,a,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length*inst_l_times;

    // L : plaintext
    inst_l_length = e_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = actual_pe;
    inst_temp = gen_inst_l(load_a_address,inst_l_length,pe_0,b,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    load_a_address +=inst_l_length*inst_l_times;

    // C: ELE_MOD_EXP_INV_EXP -> ELE_MOD_EXP_INV_MUL
    inst_temp = gen_inst_c(ELE_MOD_EXP_INV_EXP,CAL,ELE_MOD_EXP_INV_MUL,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
    // C: ELE_MOD_EXP_INV_MUL -> ELE_MOD_EXP_INV_EXP
    inst_temp = gen_inst_c(ELE_MOD_EXP_INV_MUL,CAL,ELE_MOD_EXP_INV_EXP,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
    // C: ELE_MOD_EXP_INV_EXP and WAIT
    inst_temp = gen_inst_c(ELE_MOD_EXP_INV_EXP,WAIT,ELE_MOD_EXP_INV_EXP,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // L : r
    inst_l_length = (p_bitcount/ 2) / LOCAL_BUFFER_WIDTH;
    inst_l_times = actual_pe;
    inst_temp = gen_inst_l(load_b_address,inst_l_length,pe_0,a,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    load_b_address +=inst_l_length*inst_l_times;

    // L : n
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = 1;
    inst_temp = gen_inst_l(address_n,inst_l_length,all,b,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);

    // C: ELE_MOD_EXP_INV_EXP -> ELE_MOD_EXP_INV_MUL
    inst_temp = gen_inst_c(ELE_MOD_EXP_INV_EXP,CAL,ELE_MOD_EXP_INV_MUL,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: ELE_MOD_EXP_INV_MUL -> ELE_MOD_EXP_INV_COM
    inst_temp = gen_inst_c(ELE_MOD_EXP_INV_MUL,CAL,ELE_MOD_EXP_INV_COM,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // I
    inst_temp = gen_inst_i(ddr_address,ddr_length);
    inst.push_back(inst_temp);

    // inst split
    inst_length.push_back(inst.size()-inst_length_last);
    inst_length_last = inst.size();
    // C : ELE_MOD_EXP_INV_COM -> VEC_OUTPUT_RESULTS
    inst_temp = gen_inst_c(ELE_MOD_EXP_INV_COM,CAL,VEC_OUTPUT_RESULTS,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C : VEC_OUTPUT_RESULTS -> IDLE
    inst_temp = gen_inst_c(VEC_OUTPUT_RESULTS,CAL,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
}

void generator_paillier_encrypt::_inst_gen_end_(uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: IDLE and WAIT
    actual_pe = 0;
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    inst_length.push_back(inst.size()-inst_length_last);
}

struct generator_inst_t generator_paillier_encrypt::gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<struct out_ddr_detail_t> mem_alloc)
{
    uint32_t _task_split = task_split;
    uint64_t ddr_address = 0;
    uint64_t ddr_length = 0;
    uint8_t actual_pe = 0;
    struct generator_inst_t _inst_tmp;
    this->clear();
    task_split_n = task_split;
    actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;

    _inst_gen_start_(p_bitcount,e_bitcount,actual_pe);
    uint32_t number_of_outs = std::ceil((float)_task_split/(float)NUMBER_OF_PE);
    for(uint8_t t = 0;t < number_of_outs;t++)
    {
        ddr_address = mem_alloc[t].out_ddr_addr;
        ddr_length = mem_alloc[t].out_ddr_length;

        if(t==number_of_outs-1)
        {
            actual_pe = ((_task_split%NUMBER_OF_PE)==0)?NUMBER_OF_PE:(_task_split%NUMBER_OF_PE);
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
        else
        {
            actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
    }
    _inst_gen_end_(actual_pe);
    check_inst_sram_depth(inst);
    _inst_tmp.inst = inst;
    _inst_tmp.inst_length = inst_length;
    return _inst_tmp;
}

generator_mod_exp_const_e::generator_mod_exp_const_e()
{
    _k_dat = {
        "MOD_EXP_CONST_E",
        2, 
        1, 
        2, 
        {
            {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
        } 
    };
}

void generator_mod_exp_const_e::clear()
{
    inst.clear();
    task_split.clear();
    inst_length.clear();
    inst_c_address = DATA_OUT_TO_OUT_CTRL;
    inst_l_address = 0;
    task_split_n = 0;
    load_a_address = 0;
    load_b_address = 0;
    inst_length_last = 0;
}

void generator_mod_exp_const_e::_inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;

    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
    // L: param
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,param,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: p
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,p,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: n_prime
    inst_l_length = 1;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,n_prime,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L : rsquare
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,r_square,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;  
    // L : b
    inst_l_length = e_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = 1;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,b,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length*inst_l_times;
}

void generator_mod_exp_const_e::_inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length)
{
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;
    uint64_t inst_temp = 0;
    // C: IDLE -> LOAD_PARA
    inst_temp = gen_inst_c(IDLE,CAL,LOAD_PARA,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: LOAD_PARA -> ELE_MOD_EXP
    inst_temp = gen_inst_c(LOAD_PARA,CAL,ELE_MOD_EXP,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
 
    // C: ELE_MOD_EXP and WAIT
    inst_temp = gen_inst_c(ELE_MOD_EXP,WAIT,ELE_MOD_EXP,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // L : a
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = actual_pe;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,pe_0,a,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length*inst_l_times;

    // I
    inst_temp = gen_inst_i(ddr_address,ddr_length);
    inst.push_back(inst_temp);

    // inst split
    inst_length.push_back(inst.size()-inst_length_last);
    inst_length_last = inst.size();
    // C : ELE_MOD_EXP -> VEC_OUTPUT_RESULTS
    inst_temp = gen_inst_c(ELE_MOD_EXP,CAL,VEC_OUTPUT_RESULTS,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C : VEC_OUTPUT_RESULTS -> IDLE
    inst_temp = gen_inst_c(VEC_OUTPUT_RESULTS,CAL,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
}

void generator_mod_exp_const_e::_inst_gen_end_(uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: IDLE and WAIT
    actual_pe = 0;
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    inst_length.push_back(inst.size()-inst_length_last);
}

struct generator_inst_t generator_mod_exp_const_e::gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<struct out_ddr_detail_t> mem_alloc)
{
    uint32_t _task_split = task_split;
    uint64_t ddr_address = 0;
    uint64_t ddr_length = 0;
    uint8_t actual_pe = 0;
    struct generator_inst_t _inst_tmp;
    this->clear();
    task_split_n = task_split;
    actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;
    _inst_gen_start_(p_bitcount,e_bitcount,actual_pe);
    uint32_t number_of_outs = std::ceil((float)_task_split/(float)NUMBER_OF_PE);
    for(uint8_t t = 0;t < number_of_outs;t++)
    {
        ddr_address = mem_alloc[t].out_ddr_addr;
        ddr_length = mem_alloc[t].out_ddr_length;

        if(t==number_of_outs-1)
        {
            actual_pe = ((_task_split%NUMBER_OF_PE)==0)?NUMBER_OF_PE:(_task_split%NUMBER_OF_PE);
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
        else
        {
            actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
    }
    _inst_gen_end_(actual_pe);
    check_inst_sram_depth(inst);
    _inst_tmp.inst = inst;
    _inst_tmp.inst_length = inst_length;
    return _inst_tmp;
}

generator_mod_exp_const_a::generator_mod_exp_const_a()
{
    _k_dat = {
        "MOD_EXP_CONST_A",
        3, 
        0, 
        2, 
        {
            {{"P_BITCOUNT", 0}, {"E_BITCOUNT", 1}},
        } 
    };
}

void generator_mod_exp_const_a::clear()
{
    inst.clear();
    task_split.clear();
    inst_length.clear();
    inst_c_address = DATA_OUT_TO_OUT_CTRL;
    inst_l_address = 0;
    task_split_n = 0;
    load_a_address = 0;
    load_b_address = 0;
    inst_length_last = 0;
}

void generator_mod_exp_const_a::_inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;

    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
    // L: param
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,param,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;

    // L: p
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,p,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: n_prime
    inst_l_length = 1;

    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,n_prime,inst_l_times,NOCHANGE,actual_pe);

    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L : rsquare
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;

    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,r_square,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;  

    // L : a
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = 1;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,a,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length*inst_l_times;
}

void generator_mod_exp_const_a::_inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length)
{
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;
    uint64_t inst_temp = 0;
    // C: IDLE -> LOAD_PARA
    inst_temp = gen_inst_c(IDLE,CAL,LOAD_PARA,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: LOAD_PARA -> ELE_MOD_EXP
    inst_temp = gen_inst_c(LOAD_PARA,CAL,ELE_MOD_EXP,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
 
    // C: ELE_MOD_EXP and WAIT
    inst_temp = gen_inst_c(ELE_MOD_EXP,WAIT,ELE_MOD_EXP,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // L : b
    inst_l_length = e_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = actual_pe;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,pe_0,b,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length*inst_l_times;

    // I
    inst_temp = gen_inst_i(ddr_address,ddr_length);
    inst.push_back(inst_temp);

    // inst split
    inst_length.push_back(inst.size()-inst_length_last);
    inst_length_last = inst.size();
    // C : ELE_MOD_EXP -> VEC_OUTPUT_RESULTS
    inst_temp = gen_inst_c(ELE_MOD_EXP,CAL,VEC_OUTPUT_RESULTS,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C : VEC_OUTPUT_RESULTS -> IDLE
    inst_temp = gen_inst_c(VEC_OUTPUT_RESULTS,CAL,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
}

void generator_mod_exp_const_a::_inst_gen_end_(uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: IDLE and WAIT
    actual_pe = 0;
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    inst_length.push_back(inst.size()-inst_length_last);
}

struct generator_inst_t generator_mod_exp_const_a::gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<struct out_ddr_detail_t> mem_alloc)
{
    uint32_t _task_split = task_split;
    uint64_t ddr_address = 0;
    uint64_t ddr_length = 0;
    uint8_t actual_pe = 0;
    struct generator_inst_t _inst_tmp;
    this->clear();
    task_split_n = task_split;
    actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;
    _inst_gen_start_(p_bitcount,e_bitcount,actual_pe);
    uint32_t number_of_outs = std::ceil((float)_task_split/(float)NUMBER_OF_PE);

    for(uint8_t t = 0;t < number_of_outs;t++)
    {
        ddr_address = mem_alloc[t].out_ddr_addr;
        ddr_length = mem_alloc[t].out_ddr_length;
        if(t==number_of_outs-1)
        {
            actual_pe = ((_task_split%NUMBER_OF_PE)==0)?NUMBER_OF_PE:(_task_split%NUMBER_OF_PE);

            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
        else
        {
            actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
    }
    _inst_gen_end_(actual_pe);
    check_inst_sram_depth(inst);
    _inst_tmp.inst = inst;
    _inst_tmp.inst_length = inst_length;
    return _inst_tmp;
}

generator_mod_add::generator_mod_add()
{
    _k_dat = {
        "MOD_ADD",
        1, 
        0, 
        1, 
        {
            {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
            {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}}
        } 
    };
}

void generator_mod_add::clear()
{
    inst.clear();
    task_split.clear();
    inst_length.clear();
    inst_c_address = DATA_OUT_TO_OUT_CTRL;
    inst_l_address = 0;
    task_split_n = 0;
    load_a_address = 0;
    load_b_address = 0;
    inst_length_last = 0;
}

void generator_mod_add::_inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;
    float p_bitcount_k = 0;
    float e_bitcount_k = 0;

    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
    // L: param
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,param,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: p
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,p,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    p_bitcount_k =  _k_dat.data_in[0].at("P_BITCOUNT");
    e_bitcount_k =  _k_dat.data_in[0].at("E_BITCOUNT");
    load_a_address = inst_l_address;
    load_b_address = inst_l_address + task_split_n*(p_bitcount_k*p_bitcount/LOCAL_BUFFER_WIDTH + e_bitcount_k*e_bitcount/LOCAL_BUFFER_WIDTH );
}

void generator_mod_add::_inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length)
{
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;
    uint64_t inst_temp = 0;
    // C: IDLE -> LOAD_PARA
    inst_temp = gen_inst_c(IDLE,CAL,LOAD_PARA,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: LOAD_PARA -> ELE_MOD_INV
    inst_temp = gen_inst_c(LOAD_PARA,CAL,ELE_MOD_INV,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
 
    // C: ELE_MOD_INV and WAIT
    inst_temp = gen_inst_c(ELE_MOD_INV,WAIT,ELE_MOD_INV,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // L : a
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = actual_pe;
    inst_temp = gen_inst_l(load_a_address,inst_l_length,pe_0,a,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    load_a_address +=inst_l_length*inst_l_times;

    // L : b
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = actual_pe;
    inst_temp = gen_inst_l(load_b_address,inst_l_length,pe_0,b,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    load_b_address +=inst_l_length*inst_l_times;

    // I
    inst_temp = gen_inst_i(ddr_address,ddr_length);
    inst.push_back(inst_temp);

    // inst split
    inst_length.push_back(inst.size()-inst_length_last);
    inst_length_last = inst.size();
    // C : ELE_MOD_INV -> VEC_OUTPUT_RESULTS
    inst_temp = gen_inst_c(ELE_MOD_INV,CAL,VEC_OUTPUT_RESULTS,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C : VEC_OUTPUT_RESULTS -> IDLE
    inst_temp = gen_inst_c(VEC_OUTPUT_RESULTS,CAL,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
}

void generator_mod_add::_inst_gen_end_(uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: IDLE and WAIT
    actual_pe = 0;
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    inst_length.push_back(inst.size()-inst_length_last);
}

struct generator_inst_t generator_mod_add::gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<struct out_ddr_detail_t> mem_alloc)
{
    uint32_t _task_split = task_split;
    uint64_t ddr_address = 0;
    uint64_t ddr_length = 0;
    uint8_t actual_pe = 0;
    struct generator_inst_t _inst_tmp;
    this->clear();
    task_split_n = task_split;
    actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;

    _inst_gen_start_(p_bitcount,e_bitcount,actual_pe);
    uint32_t number_of_outs = std::ceil((float)_task_split/(float)NUMBER_OF_PE);

    for(uint8_t t = 0;t < number_of_outs;t++)
    {
        ddr_address = mem_alloc[t].out_ddr_addr;
        ddr_length = mem_alloc[t].out_ddr_length;

        if(t==number_of_outs-1)
        {
            actual_pe = ((_task_split%NUMBER_OF_PE)==0)?NUMBER_OF_PE:(_task_split%NUMBER_OF_PE);
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
        else
        {
            actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
    }
    _inst_gen_end_(actual_pe);
    check_inst_sram_depth(inst);
    _inst_tmp.inst = inst;
    _inst_tmp.inst_length = inst_length;
    return _inst_tmp;
}

void generator_mod_add_const::clear()
{
    inst.clear();
    task_split.clear();
    inst_length.clear();
    inst_c_address = DATA_OUT_TO_OUT_CTRL;
    inst_l_address = 0;
    task_split_n = 0;
    load_a_address = 0;
    load_b_address = 0;
    inst_length_last = 0;
}

generator_mod_add_const::generator_mod_add_const()
{
    _k_dat = {
        "MOD_ADD",
        2, 
        0, 
        1, 
        {
            {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
        } 
    };
}

void generator_mod_add_const::_inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;

    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
    // L: param
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,param,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;

    // L: p

    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,p,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: b
    inst_l_times = 1;
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,b,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
}

void generator_mod_add_const::_inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length)
{
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;
    uint64_t inst_temp = 0;
    // C: IDLE -> LOAD_PARA
    inst_temp = gen_inst_c(IDLE,CAL,LOAD_PARA,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: LOAD_PARA -> ELE_MOD_INV
    inst_temp = gen_inst_c(LOAD_PARA,CAL,ELE_MOD_INV,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
 
    // C: ELE_MOD_INV and WAIT
    inst_temp = gen_inst_c(ELE_MOD_INV,WAIT,ELE_MOD_INV,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // L : a
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = actual_pe;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,pe_0,a,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length*inst_l_times;

    // I
    inst_temp = gen_inst_i(ddr_address,ddr_length);
    inst.push_back(inst_temp);

    // inst split
    inst_length.push_back(inst.size()-inst_length_last);
    inst_length_last = inst.size();
    // C : ELE_MOD_INV -> VEC_OUTPUT_RESULTS
    inst_temp = gen_inst_c(ELE_MOD_INV,CAL,VEC_OUTPUT_RESULTS,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C : VEC_OUTPUT_RESULTS -> IDLE
    inst_temp = gen_inst_c(VEC_OUTPUT_RESULTS,CAL,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
}

void generator_mod_add_const::_inst_gen_end_(uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: IDLE and WAIT
    actual_pe = 0;
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    inst_length.push_back(inst.size()-inst_length_last);
}

struct generator_inst_t generator_mod_add_const::gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<struct out_ddr_detail_t> mem_alloc)
{
    uint32_t _task_split = task_split;
    uint64_t ddr_address = 0;
    uint64_t ddr_length = 0;
    uint8_t actual_pe = 0;
    struct generator_inst_t _inst_tmp;
    this->clear();
    task_split_n = task_split;
    actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;

    _inst_gen_start_(p_bitcount,e_bitcount,actual_pe);
    uint32_t number_of_outs = std::ceil((float)_task_split/(float)NUMBER_OF_PE);

    for(uint8_t t = 0;t < number_of_outs;t++)
    {
        ddr_address = mem_alloc[t].out_ddr_addr;
        ddr_length = mem_alloc[t].out_ddr_length;

        if(t==number_of_outs-1)
        {
            actual_pe = ((_task_split%NUMBER_OF_PE)==0)?NUMBER_OF_PE:(_task_split%NUMBER_OF_PE);

            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
        else
        {
            actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
    }
    _inst_gen_end_(actual_pe);
    check_inst_sram_depth(inst);
    _inst_tmp.inst = inst;
    _inst_tmp.inst_length = inst_length;
    return _inst_tmp;
}

generator_mont::generator_mont()
{
    _k_dat = {
        "MONT",
        1, 
        0, 
        2, 
        {
            {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
            {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}}
        } 
    };
}

void generator_mont::clear()
{
    inst.clear();
    task_split.clear();
    inst_length.clear();
    inst_c_address = DATA_OUT_TO_OUT_CTRL;
    inst_l_address = 0;
    task_split_n = 0;
    load_a_address = 0;
    load_b_address = 0;
    inst_length_last = 0;
}

void generator_mont::_inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;
    float p_bitcount_k = 0;
    float e_bitcount_k = 0;

    // C: IDLE and WAIT

    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
    // L: param
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,param,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: p
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,p,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: n_prime
    inst_l_length = 1;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,n_prime,inst_l_times,NOCHANGE,actual_pe);

    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;

    p_bitcount_k =  _k_dat.data_in[0].at("P_BITCOUNT");
    e_bitcount_k =  _k_dat.data_in[0].at("E_BITCOUNT");
    load_a_address = inst_l_address;
    load_b_address = inst_l_address + task_split_n*(p_bitcount_k*p_bitcount/LOCAL_BUFFER_WIDTH + e_bitcount_k*e_bitcount/LOCAL_BUFFER_WIDTH );
}

void generator_mont::_inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length)
{
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;
    uint64_t inst_temp = 0;
    // C: IDLE -> LOAD_PARA
    inst_temp = gen_inst_c(IDLE,CAL,LOAD_PARA,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: LOAD_PARA -> ELEMENT_RSQUARE
    inst_temp = gen_inst_c(LOAD_PARA,CAL,ELEMENT_RSQUARE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
 
    // C: ELEMENT_RSQUARE and WAIT
    inst_temp = gen_inst_c(ELEMENT_RSQUARE,WAIT,ELEMENT_RSQUARE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // L : a
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = actual_pe;
    inst_temp = gen_inst_l(load_a_address,inst_l_length,pe_0,a,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    load_a_address +=inst_l_length*inst_l_times;

    // L : b
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = actual_pe;
    inst_temp = gen_inst_l(load_b_address,inst_l_length,pe_0,r_square,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    load_b_address +=inst_l_length*inst_l_times;

    // I
    inst_temp = gen_inst_i(ddr_address,ddr_length);
    inst.push_back(inst_temp);

    // inst split
    inst_length.push_back(inst.size()-inst_length_last);
    inst_length_last = inst.size();
    // C : ELEMENT_RSQUARE -> VEC_OUTPUT_RESULTS
    inst_temp = gen_inst_c(ELEMENT_RSQUARE,CAL,VEC_OUTPUT_RESULTS,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C : VEC_OUTPUT_RESULTS -> IDLE
    inst_temp = gen_inst_c(VEC_OUTPUT_RESULTS,CAL,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
}

void generator_mont::_inst_gen_end_(uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: IDLE and WAIT
    actual_pe = 0;
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    inst_length.push_back(inst.size()-inst_length_last);
}

struct generator_inst_t generator_mont::gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<struct out_ddr_detail_t> mem_alloc)
{
    uint32_t _task_split = task_split;
    uint64_t ddr_address = 0;
    uint64_t ddr_length = 0;
    uint8_t actual_pe = 0;
    struct generator_inst_t _inst_tmp;
    this->clear();
    task_split_n = task_split;
    actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;

    _inst_gen_start_(p_bitcount,e_bitcount,actual_pe);
    uint32_t number_of_outs = std::ceil((float)_task_split/(float)NUMBER_OF_PE);

    for(uint8_t t = 0;t < number_of_outs;t++)
    {
        ddr_address = mem_alloc[t].out_ddr_addr;
        ddr_length = mem_alloc[t].out_ddr_length;

        if(t==number_of_outs-1)
        {
            actual_pe = ((_task_split%NUMBER_OF_PE)==0)?NUMBER_OF_PE:(_task_split%NUMBER_OF_PE);
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
        else
        {
            actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
    }
    _inst_gen_end_(actual_pe);
    check_inst_sram_depth(inst);
    _inst_tmp.inst = inst;
    _inst_tmp.inst_length = inst_length;
    return _inst_tmp;
}

generator_mont_const::generator_mont_const()
{
    _k_dat = {
        "MONT_CONST",
        2, 
        0, 
        2, 
        {
            {{"P_BITCOUNT", 1}, {"E_BITCOUNT", 0}},
        } 
    };
}

void generator_mont_const::clear()
{
    inst.clear();
    task_split.clear();
    inst_length.clear();
    inst_c_address = DATA_OUT_TO_OUT_CTRL;
    inst_l_address = 0;
    task_split_n = 0;
    load_a_address = 0;
    load_b_address = 0;
    inst_length_last = 0;
}

void generator_mont_const::_inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;

    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
    // L: param
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,param,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: p
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,p,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L: n_prime
    inst_l_length = 1;

    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,n_prime,inst_l_times,NOCHANGE,actual_pe);

    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;
    // L : rsquare
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,all,r_square,inst_l_times,NOCHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length;  
}

void generator_mont_const::_inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length)
{
    uint32_t  inst_l_length =1;
    uint32_t inst_l_times = 1;
    uint64_t inst_temp = 0;
    // C: IDLE -> LOAD_PARA
    inst_temp = gen_inst_c(IDLE,CAL,LOAD_PARA,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: LOAD_PARA -> ELEMENT_RSQUARE
    inst_temp = gen_inst_c(LOAD_PARA,CAL,ELEMENT_RSQUARE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
 
    // C: ELEMENT_RSQUARE and WAIT
    inst_temp = gen_inst_c(ELEMENT_RSQUARE,WAIT,ELEMENT_RSQUARE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // L : a
    inst_l_length = p_bitcount / LOCAL_BUFFER_WIDTH;
    inst_l_times = actual_pe;
    inst_temp = gen_inst_l(inst_l_address,inst_l_length,pe_0,a,inst_l_times,CHANGE,actual_pe);
    inst.push_back(inst_temp);
    inst_l_address +=inst_l_length*inst_l_times;

    // I
    inst_temp = gen_inst_i(ddr_address,ddr_length);
    inst.push_back(inst_temp);

    // inst split
    inst_length.push_back(inst.size()-inst_length_last);
    inst_length_last = inst.size();
    // C : ELEMENT_RSQUARE -> VEC_OUTPUT_RESULTS
    inst_temp = gen_inst_c(ELEMENT_RSQUARE,CAL,VEC_OUTPUT_RESULTS,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C : VEC_OUTPUT_RESULTS -> IDLE
    inst_temp = gen_inst_c(VEC_OUTPUT_RESULTS,CAL,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);
}

void generator_mont_const::_inst_gen_end_(uint8_t actual_pe)
{
    uint64_t inst_temp = 0;
    // C: IDLE and WAIT
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    // C: IDLE and WAIT
    actual_pe = 0;
    inst_temp = gen_inst_c(IDLE,WAIT,IDLE,inst_c_address,actual_pe);
    inst.push_back(inst_temp);

    inst_length.push_back(inst.size()-inst_length_last);
}


struct generator_inst_t generator_mont_const::gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<struct out_ddr_detail_t> mem_alloc)
{
    uint32_t _task_split = task_split;
    uint64_t ddr_address = 0;
    uint64_t ddr_length = 0;
    uint8_t actual_pe = 0;
    struct generator_inst_t _inst_tmp;
    this->clear();
    task_split_n = task_split;
    actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;

    _inst_gen_start_(p_bitcount,e_bitcount,actual_pe);
    uint32_t number_of_outs = std::ceil((float)_task_split/(float)NUMBER_OF_PE);

    for(uint8_t t = 0;t < number_of_outs;t++)
    {
        ddr_address = mem_alloc[t].out_ddr_addr;
        ddr_length = mem_alloc[t].out_ddr_length;

        if(t==number_of_outs-1)
        {
            actual_pe = ((_task_split%NUMBER_OF_PE)==0)?NUMBER_OF_PE:(_task_split%NUMBER_OF_PE);
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
        else
        {
            actual_pe = (_task_split>=NUMBER_OF_PE)?NUMBER_OF_PE:_task_split;
            _inst_gen_middle_(p_bitcount,e_bitcount,actual_pe,ddr_address,ddr_length);
        }
    }
    _inst_gen_end_(actual_pe);
    check_inst_sram_depth(inst);
    _inst_tmp.inst = inst;
    _inst_tmp.inst_length = inst_length;
    return _inst_tmp;
}

struct generator_inst_t generator_asic::gen_inst(struct Program program,uint32_t task_split,std::vector<struct out_ddr_detail_t> mem_alloc)
{
    struct generator_inst_t _g_inst;
    if(program.operation_type == "MOD_MUL")
    {
        generator_mod_mul _generator_mod_mul;
        _g_inst =_generator_mod_mul.gen_inst(program.p_bitcount,program.e_bitcount,task_split,mem_alloc);
    }
    else if(program.operation_type == "PAILLIER_ENC")
    {
        generator_paillier_encrypt _generator_paillier_encrypt;
        _g_inst =_generator_paillier_encrypt.gen_inst(program.p_bitcount,program.e_bitcount,task_split,mem_alloc);
    }
    else if(program.operation_type == "MOD_EXP_CONST_E")
    {
        generator_mod_exp_const_e _generator_mod_exp_const_e;
        _g_inst =_generator_mod_exp_const_e.gen_inst(program.p_bitcount,program.e_bitcount,task_split,mem_alloc);
    }
    else if(program.operation_type == "MOD_EXP")
    {
        generator_mod_exp _generator_mod_exp;
        _g_inst =_generator_mod_exp.gen_inst(program.p_bitcount,program.e_bitcount,task_split,mem_alloc);
    }
    else if(program.operation_type == "MOD_MUL_CONST")
    {
        generator_mod_mul_const _generator_mod_mul_const;
        _g_inst =_generator_mod_mul_const.gen_inst(program.p_bitcount,program.e_bitcount,task_split,mem_alloc);
    }
    else if(program.operation_type == "MOD_EXP_CONST_A")
    {
        generator_mod_exp_const_a _generator_mod_exp_const_a;
        _g_inst =_generator_mod_exp_const_a.gen_inst(program.p_bitcount,program.e_bitcount,task_split,mem_alloc);
    }
    else if(program.operation_type == "MOD_ADD")
    {
        generator_mod_add _generator_mod_add;
        _g_inst =_generator_mod_add.gen_inst(program.p_bitcount,program.e_bitcount,task_split,mem_alloc);
    }
    else if(program.operation_type == "MOD_ADD_CONST")
    {
        generator_mod_add_const _generator_mod_add_const;
        _g_inst =_generator_mod_add_const.gen_inst(program.p_bitcount,program.e_bitcount,task_split,mem_alloc);
    }
    else if(program.operation_type == "MONT")
    {
        generator_mont _generator_mont;
        _g_inst =_generator_mont.gen_inst(program.p_bitcount,program.e_bitcount,task_split,mem_alloc);
    }
    else if(program.operation_type == "MONT_CONST")
    {
        generator_mont_const _generator_mont_const;
        _g_inst =_generator_mont_const.gen_inst(program.p_bitcount,program.e_bitcount,task_split,mem_alloc);
    }
    else if(program.operation_type == "MOD_INV_CONST_P")
    {
        generator_mod_inv_const_p _generator_mod_inv_const_p;
        _g_inst =_generator_mod_inv_const_p.gen_inst(program.p_bitcount,program.e_bitcount,task_split,mem_alloc);
    } 
    return _g_inst;
}

void generator_asic::gen_inst_para()
{
    inst.clear();
    inst_split.clear();
}