//
// Created by Павло Коваль on 06.06.2022.
//

#include "SHA256.h"


std::string SHA256::msgToBinary(const std::string& toConvert) {
    std::string result;

    for (std::size_t i = 0; i < toConvert.size(); ++i)
    {
        result += std::bitset<8>(toConvert.c_str()[i]).to_string();
    }

    return result;
}

std::string SHA256::paddingMsg(const std::string& msg) {
    std::string msgBinary = msgToBinary(msg);
    unsigned long msgLength = msgBinary.length();

    msgBinary.push_back('1');

    for (int i = 0; i < LENGTH_OF_MSG - msgLength - 1; i++)
        msgBinary.push_back('0');

    msgBinary += std::bitset<64>(msgLength).to_string();

    return msgBinary;
}

std::string SHA256::codeMsg(const std::string& msg) {
    std::vector<std::string> msgBlocks = divideIntoBlocks(msg);

    const std::vector<std::bitset<32>> constants = getConstants();
    const std::vector<std::bitset<32>> registersInitial = getRegisters();
    std::vector<std::bitset<32>> registersToChange = registersInitial;

    for (const auto& msgBlock: msgBlocks)
    {
        std::vector<std::bitset<32>> msgSchedule = getMsgSchedule(paddingMsg(msgBlock));
        registersToChange = codeMsgBlock(msgSchedule, constants, registersToChange);
    }

    std::string result;
    std::string temp;

    for (int i = 0; i < registersInitial.size(); i++)
        registersToChange[i] = registersToChange[i].to_ullong() + registersInitial[i].to_ullong();

    for (auto el: registersToChange) {
        std::stringstream res;
        res << std::hex << std::uppercase << el.to_ulong();

        result += res.str();
    }

    return result;
}

std::vector<std::bitset<32>> SHA256::codeMsgBlock(std::vector<std::bitset<32>> msgSchedule,
                                                  const std::vector<std::bitset<32>> &constants,
                                                   std::vector<std::bitset<32>> registers) {

    for (int iteration = 0; iteration < 64; iteration++) {
        unsigned long long W = msgSchedule[iteration].to_ullong();
        unsigned long long K = constants[iteration].to_ullong();

        unsigned long long T1 = sum1(registers[letters::e]).to_ullong() +
                                ch(registers[letters::e], registers[letters::f], registers[letters::g]).to_ullong() +
                                registers[letters::h].to_ullong() +
                                W + K;

        unsigned long long T2 = sum0(registers[letters::a].to_ullong()).to_ullong() +
                                maj(registers[letters::a], registers[letters::b], registers[letters::c]).to_ullong();

        std::rotate ( registers.rbegin() , registers.rbegin()+1 , registers.rend() ) ;
        registers[letters::a] = T1 + T2;
        registers[letters::e] = registers[letters::e].to_ullong() + T1;
    }

    return registers;
}

std::vector<std::string> SHA256::divideIntoBlocks(std::string msg) {
    // TODO: optimise function

    if (msg.length() >= 55) {
        int str_size = int(msg.length());
        int AMOUNT_OF_BLOCKS = (str_size / 55)+1;
        int part_size = str_size / AMOUNT_OF_BLOCKS;

        std::vector<std::string> msgBlocks_(AMOUNT_OF_BLOCKS + 1, std::string());

        auto index = msgBlocks_.begin();

        for (int iteration = 0; iteration < str_size; iteration++) {
            if (iteration % part_size == 0)
                index++;

            (*index).push_back(msg[iteration]);
        }

        msgBlocks_.erase(msgBlocks_.begin());
        return msgBlocks_;
    } else {
        std::vector<std::string> msgBlocks_;
        msgBlocks_.push_back(msg);
        return msgBlocks_;
    }
}

std::vector<std::bitset<32>> SHA256::getMsgSchedule(std::string str) {
    int str_size = int(str.length());
    int part_size = str_size / AMOUNT_OF_MESSAGES;

    std::vector<std::string> msgSchedule(AMOUNT_OF_MESSAGES+1, std::string());

    auto index = msgSchedule.begin();

    for (int iteration = 0; iteration < str_size; iteration++) {
        if (iteration % part_size == 0)
            index++;

        (*index).push_back(str[iteration]);
    }

    msgSchedule.erase(msgSchedule.begin());

    std::vector<std::bitset<32>> msgResult(64);

    for(int i = 0; i < AMOUNT_OF_MESSAGES; i++)
        msgResult[i] = std::bitset<32>(msgSchedule[i]);

    for (int i = 0; i < 48; i++)
        msgResult[i+16] = std::bitset<32>(sigma1(msgResult[i+14]).to_ullong() +
                                          msgResult[i+9].to_ullong() +
                                          sigma0(msgResult[i+1]).to_ullong() +
                                          msgResult[i].to_ullong());


    return msgResult;
}

uint32_t SHA256::rotr32(uint32_t n, unsigned int c) {
    const unsigned int mask = (CHAR_BIT*sizeof(n) - 1);

    c &= mask;
    return (n>>c) | (n<<( (-c)&mask ));
}

std::bitset<32> SHA256::sigma0(std::bitset<32> bitToUse) {
    unsigned long long converted = bitToUse.to_ulong();

    auto rotr_7 = std::bitset<32>(rotr32(converted, 7));
    auto rotr_18 = std::bitset<32>(rotr32(converted, 18));
    std::bitset<32> shr_3 = bitToUse >> 3;

    return (rotr_7 ^ rotr_18) ^ shr_3;
}

std::bitset<32> SHA256::sigma1(std::bitset<32> bitToUse) {
    unsigned long long converted = bitToUse.to_ulong();

    auto rotr_17 = std::bitset<32>(rotr32(converted, 17));
    auto rotr_19 = std::bitset<32>(rotr32(converted, 19));
    std::bitset<32> shr_10 = bitToUse >> 10;

    return (rotr_17 ^ rotr_19) ^ shr_10;
}

std::bitset<32> SHA256::sum1(std::bitset<32> bitToUse) {
    unsigned long long converted = bitToUse.to_ulong();

    auto rotr_6 = std::bitset<32>(rotr32(converted, 6));
    auto rotr_11 = std::bitset<32>(rotr32(converted, 11));
    auto rotr_25 = std::bitset<32>(rotr32(converted, 25));

    return (rotr_6 ^ rotr_11) ^ rotr_25;
}

std::bitset<32> SHA256::sum0(std::bitset<32> bitToUse) {
    unsigned long long converted = bitToUse.to_ulong();

    auto rotr_2 = std::bitset<32>(rotr32(converted, 2));
    auto rotr_13 = std::bitset<32>(rotr32(converted, 13));
    auto rotr_22 = std::bitset<32>(rotr32(converted, 22));

    return (rotr_2 ^ rotr_13) ^ rotr_22;
}

std::bitset<32> SHA256::ch(std::bitset<32> x, std::bitset<32> y, std::bitset<32> z) {
    std::string resultStr;

    std::string x_str = x.to_string();
    std::string y_str = y.to_string();
    std::string z_str = z.to_string();

    int lenOfStr = int(x_str.length());
    for (int i = 0; i < lenOfStr; i++) {
        if (x_str[i] == '1')
            resultStr.push_back(y_str[i]);
        else
            resultStr.push_back(z_str[i]);
    }

    return std::bitset<32>(resultStr);
}

std::bitset<32> SHA256::maj(std::bitset<32> x, std::bitset<32> y, std::bitset<32> z) {
    std::string resultStr;

    std::string x_str = x.to_string();
    std::string y_str = y.to_string();
    std::string z_str = z.to_string();

    int lenOfStr = int(x_str.length());
    int is_one;

    for (int i = 0; i < lenOfStr; i++) {
        is_one = 3;

        if (x_str[i] == '0')
            is_one--;
        if (y_str[i] == '0')
            is_one--;
        if (z_str[i] == '0')
            is_one--;

        if (is_one >= 2)
            resultStr.push_back('1');
        else
            resultStr.push_back('0');
    }

    return std::bitset<32>(resultStr);
}

std::vector<std::bitset<32>> SHA256::getConstants() {
    std::vector<std::bitset<32>> vec;

    std::vector<unsigned long> constants {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    for (auto number: constants)
        vec.emplace_back(number);

    return vec;
}

std::vector<std::bitset<32>> SHA256::getRegisters() {
    std::vector<std::bitset<32>> vec {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
    };
    return vec;
}
