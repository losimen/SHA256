//
// Created by Павло Коваль on 06.06.2022.
//

#ifndef SHA256_SHA256_H
#define SHA256_SHA256_H

#include <iostream>
#include <bit>
#include <bitset>
#include <vector>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <algorithm>

enum letters { a, b, c, d, e, f, g, h};
const int LENGTH_OF_MSG = 448;
const int AMOUNT_OF_MESSAGES = 16;
const std::vector<int> prime {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311};

class SHA256 {
private:
    static std::vector<std::string> divideIntoBlocks(std::string msg);

    static std::string msgToBinary(const std::string& toConvert);

    static std::string paddingMsg(const std::string& msg);

    // operations;
    static inline uint32_t rotr32 (uint32_t n, unsigned int c);

    // functions
    static std::bitset<32> sigma0(std::bitset<32> bitToUse);
    static std::bitset<32> sigma1(std::bitset<32> bitToUse);

    static std::bitset<32> sum0(std::bitset<32> bitToUse);
    static std::bitset<32> sum1(std::bitset<32> bitToUse);

    static std::bitset<32> ch(std::bitset<32> x, std::bitset<32> y, std::bitset<32> z);
    static std::bitset<32> maj(std::bitset<32> x, std::bitset<32> y, std::bitset<32> z);

    static std::vector<std::bitset<32>> getConstants();
    static std::vector<std::bitset<32>> getMsgSchedule(std::string str);
    static std::vector<std::bitset<32>> getRegisters();

    static std::vector<std::bitset<32>> codeMsgBlock(std::vector<std::bitset<32>> msgSchedule,
                                              const std::vector<std::bitset<32>> &constants,
                                              std::vector<std::bitset<32>> registers);
public:
    static std::string codeMsg(const std::string& msg);
};


#endif //SHA256_SHA256_H
