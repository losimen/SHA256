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


class SHA256 {
private:
    enum letters { a, b, c, d, e, f, g, h};

    static const int LENGTH_OF_MSG = 448;
    static const int AMOUNT_OF_MESSAGES = 16;
    const std::vector<int> prime {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311};

    static std::bitset<32> fractionToBinary(const double& t);
    static std::string msgToBinary(const std::string& toConvert);

    std::string paddingMsg(const std::string& msg) const;

    // operations;
    static inline uint32_t rotr32 (uint32_t n, unsigned int c);

    // functions
    static std::bitset<32> sigma0(std::bitset<32> bitToUse);
    static std::bitset<32> sigma1(std::bitset<32> bitToUse);

    static std::bitset<32> sum0(std::bitset<32> bitToUse);
    static std::bitset<32> sum1(std::bitset<32> bitToUse);

    static std::bitset<32> ch(std::bitset<32> x, std::bitset<32> y, std::bitset<32> z);
    static std::bitset<32> maj(std::bitset<32> x, std::bitset<32> y, std::bitset<32> z);

    std::vector<std::bitset<32>> getConstants();
    std::vector<std::bitset<32>> getMsgSchedule(std::string str);
    std::vector<std::bitset<32>> getRegisters();

    std::vector<std::bitset<32>> codeMsgBlock(std::vector<std::bitset<32>> msgSchedule,
                                              std::vector<std::bitset<32>> constants,
                                              std::vector<std::bitset<32>> registers);
public:
    std::string codeMsg(const std::string &msg);

};


#endif //SHA256_SHA256_H
