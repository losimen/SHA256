//
// Created by Павло Коваль on 06.06.2022.
//

#include "SHA256.h"


std::string SHA256::msgToBinary(const std::string &toConvert) {
    std::string result;

    for (std::size_t i = 0; i < toConvert.size(); ++i)
    {
        result += std::bitset<8>(toConvert.c_str()[i]).to_string();
    }

    return result;
}

std::string SHA256::paddingMsg(const std::string &msg) const {
    std::string msgBinary = msgToBinary(msg);
    unsigned long msgLength = msgBinary.length();

    msgBinary.push_back('1');

    for (int i = 0; i < LENGTH_OF_MSG - msgLength - 1; i++)
        msgBinary.push_back('0');

    msgBinary += std::bitset<64>(msgLength).to_string();

    return msgBinary;
}

std::string SHA256::codeMsg(const std::string &msg) {
    std::string result;

    std::vector<std::bitset<32>> msgSchedule = getMsgSchedule(paddingMsg(msg));
    std::vector<std::bitset<32>> constants = getConstants();
    std::vector<std::bitset<32>> registers = getRegisters();

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


    for (auto el: registers) {
        std::stringstream res;
        res << std::hex << std::uppercase << el.to_ulong();

        result += res.str();
    }

    return result;
}


std::vector<std::bitset<32>>
SHA256::codeMsgBlock(std::vector<std::bitset<32>> msgSchedule, std::vector<std::bitset<32>> constants,
                     std::vector<std::bitset<32>> registers) {
    return std::vector<std::bitset<32>>();
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

    for (int i = 0; i < 64; i++)
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

    auto rotr_2 = std::bitset<32>(rotr32(converted, 2));
    auto rotr_13 = std::bitset<32>(rotr32(converted, 13));
    auto rotr_22 = std::bitset<32>(rotr32(converted, 22));

    return (rotr_2 ^ rotr_13) ^ rotr_22;
}

std::bitset<32> SHA256::sum0(std::bitset<32> bitToUse) {
    unsigned long long converted = bitToUse.to_ulong();

    auto rotr_6 = std::bitset<32>(rotr32(converted, 6));
    auto rotr_11 = std::bitset<32>(rotr32(converted, 11));
    auto rotr_25 = std::bitset<32>(rotr32(converted, 25));

    return (rotr_6 ^ rotr_11) ^ rotr_25;
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
    for (auto number: prime)
        vec.push_back(fractionToBinary(cbrt(number)));

    return vec;
}

std::bitset<32> SHA256::fractionToBinary(const double &t) {
    std::ostringstream os;
    os << std::setprecision(17) << t;
    std::string s = os.str();

    std::string number = s.substr(s.find('.')+1);

    return std::bitset<32>(std::stol(s.substr(s.find('.')+1)));
}

std::vector<std::bitset<32>> SHA256::getRegisters() {
    std::vector<std::bitset<32>> vec;

    for (int i = 0; i < 8; i++)
    {
        double number = sqrt(prime[i]);
        number -= double(int(number));

        vec.push_back(fractionToBinary(double(long(number*pow(2,32)))));
    }

    return vec;
}
