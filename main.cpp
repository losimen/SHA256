#include "SHA256.h"


int main() {
    std::cout << "Hello:        " << SHA256::codeMsg("Hello") << std::endl;

    std::cout << "How are you?: " << SHA256::codeMsg("How are you?") << std::endl;
    std::cout << "How are yOu?: " << SHA256::codeMsg("How are yOu?") << std::endl;
    std::cout << "How Are you?: " << SHA256::codeMsg("How Are you?") << std::endl;


    return 0;
}
