#include "SHA256.h"


int main() {
    SHA256 a;
    std::cout << "Hello:        " << a.codeMsg("Hello") << std::endl;

    std::cout << "How are you?: " << a.codeMsg("How are you?") << std::endl;
    std::cout << "How are yOu?: " << a.codeMsg("How are yOu?") << std::endl;
    std::cout << "How Are you?: " << a.codeMsg("How Are you?") << std::endl;

    return 0;
}
