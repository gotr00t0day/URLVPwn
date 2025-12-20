#include <iostream>
#include <string>
#include "modules/urlvpwn.h"

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"
#define BOLD    "\033[1m"
#define UNDERLINE "\033[4m"

	
int main(int argc, char* argv[]) {
    std::cout << BOLD << CYAN << R"(

 ____ _____________.____ ____   ______________                
|    |   \______   \    |\   \ /   /\______   \__  _  ______  
|    |   /|       _/    | \   Y   /  |     ___/\ \/ \/ /    \ 
|    |  / |    |   \    |__\     /   |    |     \     /   |  \
|______/  |____|_  /_______ \___/    |____|      \/\_/|___|  /
                 \/        \/                              \/ 
                 Author:    c0d3Ninja
                 Version:   v1.0
                 Instagram: @gotr00t0day
                            
      )" << RESET << "\n";
	if (argc < 3) {
		std::cout << "Usage: ./urlvpwn url payload_type" << "\n";
		std::cout << "Payload types: ssrf, openredirect, pathtraversal" << "\n";
		return 1;
	}
	std::string url = argv[1];
    std::string payloadType = argv[2];
    Resolve(url, payloadType);
	return 0;
}