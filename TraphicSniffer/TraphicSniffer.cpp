#include <iostream>
#include "sniffer.h"


int main(){
    sniffer obj("log.txt", 1);
    obj.sniff();
    obj.~sniffer();
}
