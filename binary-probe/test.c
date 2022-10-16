#include <stdio.h>
 
int main() {
    int result = rename("welcome.txt", "readme.txt");
    if (result == 0) {
        printf("The file is renamed successfully.");
    } else {
        printf("The file could not be renamed.");
    }
    return 0;
}
