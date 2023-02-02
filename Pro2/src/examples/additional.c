#include<stdio.h>
#include <stdlib.h>
#include <syscall.h>
int main(int argc, char** argv)
{
    if (argc == 2)
    {
      printf("%d\n", fibonacci(atoi(argv[1])));
    }
    else if (argc == 5)
    {
        int num[4] = {atoi(argv[1]), atoi(argv[2]),atoi(argv[3]), atoi(argv[4])} ;
        printf("%d %d\n", fibonacci(num[0]), max_of_four_int(num[0], num[1], num[2], num[3]));
     
    } 
  return EXIT_SUCCESS;
} 