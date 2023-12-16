
#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>
int main(){
  int BUFFER_LENGTH =256; 
  FILE* filePointer;
  char buffer[BUFFER_LENGTH];
  char save[100][BUFFER_LENGTH];
  filePointer = fopen("config.txt", "r");

  int i = 0;
  int j=0;
  int ret, fd;

   while(fgets(save[i], BUFFER_LENGTH, filePointer)) {
      printf("%s", save[i]);
	   i++;
   }
   fclose(filePointer);
   fd = open("/dev/firewall", O_RDWR);
   if (fd < 0){
      perror("Cannot Open");
      return errno;
   }
   for(j=0; j < i; j++){
     ret = write(fd, save[j], BUFFER_LENGTH);
     if (ret < 0){
        perror("Cannot Wirte");
        return errno;
     }
   }
   return 0;
}