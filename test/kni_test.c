#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

size_t MAX_SIZE = 16384;

int main(int argc, char *argv[]) 
{
    const char *deviceName = "/dev/kni";

    int fd = open(deviceName, "r");

    if (fd == -1) {
        fprintf(stderr, "--- Unable to open %s: %s\n",
                deviceName, strerror(errno));
        return -1;
    }

    fprintf(stdout, "+++ Using device %s\n", deviceName);
    
    /* First series of test */
    char buf[MAX_SIZE];
    memset(buf, 0, MAX_SIZE);

    size_t len     = 1;
    size_t max_len = 0;

    while (len <= MAX_SIZE) {

        int ret = write(fd, buf, len);

        if (ret == len) max_len = len; 

        len = len << 1;
    }
    fprintf(stdout, "+++ max transmitted size: %d\n", max_len);

    /* Second series of test */
    struct timeval before, after, delta;
    int total_loops = 1 << 20;
    int loops = total_loops; 

    gettimeofday(&before, NULL); 
    while (--loops) {
        int ret = write(fd, buf, max_len);

        if (ret != max_len) {
            fprintf(stderr, "--- unable to transmit frame of size: %d\n", max_len);
        }
    }
    gettimeofday(&after, NULL); 
    timersub(&after, &before, &delta);

    long delay_usecs = delta.tv_sec*1000000L + delta.tv_usec;

    fprintf(stdout, "+++ %d calls, %.3fusec/call\n", total_loops, 
            (double)delay_usecs / (double)total_loops);

    return 0;
}
