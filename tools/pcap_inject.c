#include <pcap.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

// Global variables
int injectDevice = -1;
int speed        = 1;

struct timeval previousTimestamp;

void callback(u_char* user, const struct pcap_pkthdr *hdr, const u_char* data)
{
    ssize_t ret;

    if (hdr->caplen < hdr->len) {
        assert(0 && "not all bytes of the packet captured");
    }

    struct timeval currentTimestamp = hdr->ts;

    if (timerisset(&previousTimestamp)) {
        /* sleep a little bit */
        struct timeval delta;
        struct timeval now;
        struct timeval deadline;
        timersub(&currentTimestamp, &previousTimestamp, &delta);

        gettimeofday(&now, NULL);
        timeradd(&now, &delta, &deadline);

        while (timercmp(&now, &deadline, <)) {
        
                long delay_usecs =    delta.tv_sec * 1000000
                                    + delta.tv_usec;

                int ret = usleep(delay_usecs);

                /* unsupported error */            
                if (ret == -1 && errno == EINVAL) {
                    assert( 0 && "unable to sleep"); 
                    return;
                } 
            
                /* sleep was successful */
                if (ret == 0) {
                    break;
                }

                gettimeofday(&now, NULL); 
                timersub(&deadline, &now, &delta);
        }
    }

    fprintf(stdout, "(II) Injecting frame of %d bytes\n", hdr->len);

    ret = write(injectDevice, data, hdr->len);

    if (ret < 0) {
        fprintf(stderr, "(EE) Unable to write %d bytes: %s\n",
                hdr->len, strerror(errno));
        return;
    }

    if (ret < hdr->len) {
        fprintf(stderr, "(EE) Unable to write %d bytes: only %d written\n",
                hdr->len, ret);
        return;
    }

    previousTimestamp = currentTimestamp;
}

int processCapture(const char* filename)
{
    char error[PCAP_ERRBUF_SIZE];
    
    pcap_t *pcap = pcap_open_offline(filename, error); 

    if (!pcap) {
        fprintf(stderr, "(EE) Unable to open pcap file '%s': %s\n",
                filename, error);
        return -1;
    }

    fprintf(stdout, "(II) Capture file '%s' opened\n", filename);

    // start processing
    int ret = pcap_loop(pcap, -1, callback, NULL);

    pcap_close(pcap);

    return 0;
}

void usage()
{
    printf("Usage: pcap_inject [OPTION]... FILE\n"
           "  -d, --device      Select device (default: /dev/kni0)\n"
           "  -h, --help        Display this page\n"
    );
}

int main(int argc, char *argv[])
{
    const char* injectName = "/dev/kni0";
    const char* filename   = NULL;

#define CHECK                       \
do {                                \
    if (i == (argc-1)) return -1;   \
} while (0)

    // parse arguments
    int i;
    for (i=1; i<argc; ++i) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--device") == 0) {
            CHECK;
            injectName = argv[++i];
            printf("injectNAme: %s\n", injectName);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage();
            return 0; 
        } else {
            if (filename) {
                fprintf(stderr, "(EE) Multiple filenames defined\n");
                return -1; 
            }
            filename = argv[i];
            printf("filename: %s\n", filename);
        }
    }

    if (!filename) {
        usage();
        return -1;
    }

    /* initialization */
    timerclear(&previousTimestamp);

    injectDevice = open(injectName, O_WRONLY);

    if (injectDevice < 0) {
        fprintf(stderr, "(EE) Unable to open device '%s': %s\n",
                injectName, strerror(errno));
        return -1;
    }

    for (;;) {
        processCapture(filename);
        sleep(1);
    }
    
    return processCapture(filename);
}
