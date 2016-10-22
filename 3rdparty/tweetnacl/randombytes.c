#ifdef WIN32
#include "Windows.h"
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif

#include "../../src/util.h"
#include <stdlib.h>

void randombytes(unsigned char *ptr,unsigned int length)
{
#ifdef WIN32
    static HCRYPTPROV prov = 0;
    if (prov == 0 && !CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, 0))
        fwup_errx(EXIT_FAILURE, "CryptAcquireContext failed");

    if (!CryptGenRandom(prov, length, ptr))
        fwup_errx(EXIT_FAILURE, "CryptGenRandom failed");
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        fwup_err(EXIT_FAILURE, "Missing /dev/urandom?");

    while (length > 0) {
        size_t count = length;
        if (count > 65536)
            count = 65536;

        ssize_t amount_read = read(fd, ptr, count);
        if (amount_read <= 0 && errno != EINTR)
            fwup_err(EXIT_FAILURE, "Error reading /dev/urandom");

        length -= amount_read;
        ptr += amount_read;
    }
    close(fd);
#endif
}
