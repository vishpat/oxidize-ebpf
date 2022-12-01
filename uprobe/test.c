/*
 * sendfile.c: simple example of using sendfile(3EXT) interface
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

int
main(int argc, char **argv)
{
	if (argc !=  4) {
		fprintf(stderr, "usage: %s <from file> <to file> <len>\n", argv[0]);
		return (1);
	}

	const char *fromfile = argv[1];
	const char *tofile = argv[2];
	long len = atol(argv[3]);

	int fromfd, tofd;
	off_t off = 0;

	int rv;

	if (unlink(tofile) < 0 && errno != ENOENT) {
		perror("unlink");
		return (1);
	}

	errno = 0;
	if ((fromfd = open(fromfile, O_RDONLY)) < 0 ||
	    (tofd = open(tofile, O_WRONLY | O_CREAT)) < 0) {
		perror("open");
		return (1);
	}

	if ((rv = sendfile(tofd, fromfd, &off, len)) < 0) {
		(void) fprintf(stderr, "Warning: sendfile(3EXT) returned %d "
		    "(errno %d)\n", rv, errno);
	}

	(void) printf("Sent %d KiB over sendfile(3EXT) of %d KiB requested \n",
	    off / 1024, len / 1024);

	(void) close(fromfd);
	(void) close(tofd);

	return (0);
}
