PROG=gnveu
MAN=

SRCS=main.c
CFLAGS+=-Wall -Werror

DPADD+=${LIBEVENT}
LDADD=-levent

DEBUG=-g
WARNINGS=yes

NOOBJ=yes

.include <bsd.prog.mk>