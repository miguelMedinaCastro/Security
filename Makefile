# ===========================================
# COMPILADOR E FLAGS
# ===========================================

CC := gcc
CFLAGS := -O3 -std=gnu99 -Wall -Wextra -pedantic -fstack-protector-all -g3 -DDEBUG=1
LIBS := -lcrypto -Wno-deprecated-declarations

# ===========================================
# DIRETÓRIOS
# ===========================================

SRCDIR := src
INCDIR := include
BINDIR := bin

BINARY := binary

# ===========================================
# ARQUIVOS
# ===========================================

SRC := $(wildcard $(SRCDIR)/*.c)
OBJ := $(patsubst $(SRCDIR)/%.c,$(SRCDIR)/%.o,$(SRC))

# ===========================================
# REGRAS
# ===========================================

all: $(BINDIR)/$(BINARY)

$(BINDIR)/$(BINARY): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LIBS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -c $< -o $@ $(CFLAGS) -I$(INCDIR)

clean:
	rm -f $(SRCDIR)/*.o
	rm -f $(BINDIR)/$(BINARY)

.PHONY: all clean
