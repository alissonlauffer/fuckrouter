CC = gcc
CFLAGS = -Wall -O2
TARGET = fuckrouter
SRC = fuckrouter.c
PREFIX = /usr
BINDIR = $(PREFIX)/bin
SERVICEDIR = /etc/systemd/system

# Build the program
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

# Install the program and systemd service
install: $(TARGET)
	# Install the binary
	install -D -m 0755 $(TARGET) $(BINDIR)/$(TARGET)
	# Install the systemd service and timer
	install -D -m 0644 fuckrouter.service $(SERVICEDIR)/fuckrouter.service

	# Reload systemd daemon
	systemctl daemon-reload
	# Enable and start the service
	systemctl enable --now fuckrouter.service

# Clean the build
clean:
	rm -f $(TARGET)

.PHONY: clean install
