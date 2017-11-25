class Logger(object):
    def __init__(self, log_file, stream=None):
        self.terminal = stream
        self.log_file = open(log_file, "a")

    def write(self, message):
        if self.terminal:
            self.terminal.write(message)

        self.log_file.write(message)

    def log(self, message):
        self.log_file.write(message)

    def flush(self):
        self.log_file.flush()

        if self.terminal:
            self.terminal.flush()
